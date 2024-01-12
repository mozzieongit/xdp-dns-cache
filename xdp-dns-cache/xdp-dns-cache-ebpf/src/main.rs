#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::xdp_action, helpers::*, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn xdp_dns_cache(ctx: XdpContext) -> u32 {
    match try_xdp_dns_cache(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_dns_cache(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (source_port, dest_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(()),
    };

    let action;
    let mut should_change = false;

    // WARN: make sure to also change MAC addresses in future, the loopback
    // devices uses a MAC of 0x00, so there is no issue when testing against lo
    match source_addr {
        // source == 127.0.0.2
        0x7f000002 => {
            info!(&ctx, "Changing and returning the packet");
            unsafe {
                (*ipv4hdr).dst_addr = u32::to_be(source_addr);
                (*ipv4hdr).src_addr = u32::to_be(dest_addr);
            };
            match unsafe { (*ipv4hdr).proto } {
                IpProto::Udp => {
                    let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    unsafe {
                        (*udphdr).source = u16::to_be(dest_port);
                        (*udphdr).dest = u16::to_be(source_port);
                    }
                }
                _ => return Err(()),
            };
            should_change = true;
            action = xdp_action::XDP_TX;

            info!(
                &ctx,
                "{:i}:{} => {:i}:{}", source_addr, source_port, dest_addr, dest_port
            );
        }
        _ => action = xdp_action::XDP_PASS,
    }

    if should_change {
        // change IPv4 length and UDP length headers and checksums
        // let packet_delta = 364; // dig . NS
        // let packet_delta = 362; // dig a. NS
        // let packet_delta = 300;
        // let packet_delta = 982; // dig . NS +padding=446
        // let packet_delta = 916; // dig . NS +padding=512
        let packet_delta = 1980; // virtio_net
        let ipv4_len_old = u16::from_be(unsafe { (*ipv4hdr).tot_len });
        // Addition would normaly just overflow, so let's check if that would happen
        if let Some(ipv4_len_new) = ipv4_len_old.checked_add(packet_delta) {
            let mut csum = u16::from_be(unsafe { (*ipv4hdr).check });
            csum = csum_replace(csum, ipv4_len_old, ipv4_len_new);

            // I understood the cilium docs that data_end points at the last
            // byte of the packet, but that is not the case. It points at the
            // first byte not part of the packet. So there is no need for +1.
            let complete_len = ctx.data_end() - ctx.data();

            unsafe {
                info!(
                    &ctx,
                    "ctx.len: {} + delta = {} || ipv4 len before: {}, ipv4 len after: {}, delta: {}",
                    complete_len,
                    complete_len + packet_delta as usize,
                    ipv4_len_old,
                    ipv4_len_new,
                    packet_delta
                );
                (*ipv4hdr).tot_len = u16::to_be(ipv4_len_new);
                (*ipv4hdr).check = u16::to_be(csum);
            }

            match unsafe { (*ipv4hdr).proto } {
                IpProto::Udp => {
                    let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    unsafe {
                        (*udphdr).len = u16::to_be(u16::from_be((*udphdr).len) + packet_delta);
                        (*udphdr).check = 0;
                    }
                }
                _ => {}
            };

            // using adjust_tail invalidates all boundschecks priviously done, so this
            // has to go below the src/dst swaps
            if unsafe { bpf_xdp_adjust_tail(ctx.ctx, packet_delta.into()) } != 0 {
                info!(&ctx, "adjust_tail failed");
            }
        } else {
            info!(&ctx, "Increasing the IPv4 packet length by the desired delta of {} makes it larger than 0xffff", packet_delta);
        }
    }

    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

fn csum_replace_u32(mut check: u16, old: u32, new: u32) -> u16 {
    check = csum_replace(check, (old >> 16) as u16, (new >> 16) as u16);
    check = csum_replace(check, (old & 0xffff) as u16, (new & 0xffff) as u16);
    check
}

// I had used this before in my bachelor thesis
/*******************************************************************************
* Title: XDP Tutorial
* Author: Eelco Chaudron
* Date: 2019-08-16
* Availability: https://github.com/xdp-project/xdp-tutorial
* **************************************************************************/
// from xdp-tutorial:advanced03-AF_XDP/af_xdp_user.c
// static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
//     uint16_t res = (uint16_t)csum;

//     res += (__u16)addend;
//     return (__sum16)(res + (res < (__u16)addend));
// }
// static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
//     return csum16_add(csum, ~addend);
// }
// static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new) {
//     *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
// }
// The algorithm can also be found in RFC 1624.
// The Code was modified to fit into rust syntax.

fn csum16_add(csum: u16, addend: u16) -> u16 {
    let res: u16 = csum;
    let res = res.wrapping_add(addend);
    if res < addend {
        res + 1
    } else {
        res
    }
}

fn csum16_sub(csum: u16, addend: u16) -> u16 {
    csum16_add(csum, !addend)
}

fn csum_replace(check: u16, old: u16, new: u16) -> u16 {
    !csum16_add(csum16_sub(!check, old), new)
}
