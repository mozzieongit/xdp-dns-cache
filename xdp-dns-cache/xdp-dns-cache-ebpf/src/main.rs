#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::xdp_action, helpers::*, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

mod dns;
use dns::DnsHdr;

const MAX_SENSIBLE_LABEL_COUNT: u8 = 20;

struct Cursor {
    pos: usize,
}

impl Cursor {
    fn new(pos: usize) -> Self {
        Self { pos }
    }
}

#[xdp]
pub fn xdp_dns_cache(ctx: XdpContext) -> u32 {
    match try_xdp_dns_cache(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_dns_cache(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => do_ipv4(ctx),
        EtherType::Ipv6 => do_ipv6(ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn do_ipv6(ctx: XdpContext) -> Result<u32, ()> {
    Ok(xdp_action::XDP_PASS)
}

fn do_ipv4(ctx: XdpContext) -> Result<u32, ()> {
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    // FIXME: should we also check IPv4 IHL to verify that no options are used which would mess up
    // our arithmetics?

    if unsafe { (*ipv4hdr).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    };

    let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let source_port = u16::from_be(unsafe { (*udphdr).source });
    let dest_port = u16::from_be(unsafe { (*udphdr).dest });

    if dest_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    }

    let dnshdr: *mut DnsHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;
    unsafe {
        info!(
            &ctx,
            "QR:{}, OPCODE:{}, AA:{}, TC:{}, RD:{}, RA:{}, Z:{}, AD:{}, CD:{}, RCODE:{}, QDCOUNT:{}, ANCOUNT:{}, NSCOUNT:{}, ARCOUNT:{}",
            (*dnshdr).qr(),
            (*dnshdr).opcode(),
            (*dnshdr).aa(),
            (*dnshdr).tc(),
            (*dnshdr).rd(),
            (*dnshdr).ra(),
            (*dnshdr).z(),
            (*dnshdr).ad(),
            (*dnshdr).cd(),
            (*dnshdr).rcode(),
            (*dnshdr).qdcount(),
            (*dnshdr).ancount(),
            (*dnshdr).nscount(),
            (*dnshdr).arcount(),
        );
    }

    unsafe {
        let dnshdr: &DnsHdr = &*(dnshdr);
        if dnshdr.qr() != 0
            || dnshdr.qdcount() != 1
            || dnshdr.ancount() != 0
            || dnshdr.nscount() != 0
            || dnshdr.arcount() > 1
        {
            info!(&ctx, "Aborting this message, the DNS query is bogus");
            return Ok(xdp_action::XDP_ABORTED);
        }
    }

    let mut cursor: Cursor =
        Cursor::new(ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DnsHdr::LEN);

    let qname = parse_dname(&ctx, &mut cursor, dnshdr as usize)?;
    info!(&ctx, "qname len: {}", qname.len());
    let is_label = false;
    let mut counter = 0;
    let mut buf: [u8; 255] = [0; 255];
    let mut len = 0;
    for i in 0..255 {
        if i >= qname.len() {
            break;
        }
        if counter == 0 {
            counter = qname[i];
            buf[len] = b'.';
        } else {
            // info!(&ctx, "{}", qname[i].clone());
            buf[len] = qname[i];
            counter -= 1;
        }
        len += 1;
    }

    let mut action = xdp_action::XDP_PASS;

    // to not disrupt DNS on the dev system completely
    match source_addr {
        // source == 127.0.0.2 || 10.1.1.1
        0x7f000002 | 0x0a010101 => {
            let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;
            swap_ipv4_addr(ipv4hdr);
            swap_eth_addr(ethhdr);
            swap_udp_ports(udphdr);

            change_len_and_checksums(ctx, ipv4hdr, udphdr)?;
            action = xdp_action::XDP_TX;
        }
        _ => {}
    }

    Ok(action)
}

fn parse_dname<'a>(
    ctx: &'a XdpContext,
    cursor: &mut Cursor,
    dnshdr_start: usize
) -> Result<&'a [u8], ()> {
    let frame_start = ctx.data();
    let frame_end = ctx.data_end();
    let dname_start = cursor.pos;
    for _i in 0..MAX_SENSIBLE_LABEL_COUNT {
        if cursor.pos + 1 > frame_end {
            return Err(());
        }

        let char: u8 = unsafe { u8::from_be(*(cursor.pos as *const u8)) };
        info!(ctx, "{}", char);
        if (char & 0xC0) == 0xC0 {
            info!(ctx, "complabel");
            // compression label, only back references allowed
            if (char | 0x3F) as usize >= (dname_start - dnshdr_start) {
                info!(ctx, "complabel_err");
                return Err(());
            }

            // compression label would be the last label of dname
            cursor.pos += 1;
            break;
        } else if (char & 0xC0) != 0 {
            info!(ctx, "unknown label");
            // unknown label type
            return Err(());
        }

        cursor.pos += char as usize + 1;
        info!(ctx, "check char");
        if char == 0 {
            info!(ctx, "char==0");
            break;
        }
    }
    let dname_len = cursor.pos - dname_start;
    Ok(unsafe { core::slice::from_raw_parts(dname_start as *const u8, dname_len) })
    // Ok(&[])
}

fn change_len_and_checksums(
    ctx: XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    udphdr: *mut UdpHdr,
) -> Result<u32, ()> {
    // change IPv4 length and UDP length headers and checksums

    let orig_frame_size = ctx.data_end() - ctx.data();
    let packet_delta_tail;
    // let packet_delta_tail = 982; // dig @loopback . NS +padding=446
    // let packet_delta_tail = 916; // dig @loopback . NS +padding=512
    // let packet_delta_tail = 3426; // dig @virtio_net . NS

    // should work for now. (loopback on my laptop linux 6.6.10-1-MANJARO)
    // TODO: evaluate/prove numbers
    // TODO: get number from map as we can know from the desired answer how much space we need
    if orig_frame_size < 304 {
        // small request frame, max frame size likely 446 bytes.
        packet_delta_tail = 446 - orig_frame_size as u16;
    } else if orig_frame_size < 500 {
        // 500 and 580 are arbitrary, but tested, numbers
        packet_delta_tail = 580 - orig_frame_size as u16;
    } else if orig_frame_size < 1470 {
        // we should get to 1470 and above in the other cases
        packet_delta_tail = 1470 - orig_frame_size as u16;
    } else {
        info!(
            &ctx,
            "there has been a fairly large frame here: {} bytes", orig_frame_size
        );
        // TODO: just don't bother with this frame?
        return Ok(xdp_action::XDP_PASS);
    }

    let packet_delta = packet_delta_tail;
    let orig_ipv4_len = u16::from_be(unsafe { (*ipv4hdr).tot_len });
    let ipv4_len_new = orig_ipv4_len + packet_delta;
    let mut csum = u16::from_be(unsafe { (*ipv4hdr).check });

    csum = csum_replace(csum, orig_ipv4_len, ipv4_len_new);

    unsafe {
        info!(
            &ctx,
            "ctx.len: {} + delta = {} || ipv4 len before: {}, ipv4 len after: {}, delta: {}",
            orig_frame_size,
            orig_frame_size + packet_delta as usize,
            orig_ipv4_len,
            ipv4_len_new,
            packet_delta
        );
        (*ipv4hdr).tot_len = u16::to_be(ipv4_len_new);
        (*ipv4hdr).check = u16::to_be(csum);
    }

    unsafe {
        (*udphdr).len = u16::to_be(u16::from_be((*udphdr).len) + packet_delta);
        (*udphdr).check = 0;
    }

    // using adjust_tail invalidates all boundschecks priviously done, so this
    // has to go below the address swaps
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, packet_delta_tail.into()) } != 0 {
        info!(
            &ctx,
            "adjust_tail failed for tail delta: {}", packet_delta_tail
        );
    }

    Ok(xdp_action::XDP_PASS)
}

fn swap_udp_ports(udphdr: *mut UdpHdr) {
    unsafe {
        let src_port_be = (*udphdr).source;
        (*udphdr).source = (*udphdr).dest;
        (*udphdr).dest = src_port_be;
    }
}

fn swap_eth_addr(ethhdr: *mut EthHdr) {
    unsafe {
        let src_addr_be = (*ethhdr).src_addr;
        (*ethhdr).src_addr = (*ethhdr).dst_addr;
        (*ethhdr).dst_addr = src_addr_be;
    }
}

fn swap_ipv4_addr(ipv4hdr: *mut Ipv4Hdr) {
    unsafe {
        let src_addr_be = (*ipv4hdr).src_addr;
        (*ipv4hdr).src_addr = (*ipv4hdr).dst_addr;
        (*ipv4hdr).dst_addr = src_addr_be;
    };
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
