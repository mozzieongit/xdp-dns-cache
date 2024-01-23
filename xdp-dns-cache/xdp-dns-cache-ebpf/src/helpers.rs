use aya_bpf::{programs::XdpContext, helpers::bpf_xdp_adjust_tail, bindings::xdp_action};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

use crate::csum::*;

#[inline(always)]
pub fn swap_udp_ports(udphdr: *mut UdpHdr) {
    unsafe {
        let src_port_be = (*udphdr).source;
        (*udphdr).source = (*udphdr).dest;
        (*udphdr).dest = src_port_be;
    }
}

#[inline(always)]
pub fn swap_eth_addr(ethhdr: *mut EthHdr) {
    unsafe {
        let src_addr_be = (*ethhdr).src_addr;
        (*ethhdr).src_addr = (*ethhdr).dst_addr;
        (*ethhdr).dst_addr = src_addr_be;
    }
}

#[inline(always)]
pub fn swap_ipv4_addr(ipv4hdr: *mut Ipv4Hdr) {
    unsafe {
        let src_addr_be = (*ipv4hdr).src_addr;
        (*ipv4hdr).src_addr = (*ipv4hdr).dst_addr;
        (*ipv4hdr).dst_addr = src_addr_be;
    };
}

#[allow(dead_code)]
#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub fn csum_replace_u32(mut check: u16, old: u32, new: u32) -> u16 {
    check = csum_replace(check, (old >> 16) as u16, (new >> 16) as u16);
    check = csum_replace(check, (old & 0xffff) as u16, (new & 0xffff) as u16);
    check
}

#[inline(always)]
pub fn change_len_and_checksums_v4(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    udphdr: *mut UdpHdr,
    delta: u16,
) -> Result<u32, ()> {
    // change IPv4 length and UDP length headers and checksums

    let orig_frame_size = ctx.data_end() - ctx.data();

    let orig_ipv4_len = u16::from_be(unsafe { (*ipv4hdr).tot_len });
    let ipv4_len_new = orig_ipv4_len + delta;
    let mut csum = u16::from_be(unsafe { (*ipv4hdr).check });

    csum = csum_replace(csum, orig_ipv4_len, ipv4_len_new);

    unsafe {
        info!(
            ctx,
            "ctx.len: {} + delta = {} || ipv4 len before: {}, ipv4 len after: {}, delta: {}",
            orig_frame_size,
            orig_frame_size + delta as usize,
            orig_ipv4_len,
            ipv4_len_new,
            delta
        );
        (*ipv4hdr).tot_len = u16::to_be(ipv4_len_new);
        (*ipv4hdr).check = u16::to_be(csum);
    }

    unsafe {
        (*udphdr).len = u16::to_be(u16::from_be((*udphdr).len) + delta);
        (*udphdr).check = 0;
    }

    // using adjust_tail invalidates all boundschecks priviously done, so this
    // has to go below the address swaps
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta.into()) } != 0 {
        info!(
            ctx,
            "adjust_tail failed for tail delta: {}", delta
        );
    }

    Ok(xdp_action::XDP_PASS)
}
