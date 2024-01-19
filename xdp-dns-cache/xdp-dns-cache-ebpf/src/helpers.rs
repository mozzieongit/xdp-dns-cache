use aya_bpf::{bindings::xdp_action, programs::XdpContext};
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
