#![no_std]
#![no_main]

use core::mem;

mod dns;
use dns::*;
mod csum;
use csum::*;
mod helpers;
use helpers::*;
mod cursor;
use cursor::Cursor;
mod metadata;
use metadata::*;

use aya_bpf::{
    bindings::xdp_action,
    helpers::*,
    macros::{map, xdp},
    maps::ProgramArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

const MAX_SENSIBLE_LABEL_COUNT: u8 = 20;

#[map(name = "JUMP_TABLE")]
static mut JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(8, 0);

const XDP_DNS_CACHE: u32 = 0;
const XDP_PARSE_DNAME: u32 = 1;
const XDP_CHECK_CACHE: u32 = 2;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn xdp_dns_cache(ctx: XdpContext) -> u32 {
    match try_xdp_dns_cache(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_xdp_dns_cache(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => do_ipv4(ctx),
        EtherType::Ipv6 => do_ipv6(ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn do_ipv6(ctx: XdpContext) -> Result<u32, ()> {
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn do_ipv4(ctx: XdpContext) -> Result<u32, ()> {
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;

    // TODO: should we also check IPv4 IHL to verify that no options are used which would mess up
    // our arithmetics?

    if is_udp_v4(ipv4hdr) {
        return do_udp(ctx, EthHdr::LEN + Ipv4Hdr::LEN);
    };

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn is_udp_v4(ipv4hdr: *const Ipv4Hdr) -> bool {
    unsafe { (*ipv4hdr).proto == IpProto::Udp }
}

#[inline(always)]
fn is_udp_v6(ipv6hdr: *const Ipv6Hdr) -> bool {
    unsafe { (*ipv6hdr).next_hdr == IpProto::Udp }
}

#[inline(always)]
fn do_udp(ctx: XdpContext, header_offset: usize) -> Result<u32, ()> {
    let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, header_offset)?;
    let dest_port = u16::from_be(unsafe { (*udphdr).dest });

    if dest_port == 53 {
        return do_dns(ctx, header_offset + UdpHdr::LEN);
    } else {
        return Ok(xdp_action::XDP_PASS);
    }
}

#[inline(always)]
fn do_dns(ctx: XdpContext, header_offset: usize) -> Result<u32, ()> {
    info!(&ctx, "do_dns");
    let dnshdr: *mut DnsHdr = ptr_at_mut(&ctx, header_offset)?;
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

    unsafe {
        // WARNING: delta for adjust_meta must be <= 32 and a multiple of 4
        if bpf_xdp_adjust_meta(ctx.ctx, -(mem::size_of::<MetaData>() as i32)) != 0 {
            info!(&ctx, "Could not adjust metadata");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    if ctx.metadata() + mem::size_of::<MetaData>() > ctx.metadata_end() {
        info!(&ctx, "Adjust metadata didn't work? The struct doesn't fit");
        return Ok(xdp_action::XDP_PASS);
    }

    let meta: *mut MetaData = ctx.metadata() as *mut MetaData;

    unsafe {
        (*meta).dname_offset = (header_offset + DnsHdr::LEN) as u8;

        let _ = JUMP_TABLE.tail_call(&ctx, XDP_PARSE_DNAME);
    }

    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn xdp_parse_dname(ctx: XdpContext) -> u32 {
    info!(&ctx, "Hello tailcall :)");
    if ctx.metadata() + 1 > ctx.data() {
        info!(&ctx, "there is no metadata available in xdp_parse_dname");
        return xdp_action::XDP_PASS;
    }

    let data_end = ctx.data_end();
    let metadata: &mut MetaData = unsafe { &mut *(ctx.metadata() as *mut MetaData) };

    // if ctx.data() + (metadata.dname_offset as usize) > ctx.data_end() {}
    let dnshdr_off = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DnsHdr::LEN;

    if ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DnsHdr::LEN > ctx.data_end() {
        info!(&ctx, "we goofed with the dname_offset. it's points outside of the frame");
        return xdp_action::XDP_ABORTED;
    }

    unsafe {
        let _ = JUMP_TABLE.tail_call(&ctx, XDP_CHECK_CACHE);
    }
    xdp_action::XDP_PASS
}

#[xdp]
pub fn xdp_check_cache(ctx: XdpContext) -> u32 {
    info!(&ctx, "Hello second tailcall :)");
    xdp_action::XDP_PASS
}
