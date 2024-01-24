#![no_std]
#![no_main]

use core::mem;

mod dns;
use dns::*;
mod csum;
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
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

// make a simple wrapper around aya_log_ebpf::info to only include it if the cfg flag
// "include_info" is set: i.e. $ RUSTFLAGS="--cfg include_info" cargo xtask build-ebpf
// This is necessary as different kernels have different limits and including logging adds
// many many instructions to the resulting BPF bytecode. This allows disabling logging at
// compile-time without going through the code to delete every logging statement.
macro_rules! info {
    ($($arg:tt)*) => {
        #[cfg(include_info)]
        {
            aya_log_ebpf::info!($($arg)*);
        }
    };
}

const MAX_SENSIBLE_LABEL_COUNT: u8 = 20;
const CACHED_QNAME_SIZE: usize = 32;

#[map(name = "JUMP_TABLE")]
static mut JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(8, 0);

#[allow(dead_code)]
const XDP_DNS_CACHE: u32 = 0;
const XDP_PARSE_DNAME: u32 = 1;
const XDP_CHECK_CACHE: u32 = 2;

// answer for nl. NS IN including compression
// const ANSWER_LEN: usize = 58;
// const NSCOUNT: u16 = 3;
// const ARCOUNT: u16 = 0;
// const ANSWER_DATA: [u8; ANSWER_LEN] = [
//     0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x0a, 0x03, 0x6e, 0x73, 0x31,
//     0x03, 0x64, 0x6e, 0x73, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
//     0x00, 0x06, 0x03, 0x6e, 0x73, 0x33, 0xc0, 0x24, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
//     0xa3, 0x00, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x24,
// ];

// answer for nl. NS IN including compression and glue
const ANSWER_LEN: usize = 201;
const NSCOUNT: u16 = 3;
const ARCOUNT: u16 = 7;
const ANSWER_DATA: [u8; ANSWER_LEN] = [
    0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x0a, 0x03, 0x6e, 0x73, 0x31,
    0x03, 0x64, 0x6e, 0x73, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
    0x00, 0x06, 0x03, 0x6e, 0x73, 0x33, 0xc0, 0x24, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
    0xa3, 0x00, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x24, 0xc0, 0x20, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc2, 0x00, 0x1c, 0x35, 0xc0, 0x36, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc2, 0x00, 0x19, 0x18, 0xc0, 0x48, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xb9, 0x9f, 0xc7, 0xc8, 0xc0, 0x20, 0x00, 0x1c, 0x00, 0x01,
    0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x06, 0x78, 0x00, 0x2c, 0x00, 0x00, 0x01, 0x94,
    0x00, 0x00, 0x00, 0x28, 0x00, 0x53, 0xc0, 0x36, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
    0x00, 0x10, 0x20, 0x01, 0x06, 0x78, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x24, 0xc0, 0x48, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x26, 0x20,
    0x01, 0x0a, 0x80, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

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

    let source_addr = unsafe { u32::from_be((*ipv4hdr).src_addr) };

    match source_addr {
        // source == 127.0.0.2 || 10.1.1.1
        0x7f000002 | 0x0a010101 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

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

        /////
        if header_offset == EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN {
            let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
            let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            change_len_and_checksums_v4(&ctx, ipv4hdr, udphdr, ANSWER_LEN as u16)?;
        // } else if header_offset == EthHdr::LEN + Ipv6Hdr::LEN + UdpHdr::LEN {
        //     let ipv6hdr: *mut Ipv6Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
        //     let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

        //     change_len_and_checksums_v6(&ctx, ipv6hdr, udphdr, ANSWER_LEN as u16)?;
        } else {
            return Err(());
        }
        /////

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

    if ctx.metadata() + mem::size_of::<MetaData>() > ctx.data() {
        info!(&ctx, "we goofed with the metadata");
        return xdp_action::XDP_PASS;
    }

    let proto: EtherType;
    let dnshdr: &mut DnsHdr;
    let dnsdata_off: usize;
    let v4_off = Ipv4Hdr::LEN + EthHdr::LEN + UdpHdr::LEN + DnsHdr::LEN;
    let v6_off = Ipv6Hdr::LEN + EthHdr::LEN + UdpHdr::LEN + DnsHdr::LEN;
    if metadata.dname_offset as usize == v4_off {
        proto = EtherType::Ipv4;
        dnsdata_off = v4_off;
        unsafe {
            dnshdr = &mut *((ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *mut DnsHdr)
        }
    } else if metadata.dname_offset as usize == v6_off {
        proto = EtherType::Ipv6;
        dnsdata_off = v6_off;
        unsafe {
            dnshdr = &mut *((ctx.data() + EthHdr::LEN + Ipv6Hdr::LEN + UdpHdr::LEN) as *mut DnsHdr)
        }
    } else {
        info!(&ctx, "ether_type doesn't match");
        return xdp_action::XDP_PASS;
    }

    let mut cursor: Cursor = Cursor::new(ctx.data() + dnsdata_off);
    let mut buf: [u8; CACHED_QNAME_SIZE] = [0; CACHED_QNAME_SIZE];

    // if dns query is at least X bytes long
    // let len = 5; // .
    // // let len = 7; // no need to check for single character long TLDs (they don't exist)
    // let len = 8; // nl. / de. / ...
    // let len = 9; // com. / ...
    // let len = 10; // name. / ...
    // NOTE: we might be able to use a for loop (unrolled possibly) to reduce the amount of code
    // TODO: maybe ignore the need for class and type in the bounds/numbers below?
    if ctx.data() + dnsdata_off + 18 < ctx.data_end() {
        // at least a query to nlnetlabs.nl. fits
        if let Err(action) = parse_qname(&ctx, 14, &mut buf, &mut cursor) {
            return action;
        }
    } else if ctx.data() + dnsdata_off + 10 < ctx.data_end() {
        // at least a query to name. fits
        if let Err(action) = parse_qname(&ctx, 6, &mut buf, &mut cursor) {
            return action;
        }
    } else if ctx.data() + dnsdata_off + 9 < ctx.data_end() {
        // at least a query to com. fits
        if let Err(action) = parse_qname(&ctx, 5, &mut buf, &mut cursor) {
            return action;
        }
    } else if ctx.data() + dnsdata_off + 8 < ctx.data_end() {
        // at least a query to nl. fits
        if let Err(action) = parse_qname(&ctx, 4, &mut buf, &mut cursor) {
            return action;
        }
    } else if ctx.data() + dnsdata_off + 5 < ctx.data_end() {
        // at least a query to . fits
        if let Err(action) = parse_qname(&ctx, 1, &mut buf, &mut cursor) {
            return action;
        }
    } else {
        info!(&ctx, "dns query not long enough");
        return xdp_action::XDP_ABORTED;
    }

    unsafe {
        let s = core::str::from_utf8_unchecked(&buf);
        info!(&ctx, "buf (unchecked utf8): {}", s);
    }

    if cursor.pos + 2 > ctx.data_end() {
        info!(&ctx, "dns query not long enough");
        return xdp_action::XDP_ABORTED;
    }

    let q_type: u16 = u16::from_be(unsafe { *(cursor.pos as *const u16) });
    cursor.pos += 2;

    if cursor.pos + 2 > ctx.data_end() {
        info!(&ctx, "dns query not long enough");
        return xdp_action::XDP_ABORTED;
    }

    let q_class: u16 = u16::from_be(unsafe { *(cursor.pos as *const u16) });
    cursor.pos += 2;

    info!(&ctx, "q_type: {}, class: {}", q_type, q_class);

    // TODO: get answer from cache

    if buf[0..4] == [0x02, 0x6e, 0x6c, 0x00] {
        info!(&ctx, "yes it's for nl.");

        match proto {
            EtherType::Ipv6 => {
                // if let Ok(ipv6hdr) = ptr_at_mut(&ctx, EthHdr::LEN) {
                //     swap_ipv6_addr(ipv6hdr);
                // }

                // if let Ok(udphdr) = ptr_at_mut(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) {
                //     swap_udp_ports(udphdr);
                // }
            }
            EtherType::Ipv4 => {
                if let Ok(ipv4hdr) = ptr_at_mut(&ctx, EthHdr::LEN) {
                    swap_ipv4_addr(ipv4hdr);
                }

                if let Ok(udphdr) = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) {
                    swap_udp_ports(udphdr);
                }
            }
            _ => return xdp_action::XDP_PASS,
        }

        if let Ok(ethhdr) = ptr_at_mut(&ctx, 0) {
            swap_eth_addr(ethhdr);
        }

        // dnshdr.set_tc(1);
        dnshdr.set_qr(1);
        dnshdr.set_ra(0);
        dnshdr.set_nscount(NSCOUNT);
        dnshdr.set_arcount(ARCOUNT);

        // ignore EDNS0 and just overwrite with answer
        if cursor.pos + ANSWER_LEN < ctx.data_end() {
            for i in 0..ANSWER_LEN {
                unsafe {
                    *(cursor.pos as *mut u8) = ANSWER_DATA[i];
                    cursor.pos += 1;
                }
            }

            // nullify the rest
            for _i in 0..100 {
                if cursor.pos < ctx.data_end() {
                    unsafe {
                        *(cursor.pos as *mut u8) = 0;
                        cursor.pos += 1;
                    }
                }
            }
        }
        return xdp_action::XDP_TX;
    }

    unsafe {
        let _ = JUMP_TABLE.tail_call(&ctx, XDP_CHECK_CACHE);
        info!(&ctx, "tail call failed");
    }
    xdp_action::XDP_PASS
}

#[xdp]
pub fn xdp_check_cache(ctx: XdpContext) -> u32 {
    info!(&ctx, "Hello second tailcall :)");
    xdp_action::XDP_PASS
}

#[inline(always)]
fn parse_qname(
    ctx: &XdpContext,
    max_bytes: usize,
    buf: &mut [u8],
    cursor: &mut Cursor,
) -> Result<(), u32> {
    let mut buf_index = 0;
    let mut label_bytes_left = 0;
    let mut reached_root_label = false;
    for _i in 0..=max_bytes {
        // if cursor.pos + 1 > frame_end {
        //     return Err(());
        // }

        let char: u8 = unsafe { *(cursor.pos as *const u8) };
        info!(ctx, "{}", char);
        cursor.pos += 1;
        if char == 0 {
            info!(ctx, "reached root label");
            reached_root_label = true;
            break;
        }

        if label_bytes_left == 0 {
            if (char & 0xC0) == 0xC0 {
                info!(ctx, "complabel");
                // compression label
                // not checking validity of reference
                // compression label would be the last label of dname
                break;
            } else if (char & 0xC0) != 0 {
                info!(ctx, "unknown label");
                return Err(xdp_action::XDP_PASS);
            } else {
                info!(ctx, "label len: {}", char);
                label_bytes_left = char + 1; // +1 because of length itself
            }
        }

        buf[buf_index] = char;
        buf_index += 1;
        label_bytes_left -= 1;
    }

    info!(ctx, "chars left: {}", label_bytes_left);
    if !reached_root_label {
        info!(ctx, "qname was not read appropriately");
        return Err(xdp_action::XDP_PASS);
    }

    Ok(())
}
