use c2rust_bitfields::BitfieldStruct;

#[repr(C, align(1))]
#[derive(BitfieldStruct)]
pub struct DnsHdr {
    id: u16,
    #[bitfield(name = "qr", ty = "u8", bits = "7..=7")]
    #[bitfield(name = "opcode", ty = "u8", bits = "3..=6")]
    #[bitfield(name = "aa", ty = "u8", bits = "2..=2")]
    #[bitfield(name = "tc", ty = "u8", bits = "1..=1")]
    #[bitfield(name = "rd", ty = "u8", bits = "0..=0")]
    #[bitfield(name = "ra", ty = "u8", bits = "15..=15")]
    #[bitfield(name = "z", ty = "u8", bits = "14..=14")]
    #[bitfield(name = "ad", ty = "u8", bits = "13..=13")]
    #[bitfield(name = "cd", ty = "u8", bits = "12..=12")]
    #[bitfield(name = "rcode", ty = "u8", bits = "8..=11")]
    codes_and_flags: [u8; 2],
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHdr {
    pub fn id(&self) -> u16 {
        (self.id << 8) + (self.id >> 8)
    }

    pub fn qdcount(&self) -> u16 {
        (self.qdcount << 8) + (self.qdcount >> 8)
    }

    pub fn ancount(&self) -> u16 {
        (self.ancount << 8) + (self.ancount >> 8)
    }

    pub fn nscount(&self) -> u16 {
        (self.nscount << 8) + (self.nscount >> 8)
    }

    pub fn arcount(&self) -> u16 {
        (self.arcount << 8) + (self.arcount >> 8)
    }
}

pub const DNS_PORT: u16 = 53;
pub const RR_TYPE_OPT: u16 = 41;
pub const RCODE_REFUSED: u8 = 5;

#[repr(C)]
pub struct DnsQrr {
    qtype: u16,
    qclass: u16
}

// #[repr(C, packed)] // packed?
#[repr(C)]
pub struct DnsRr {
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata_len: u16
}
