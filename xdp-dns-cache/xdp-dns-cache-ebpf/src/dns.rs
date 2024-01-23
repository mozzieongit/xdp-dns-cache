use c2rust_bitfields::BitfieldStruct;

pub const DNS_PORT: u16 = 53;
pub const RR_TYPE_OPT: u16 = 41;
pub const RCODE_REFUSED: u8 = 5;

#[repr(C, align(1))]
#[derive(BitfieldStruct)]
pub struct DnsHdr {
    pub id: u16,
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
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[allow(dead_code)]
impl DnsHdr {
    pub const LEN: usize = core::mem::size_of::<DnsHdr>();

    pub fn id(&self) -> u16 {
        u16::from_be(self.id)
    }

    pub fn qdcount(&self) -> u16 {
        u16::from_be(self.qdcount)
    }

    pub fn ancount(&self) -> u16 {
        u16::from_be(self.ancount)
    }

    pub fn nscount(&self) -> u16 {
        u16::from_be(self.nscount)
    }

    pub fn arcount(&self) -> u16 {
        u16::from_be(self.arcount)
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = u16::to_be(id)
    }

    pub fn set_qdcount(&mut self, count: u16) {
        self.qdcount = u16::to_be(count)
    }

    pub fn set_ancount(&mut self, count: u16) {
        self.ancount = u16::to_be(count)
    }

    pub fn set_nscount(&mut self, count: u16) {
        self.nscount = u16::to_be(count)
    }

    pub fn set_arcount(&mut self, count: u16) {
        self.arcount = u16::to_be(count)
    }
}
