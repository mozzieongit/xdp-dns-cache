use network_types::eth::EtherType;

// This struct needs to be a multiple of 4 bytes in size and at max 32 bytes in size
#[repr(C)]
pub struct MetaData {
    pub ether_type: EtherType, // size 2
    pub dname_offset: u8,
    pub lbl1_offset: u8,
    pub lbl2_offset: u8,
    pub lbl3_offset: u8,
    pub _padding: u16
}
