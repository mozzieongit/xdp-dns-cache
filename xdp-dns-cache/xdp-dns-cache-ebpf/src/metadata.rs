// This struct needs to be a multiple of 4 bytes in size and at max 32 bytes in size
// Check in kernel code in file include/net/xdp.h:xdp_metalen_invalid
#[repr(C)]
pub struct MetaData {
    pub dname_offset: u8,
    pub lbl1_offset: u8,
    pub lbl2_offset: u8,
    pub lbl3_offset: u8,
}
