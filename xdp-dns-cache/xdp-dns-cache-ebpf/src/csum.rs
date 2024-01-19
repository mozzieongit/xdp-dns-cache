/*******************************************************************************
* Title: XDP Tutorial
* Author: Eelco Chaudron
* Date: 2019-08-16
* Availability: https://github.com/xdp-project/xdp-tutorial
* **************************************************************************/
// Inspired by xdp-tutorial:advanced03-AF_XDP/af_xdp_user.c
// The algorithm can also be found in RFC 1624.

#[inline(always)]
pub fn csum16_add(csum: u16, addend: u16) -> u16 {
    let res: u16 = csum;
    let res = res.wrapping_add(addend);
    if res < addend {
        res + 1
    } else {
        res
    }
}

#[inline(always)]
pub fn csum16_sub(csum: u16, addend: u16) -> u16 {
    csum16_add(csum, !addend)
}

#[inline(always)]
pub fn csum_replace(check: u16, old: u16, new: u16) -> u16 {
    !csum16_add(csum16_sub(!check, old), new)
}
