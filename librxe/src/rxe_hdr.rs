#![allow(dead_code)]
use self::{aeth_mask::*, bth_mask::*, deth_mask::*, rdeth_mask::*};
use crate::rxe_opcode::rxe_hdr_type::*;
use crate::rxe_opcode::*;
use bytes::BytesMut;
#[derive(Debug, Clone)]
pub struct RxePktInfo {
    pub hdr: BytesMut,   /* IBA packet buffer */
    pub mask: u32,       /* useful info about pkt */
    pub psn: u32,        /* bth psn of packet */
    pub pkey_index: u16, /* partition of pkt */
    pub paylen: u16,     /* length from bth start to icrc end */
    pub port_num: u8,    /* port pkt received on */
    pub opcode: u8,      /* bth opcode of packet */
}

/*
 * IBA header types and methods
 *
 */
pub const RXE_ICRC_SIZE: u32 = 4;
pub const RXE_MAX_HDR_LENGTH: u32 = 80;

/******************************************************************************
 * Base Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeBth {
    pub opcode: u8,
    pub flags: u8,
    // in bigendian
    pub pkey: u16,
    // in bigendian
    pub qpn: u32,
    // in bigendian
    pub apsn: u32,
}

pub const BTH_TVER: u32 = 0;
pub const BTH_DEF_PKEY: u32 = 0xffff;
pub mod bth_mask {
    pub const BTH_SE_MASK: u8 = 0x80;
    pub const BTH_MIG_MASK: u8 = 0x40;
    pub const BTH_PAD_MASK: u8 = 0x30;
    pub const BTH_TVER_MASK: u8 = 0x0f;

    pub const BTH_FECN_MASK: u32 = 0x8000_0000;
    pub const BTH_BECN_MASK: u32 = 0x4000_0000;
    pub const BTH_RESV6A_MASK: u32 = 0x3f00_0000;
    pub const BTH_QPN_MASK: u32 = 0x00ff_ffff;
    pub const BTH_ACK_MASK: u32 = 0x8000_0000;
    pub const BTH_RESV7_MASK: u32 = 0x7f00_0000;
    pub const BTH_PSN_MASK: u32 = 0x00ff_ffff;
}
/******************************************************************************
 * Reliable Datagram Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeRdeth {
    // in bigendian
    pub een: u32,
}
pub mod rdeth_mask {
    pub const RDETH_EEN_MASK: u32 = 0x00ffffff;
}
/******************************************************************************
 * Datagram Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeDeth {
    // in bigendian
    pub qkey: u32,
    // in bigendian
    pub sqp: u32,
}
pub const GSI_QKEY: u32 = 0x80010000;
pub mod deth_mask {
    pub const DETH_SQP_MASK: u32 = 0x00ffffff;
}
/******************************************************************************
 * RDMA Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeReth {
    pub va: u64,
    pub rkey: u32,
    pub len: u32,
}

/******************************************************************************
 * Atomic Extended Transport Header
 ******************************************************************************/
#[repr(packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeAtmeth {
    // in bigendian
    pub va: u64,
    // in bigendian
    pub rkey: u32,
    // in bigendian
    pub swap_add: u64,
    // in bigendian
    pub comp: u64,
}

/******************************************************************************
 * Ack Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeAeth {
    // in bigendian
    smsn: u32,
}
pub mod aeth_mask {
    pub const AETH_SYN_MASK: u32 = 0xff000000;
    pub const AETH_MSN_MASK: u32 = 0x00ffffff;
}
pub mod aeth_syndrome {
    pub const AETH_TYPE_MASK: u8 = 0xe0;
    pub const AETH_ACK: u8 = 0x00;
    pub const AETH_RNR_NAK: u8 = 0x20;
    pub const AETH_RSVD: u8 = 0x40;
    pub const AETH_NAK: u8 = 0x60;
    pub const AETH_ACK_UNLIMITED: u8 = 0x1f;
    pub const AETH_NAK_PSN_SEQ_ERROR: u8 = 0x60;
    pub const AETH_NAK_INVALID_REQ: u8 = 0x61;
    pub const AETH_NAK_REM_ACC_ERR: u8 = 0x62;
    pub const AETH_NAK_REM_OP_ERR: u8 = 0x63;
    pub const AETH_NAK_INV_RD_REQ: u8 = 0x64;
}
/******************************************************************************
 * Atomic Ack Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeAtmack {
    // in big endian
    pub orig: u64,
}

/******************************************************************************
 * Immediate Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeImmdt {
    // in big endian
    pub imm: u32,
}

/******************************************************************************
 * Invalidate Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeIeth {
    // in big endian
    pub rkey: u32,
}

pub mod rxe_hdr_length {
    use super::*;
    pub type Type = u8;
    pub const RXE_BTH_BYTES: Type = ::std::mem::size_of::<RxeBth>() as _;
    pub const RXE_DETH_BYTES: Type = ::std::mem::size_of::<RxeDeth>() as _;
    pub const RXE_IMMDT_BYTES: Type = ::std::mem::size_of::<RxeImmdt>() as _;
    pub const RXE_RETH_BYTES: Type = ::std::mem::size_of::<RxeReth>() as _;
    pub const RXE_AETH_BYTES: Type = ::std::mem::size_of::<RxeAeth>() as _;
    pub const RXE_ATMACK_BYTES: Type = ::std::mem::size_of::<RxeAtmack>() as _;
    pub const RXE_ATMETH_BYTES: Type = ::std::mem::size_of::<RxeAtmeth>() as _;
    pub const RXE_IETH_BYTES: Type = ::std::mem::size_of::<RxeIeth>() as _;
    pub const RXE_RDETH_BYTES: Type = ::std::mem::size_of::<RxeRdeth>() as _;
}

impl RxePktInfo {
    // use mtu as IBA buffer capacity
    #[inline]
    pub fn new(
        mask: u32,
        psn: u32,
        pkey_index: u16,
        paylen: u16,
        port_num: u8,
        opcode: u8,
        mtu: u32,
    ) -> Self {
        RxePktInfo {
            hdr: BytesMut::zeroed(mtu as _),
            mask: mask,
            psn: psn,
            pkey_index: pkey_index,
            paylen: paylen,
            port_num: port_num,
            opcode: opcode,
        }
    }

    #[inline]
    pub fn get_iba_hdr_len(&self) -> usize {
        RXE_OPCODE_INFO[self.opcode as usize].length as usize
    }
    #[inline]
    pub fn get_iba_pkt_len(&self) -> usize {
        self.hdr.len()
    }
    #[inline]
    pub fn set_iba_pkt_len(&mut self, len: usize) {
        unsafe { self.hdr.set_len(len) }
    }
    #[inline]
    pub fn payload_size(&self) -> usize {
        (self.paylen as usize)
            - (RXE_OPCODE_INFO[self.opcode as usize].offset[RXE_PAYLOAD as usize] as usize)
            - (self.bth_pad() as usize)
            - RXE_ICRC_SIZE as usize
    }
    // create new buffer view points by offset
    #[inline]
    pub fn split_iba_pkt(&mut self, offset: usize) -> BytesMut {
        self.hdr.split_off(offset)
    }
    // destory a buffer view
    #[inline]
    pub fn unsplit_iba_pkt(&mut self, to_unsplit: BytesMut) {
        self.hdr.unsplit(to_unsplit)
    }
    #[inline]
    pub fn header_size(&self) -> usize {
        RXE_OPCODE_INFO[self.opcode as usize].length as usize
    }
    #[inline]
    fn get_bth_hdr(&self) -> &RxeBth {
        unsafe { &*(self.hdr.as_ptr() as *const RxeBth) }
    }

    #[inline]
    fn get_mut_bth_hdr(&mut self) -> &mut RxeBth {
        unsafe { &mut *(self.hdr.as_mut_ptr() as *mut RxeBth) }
    }

    // Get IBA headers by offset
    #[inline]
    fn get_iba_hdr<T>(&self, iba_hdr_base: usize) -> &T {
        unsafe {
            &*(self
                .hdr
                .as_ptr()
                .add(RXE_OPCODE_INFO[self.opcode as usize].offset[iba_hdr_base] as usize)
                as *const T)
        }
    }
    #[inline]
    fn get_mut_iba_hdr<T>(&mut self, iba_hdr_base: usize) -> &mut T {
        unsafe {
            &mut *(self
                .hdr
                .as_mut_ptr()
                .add(RXE_OPCODE_INFO[self.opcode as usize].offset[iba_hdr_base] as usize)
                as *mut T)
        }
    }
    // Base Transport Header
    #[inline]
    pub fn bth_init(
        &mut self,
        opcode: u8,
        se: bool,
        mig: bool,
        pad: u8,
        pkey: u16,
        qpn: u32,
        ack_req: bool,
        psn: u32,
    ) {
        let bth = self.get_mut_bth_hdr();
        bth.opcode = opcode;
        bth.flags = (pad << 4) & BTH_PAD_MASK;
        if se == true {
            bth.flags = bth.flags | BTH_SE_MASK;
        }
        if mig == true {
            bth.flags = bth.flags | BTH_MIG_MASK;
        }
        bth.pkey = pkey.to_be();
        bth.qpn = (qpn & BTH_QPN_MASK).to_be();
        let mut _psn = psn & BTH_PSN_MASK;
        if ack_req == true {
            _psn |= BTH_ACK_MASK;
        }
        bth.apsn = _psn.to_be();
    }

    #[inline]
    pub fn bth_opcode(&self) -> u8 {
        let bth = self.get_bth_hdr();
        bth.opcode
    }
    #[inline]
    pub fn bth_se(&self) -> bool {
        let bth = self.get_bth_hdr();
        0 != (BTH_SE_MASK & bth.flags)
    }
    #[inline]
    pub fn bth_mig(&self) -> bool {
        let bth = self.get_bth_hdr();
        0 != (BTH_MIG_MASK & bth.flags)
    }
    #[inline]
    pub fn bth_pad(&self) -> u8 {
        let bth = self.get_bth_hdr();
        (BTH_PAD_MASK & bth.flags) >> 4
    }
    #[inline]
    pub fn bth_tver(&self) -> u8 {
        let bth = self.get_bth_hdr();
        BTH_TVER_MASK & bth.flags
    }
    #[inline]
    pub fn bth_pkey(&self) -> u16 {
        let bth = self.get_bth_hdr();
        u16::from_be(bth.pkey)
    }
    #[inline]
    pub fn bth_qpn(&self) -> u32 {
        let bth = self.get_bth_hdr();
        u32::from_be(bth.qpn) & BTH_QPN_MASK
    }
    #[inline]
    pub fn bth_fecn(&self) -> bool {
        let bth = self.get_bth_hdr();
        0 != (BTH_FECN_MASK.to_be() & (bth.flags as u32))
    }

    #[inline]
    pub fn bth_becn(&self) -> bool {
        let bth = self.get_bth_hdr();
        0 != (BTH_BECN_MASK.to_be() & (bth.flags as u32))
    }
    #[inline]
    pub fn bth_resv6a(&self) -> u8 {
        let bth = self.get_bth_hdr();
        ((BTH_RESV6A_MASK & u32::from_be(bth.qpn)) >> 24) as u8
    }
    #[inline]
    pub fn bth_ack(&self) -> bool {
        let bth = self.get_bth_hdr();
        0 != ((BTH_ACK_MASK).to_be() & bth.apsn)
    }
    #[inline]
    pub fn bth_psn(&self) -> u32 {
        let bth = self.get_bth_hdr();
        u32::from_be(bth.apsn) & BTH_PSN_MASK
    }

    #[inline]
    pub fn bth_set_opcode(&mut self, opcode: u8) {
        let bth = self.get_mut_bth_hdr();
        bth.opcode = opcode;
    }
    #[inline]
    pub fn bth_set_se(&mut self, se: bool) {
        let bth = self.get_mut_bth_hdr();
        bth.flags = if se {
            bth.flags | BTH_SE_MASK
        } else {
            bth.flags & (!BTH_SE_MASK)
        }
    }
    #[inline]
    pub fn bth_set_mig(&mut self, mig: bool) {
        let bth = self.get_mut_bth_hdr();
        bth.flags = if mig {
            bth.flags | BTH_MIG_MASK
        } else {
            bth.flags & (!BTH_MIG_MASK)
        }
    }
    #[inline]
    pub fn bth_set_pad(&mut self, pad: u8) {
        let bth = self.get_mut_bth_hdr();
        bth.flags = (BTH_PAD_MASK & (pad << 4)) | (!BTH_PAD_MASK & bth.flags);
    }
    #[inline]
    pub fn bth_set_tver(&mut self, tver: u8) {
        let bth = self.get_mut_bth_hdr();
        bth.flags = (BTH_TVER_MASK & tver) | (!BTH_TVER_MASK & bth.flags);
    }
    #[inline]
    pub fn bth_set_pkey(&mut self, pkey: u16) {
        let bth = self.get_mut_bth_hdr();
        bth.pkey = pkey.to_be()
    }
    #[inline]
    pub fn bth_set_qpn(&mut self, qpn: u32) {
        let bth = self.get_mut_bth_hdr();
        let resvqpn = u32::from_be(bth.qpn);
        bth.qpn = ((BTH_QPN_MASK & qpn) | (!BTH_QPN_MASK & resvqpn)).to_be()
    }
    #[inline]
    pub fn bth_set_fecn(&mut self, fecn: bool) {
        let bth = self.get_mut_bth_hdr();
        bth.flags = if fecn {
            bth.flags | (BTH_FECN_MASK.to_be() as u8)
        } else {
            bth.flags & (!(BTH_FECN_MASK.to_be() as u8))
        }
    }
    #[inline]
    pub fn bth_set_becn(&mut self, becn: bool) {
        let bth = self.get_mut_bth_hdr();
        bth.flags = if becn {
            bth.flags | (BTH_BECN_MASK.to_be() as u8)
        } else {
            bth.flags & (!(BTH_BECN_MASK.to_be() as u8))
        }
    }
    #[inline]
    pub fn bth_set_resv6a(&mut self) {
        let bth = self.get_mut_bth_hdr();
        bth.qpn = (!BTH_RESV6A_MASK).to_be();
    }
    #[inline]
    pub fn bth_set_ack(&mut self, ack: bool) {
        let bth = self.get_mut_bth_hdr();
        bth.qpn = if ack {
            bth.apsn | (BTH_ACK_MASK.to_be())
        } else {
            bth.apsn & (!(BTH_ACK_MASK.to_be()))
        }
    }
    #[inline]
    pub fn bth_set_psn(&mut self, psn: u32) {
        let bth = self.get_mut_bth_hdr();
        let apsn = u32::from_be(bth.apsn);
        bth.apsn = ((BTH_PSN_MASK & psn) | (!BTH_PSN_MASK & apsn)).to_be()
    }

    // Reliable Datagram Extended Transport Header
    #[inline]
    pub fn rdeth_een(&self) -> u32 {
        let rdeth = self.get_iba_hdr::<RxeRdeth>(RXE_RDETH as usize);
        u32::from_be(rdeth.een) & RDETH_EEN_MASK
    }
    #[inline]
    pub fn rdeth_set_een(&mut self, een: u32) {
        let rdeth = self.get_mut_iba_hdr::<RxeRdeth>(RXE_RDETH as usize);
        rdeth.een = (een & RDETH_EEN_MASK).to_be();
    }

    // Datagram Extended Transport Header
    #[inline]
    pub fn deth_qkey(&self) -> u32 {
        let deth = self.get_iba_hdr::<RxeDeth>(RXE_DETH as usize);
        u32::from_be(deth.qkey)
    }
    #[inline]
    pub fn deth_sqp(&self) -> u32 {
        let deth = self.get_iba_hdr::<RxeDeth>(RXE_DETH as usize);
        u32::from_be(deth.sqp) & DETH_SQP_MASK
    }
    #[inline]
    pub fn deth_set_qkey(&mut self, qkey: u32) {
        let deth = self.get_mut_iba_hdr::<RxeDeth>(RXE_DETH as usize);
        deth.qkey = qkey.to_be();
    }
    #[inline]
    pub fn deth_set_sqp(&mut self, sqp: u32) {
        let deth = self.get_mut_iba_hdr::<RxeDeth>(RXE_DETH as usize);
        deth.sqp = (sqp & DETH_SQP_MASK).to_be();
    }
    // RDMA Extended Transport Header
    #[inline]
    pub fn reth_rkey(&self) -> u32 {
        let reth = self.get_iba_hdr::<RxeReth>(RXE_RETH as usize);
        u32::from_be(reth.rkey)
    }
    #[inline]
    pub fn reth_va(&self) -> u64 {
        let reth = self.get_iba_hdr::<RxeReth>(RXE_RETH as usize);
        u64::from_be(reth.va)
    }
    #[inline]
    pub fn reth_len(&self) -> u32 {
        let reth = self.get_iba_hdr::<RxeReth>(RXE_RETH as usize);
        u32::from_be(reth.len)
    }
    #[inline]
    pub fn reth_set_rkey(&mut self, rkey: u32) {
        let reth = self.get_mut_iba_hdr::<RxeReth>(RXE_RETH as usize);
        reth.rkey = rkey.to_be();
    }
    #[inline]
    pub fn reth_set_va(&mut self, va: u64) {
        let reth = self.get_mut_iba_hdr::<RxeReth>(RXE_RETH as usize);
        reth.va = va.to_be();
    }
    #[inline]
    pub fn reth_set_len(&mut self, len: u32) {
        let reth = self.get_mut_iba_hdr::<RxeReth>(RXE_RETH as usize);
        reth.len = len.to_be();
    }
    // Atomic Extended Transport Header
    #[inline]
    pub fn atmeth_va(&self) -> u64 {
        let atmeth = self.get_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        u64::from_be(atmeth.va)
    }
    #[inline]
    pub fn atmeth_rkey(&self) -> u32 {
        let atmeth = self.get_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        u32::from_be(atmeth.rkey)
    }
    #[inline]
    pub fn atmeth_swap_add(&self) -> u64 {
        let atmeth = self.get_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        u64::from_be(atmeth.swap_add)
    }
    #[inline]
    pub fn atmeth_comp(&self) -> u64 {
        let atmeth = self.get_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        u64::from_be(atmeth.comp)
    }
    #[inline]
    pub fn atmeth_set_va(&mut self, va: u64) {
        let atmeth = self.get_mut_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        atmeth.va = va.to_be()
    }
    #[inline]
    pub fn atmeth_set_rkey(&mut self, rkey: u32) {
        let atmeth = self.get_mut_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        atmeth.rkey = rkey.to_be()
    }
    #[inline]
    pub fn atmeth_set_swap_add(&mut self, swap_add: u64) {
        let atmeth = self.get_mut_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        atmeth.swap_add = swap_add.to_be()
    }
    #[inline]
    pub fn atmeth_set_comp(&mut self, comp: u64) {
        let atmeth = self.get_mut_iba_hdr::<RxeAtmeth>(RXE_ATMETH as usize);
        atmeth.comp = comp.to_be()
    }
    // Ack Extended Transport Header
    #[inline]
    pub fn aeth_smsn(&self) -> u32 {
        let aeth = self.get_iba_hdr::<RxeAeth>(RXE_AETH as usize);
        u32::from_be(aeth.smsn) & AETH_MSN_MASK
    }
    #[inline]
    pub fn aeth_syn(&self) -> u8 {
        let aeth = self.get_iba_hdr::<RxeAeth>(RXE_AETH as usize);
        ((AETH_SYN_MASK & u32::from_be(aeth.smsn)) >> 24) as u8
    }
    #[inline]
    pub fn aeth_set_smsn(&mut self, smsn: u32) {
        let aeth = self.get_mut_iba_hdr::<RxeAeth>(RXE_AETH as usize);
        aeth.smsn = smsn.to_be()
    }
    #[inline]
    pub fn aeth_set_syn(&mut self, syn: u8) {
        let aeth = self.get_mut_iba_hdr::<RxeAeth>(RXE_AETH as usize);
        let smsn: u32 = u32::from_be(aeth.smsn);
        aeth.smsn = ((AETH_SYN_MASK & ((syn as u32) << 24)) | (!AETH_SYN_MASK & smsn)).to_be();
    }
    // Atomic Ack Extended Transport Header
    #[inline]
    pub fn atmack_orig(&self) -> u64 {
        let atmack = self.get_iba_hdr::<RxeAtmack>(RXE_ATMACK as usize);
        u64::from_be(atmack.orig)
    }
    #[inline]
    pub fn atmack_set_orig(&mut self, orig: u64) {
        let atmack = self.get_mut_iba_hdr::<RxeAtmack>(RXE_ATMACK as usize);
        atmack.orig = orig.to_be()
    }
    // Immediate Extended Transport Header
    #[inline]
    pub fn immdt_imm(&self) -> u32 {
        let immdt = self.get_iba_hdr::<RxeImmdt>(RXE_IMMDT as usize);
        u32::from_be(immdt.imm)
    }
    #[inline]
    pub fn immdt_set_imm(&mut self, imm_be: u32) {
        let immdt = self.get_mut_iba_hdr::<RxeImmdt>(RXE_IMMDT as usize);
        // imm is in big endian
        immdt.imm = imm_be
    }
    // Invalidate Extended Transport Header
    #[inline]
    pub fn ieth_rkey(&self) -> u32 {
        let ieth = self.get_iba_hdr::<RxeIeth>(RXE_IETH as usize);
        u32::from_be(ieth.rkey)
    }
    #[inline]
    pub fn ieth_set_rkey(&mut self, rkey: u32) {
        let ieth = self.get_mut_iba_hdr::<RxeIeth>(RXE_IETH as usize);
        ieth.rkey = rkey.to_be()
    }
}
#[cfg(test)]
mod tests {
    use rdma_sys::ibv_opcode::*;

    use crate::rxe_hdr::rxe_hdr_length::{RXE_AETH_BYTES, RXE_DETH_BYTES};

    use super::{
        rxe_hdr_length::{RXE_BTH_BYTES, RXE_RETH_BYTES},
        *,
    };
    #[test]
    fn check_rxe_hdr_length() {
        // Refer to IB Sepc Vol1 Ver1.3 Chap5: Data packet format for definition of length
        assert_eq!(
            ::std::mem::size_of::<RxeBth>(),
            12usize,
            concat!("Size of: ", stringify!(RxeBth))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeDeth>(),
            8usize,
            concat!("Size of: ", stringify!(RxeDeth))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeImmdt>(),
            4usize,
            concat!("Size of: ", stringify!(RxeImmdt))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeReth>(),
            16usize,
            concat!("Size of: ", stringify!(RxeReth))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeAeth>(),
            4usize,
            concat!("Size of: ", stringify!(RxeAeth))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeAtmack>(),
            8usize,
            concat!("Size of: ", stringify!(RxeAtmack))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeAtmeth>(),
            28usize,
            concat!("Size of: ", stringify!(RxeAtmeth))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeIeth>(),
            4usize,
            concat!("Size of: ", stringify!(RxeIeth))
        );

        assert_eq!(
            ::std::mem::size_of::<RxeRdeth>(),
            4usize,
            concat!("Size of: ", stringify!(RxeRdeth))
        );
    }
    #[test]
    fn check_base_transport_header() {
        let mut rxe_pkt = rxe_pkt_info_zerod();
        // RC Ack
        let opcode = IBV_OPCODE_RC_ACKNOWLEDGE;
        let hdr_len = rxe_pkt.get_iba_hdr_len();
        rxe_pkt.set_iba_pkt_len(hdr_len);
        let dest_qp = 0x18;
        let psn = 0xC8002C;
        rxe_pkt.bth_init(opcode, false, false, 0, 0xFFFF, dest_qp, false, psn);
        let golden_from_pcap = [0x11, 00, 0xff, 0xff, 00, 00, 00, 0x18, 00, 0xc8, 00, 0x2c];
        assert_eq!(rxe_pkt.hdr.to_vec().len(), golden_from_pcap.len());
        assert_eq!(rxe_pkt.hdr.to_vec(), golden_from_pcap);
        // set headers by setters funcion
        rxe_pkt.bth_set_opcode(opcode);
        rxe_pkt.bth_set_qpn(dest_qp);
        rxe_pkt.bth_set_psn(psn);

        assert_eq!(opcode, rxe_pkt.bth_opcode());
        assert_eq!(dest_qp, rxe_pkt.bth_qpn());
        assert_eq!(psn, rxe_pkt.bth_psn())
    }
    // Datagram Extended Transport Header
    #[test]
    fn check_datagram_extended_transport_header() {
        let mut rxe_pkt = rxe_pkt_info_zerod();
        // UD send only
        rxe_pkt.opcode = IBV_OPCODE_UD_SEND_ONLY;
        let hdr_len = rxe_pkt.get_iba_hdr_len();
        rxe_pkt.set_iba_pkt_len(hdr_len);
        let qkey = 0x11111111;
        let src_qp = 0x23;
        rxe_pkt.deth_set_qkey(qkey);
        rxe_pkt.deth_set_sqp(src_qp);
        let golden_from_pcap = [0x11, 0x11, 0x11, 0x11, 00, 00, 00, 0x23];
        assert_eq!(rxe_pkt.hdr.len(), (RXE_BTH_BYTES + RXE_DETH_BYTES) as _);
        assert_eq!(rxe_pkt.hdr.to_vec()[RXE_BTH_BYTES as _..], golden_from_pcap);
        assert_eq!(qkey, rxe_pkt.deth_qkey());
        assert_eq!(src_qp, rxe_pkt.deth_sqp());
    }
    //  RDMA Extended Transport Header
    #[test]
    fn check_rdma_extended_transport_header() {
        let mut rxe_pkt = rxe_pkt_info_zerod();
        // RDMA Read
        rxe_pkt.opcode = IBV_OPCODE_RC_RDMA_READ_REQUEST;
        let hdr_len = rxe_pkt.get_iba_hdr_len();
        rxe_pkt.set_iba_pkt_len(hdr_len);
        let len = 0x0a;
        let va = 0x00005617c3486500;
        let rkey = 0x00001208;
        rxe_pkt.reth_set_len(len);
        rxe_pkt.reth_set_va(va);
        rxe_pkt.reth_set_rkey(0x00001208);
        let golden_from_pcap = [
            00, 00, 0x56, 0x17, 0xc3, 0x48, 0x65, 00, 00, 00, 0x12, 0x08, 00, 00, 00, 0x0a,
        ];
        assert_eq!(rxe_pkt.hdr.len(), (RXE_BTH_BYTES + RXE_RETH_BYTES) as _);
        assert_eq!(rxe_pkt.hdr.to_vec()[RXE_BTH_BYTES as _..], golden_from_pcap);
        assert_eq!(len, rxe_pkt.reth_len());
        assert_eq!(va, rxe_pkt.reth_va());
        assert_eq!(rkey, rxe_pkt.reth_rkey());
    }

    // Ack Extended Transport Header
    #[test]
    fn check_ack_ex_transport_header() {
        let mut rxe_pkt = rxe_pkt_info_zerod();
        //  RC ACK
        rxe_pkt.opcode = IBV_OPCODE_RC_ACKNOWLEDGE;
        let hdr_len = rxe_pkt.get_iba_hdr_len();
        rxe_pkt.set_iba_pkt_len(hdr_len);
        let smsn = 1;
        rxe_pkt.aeth_set_smsn(smsn);
        rxe_pkt.aeth_set_syn(aeth_syndrome::AETH_ACK_UNLIMITED);
        let golden_from_pcap = [0x1f, 00, 00, 0x01];
        assert_eq!(rxe_pkt.hdr.len(), (RXE_BTH_BYTES + RXE_AETH_BYTES) as _);
        assert_eq!(rxe_pkt.hdr.to_vec()[RXE_BTH_BYTES as _..], golden_from_pcap);
        assert_eq!(smsn, rxe_pkt.aeth_smsn());
        assert_eq!(aeth_syndrome::AETH_ACK_UNLIMITED, rxe_pkt.aeth_syn());
    }
    // TODO:
    // Atomic Extended Transport Header
    // Immediate Extended Transport Header
    // Invalidate Extended Transport Header

    fn rxe_pkt_info_zerod() -> RxePktInfo {
        RxePktInfo::new(0, 0, 0, 0, 0, 0, 1024)
    }
}
