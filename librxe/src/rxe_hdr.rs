use bytes::BytesMut;
use crate::rxe_opcode::*;
use crate::rxe_opcode::rxe_hdr_type::*;

#[derive(Debug, Clone)]
pub struct RxePktInfo {
    pub hdr: BytesMut,   /* all IBA headers buffer */
    pub mask: u32,       /* useful info about pkt */
    pub psn: u32,        /* bth psn of packet */
    pub pkey_index: u16, /* partition of pkt */
    pub paylen: u16,     /* length of bth - icrc*/
    pub port_num: u8,    /* port pkt received on */
    pub opcode: u8,      /* bth opcode of packet */
}

/*
 * IBA header types and methods
 *
 */
pub const RXE_ICRC_SIZE: u32 = 4;
pub const RXE_MAX_HDR_LENGTH: u32 = 80;

pub const BTH_TVER: u32 = 0;
pub const BTH_DEF_PKEY: u32 = 0xffff;
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

/******************************************************************************
 * Reliable Datagram Extended Transport Header
 ******************************************************************************/
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RxeRdeth {
    // in bigendian
    pub een: u32,
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
    #[inline]
    pub fn new(
        mask: u32,
        psn: u32,
        pkey_index: u16,
        paylen: u16,
        port_num: u8,
        opcode: u8,
    ) -> Self {
        RxePktInfo {
            hdr: BytesMut::with_capacity(RXE_MAX_HDR_LENGTH as _),
            mask: mask,
            psn: psn,
            pkey_index: pkey_index,
            paylen: paylen,
            port_num: port_num,
            opcode: opcode,
        }
    }

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
        let mut bth = unsafe { &mut *(self.hdr.as_mut_ptr() as *mut RxeBth) };

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
        unsafe { self.hdr.set_len(rxe_hdr_length::RXE_BTH_BYTES as _) }
    }
    // call this func after opcode was set correctly
    #[inline]
    pub fn init_iba_hdr_buf_len(&mut self) {
        let len = RXE_OPCODE_INFO[self.opcode as usize].offset[RXE_PAYLOAD as usize] as usize;
        unsafe { self.hdr.set_len(len) }
    }

    // RDMA Extended Transport Header
    #[inline]
    fn get_mut_reth_hdr(&mut self) -> &mut RxeReth {
        unsafe {
            &mut *(self
                .hdr
                .as_mut_ptr()
                .add(RXE_OPCODE_INFO[self.opcode as usize].offset[RXE_RETH as usize] as usize)
                as *mut RxeReth)
        }
    }
    #[inline]
    pub fn reth_set_rkey(&mut self, rkey: u32) {
        let reth = self.get_mut_reth_hdr();
        reth.rkey = rkey.to_be();
    }
    #[inline]
    pub fn reth_set_va(&mut self, va: u64) {
        let reth = self.get_mut_reth_hdr();
        reth.va = va.to_be();
    }
    #[inline]
    pub fn reth_set_len(&mut self, len: u32) {
        let reth = self.get_mut_reth_hdr();
        reth.len = len.to_be();
    }
}
#[cfg(test)]
mod tests {
    use rdma_sys::ibv_opcode::*;

    use super::{*, rxe_hdr_length::{RXE_BTH_BYTES, RXE_RETH_BYTES}};
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
    fn check_base_transport_header_init() {
        let mut rxe_pkt = rxe_pkt_info_init();
        // A RC Send first
        rxe_pkt.bth_init(
            IBV_OPCODE_RC_SEND_FIRST,
            false,
            false,
            0,
            0xFFFF,
            0x1B,
            false,
            0x2ACE5B,
        );
        let golden_rc_send_first = [00, 00, 0xff, 0xff, 00, 00, 00, 0x1b, 00, 0x2a, 0xce, 0x5b];
        assert_eq!(rxe_pkt.hdr.to_vec().len(), golden_rc_send_first.len());
        assert_eq!(rxe_pkt.hdr.to_vec(), golden_rc_send_first);
    }

    #[test]
    fn check_rdma_ex_transport_header() {
        let mut rxe_pkt = rxe_pkt_info_init();
        rxe_pkt.opcode = IBV_OPCODE_RC_RDMA_READ_REQUEST;
        rxe_pkt.init_iba_hdr_buf_len();

        rxe_pkt.reth_set_len(0x0a);
        rxe_pkt.reth_set_va(0x00005617c3486500);
        rxe_pkt.reth_set_rkey(0x00001208);
        let golden = [00, 00, 0x56 , 0x17 ,0xc3 ,0x48,0x65, 00, 00, 00, 0x12 ,0x08, 00, 00 ,00, 0x0a];
        assert_eq!(rxe_pkt.hdr.len(), (RXE_BTH_BYTES + RXE_RETH_BYTES)as _);
        assert_eq!(
            rxe_pkt.hdr.to_vec()[RXE_BTH_BYTES as _..],
            golden
        )
    }

    fn rxe_pkt_info_init() -> RxePktInfo {
        RxePktInfo::new(0x11111111, 0x22222222, 0x3333, 0x4444, 0x1, 0x1)
    }
}
