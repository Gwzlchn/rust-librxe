#[derive(Debug, Clone, Copy)]
pub struct RxePktInfo<'a> {
    pub hdr: &'a RxeBth,
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
pub const RXE_ICRC_SIZE: u64 = 4;
pub const RXE_MAX_HDR_LENGTH: u64 = 80;

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
    pub type Type = usize;
    pub const RXE_BTH_BYTES: Type = ::std::mem::size_of::<RxeBth>();
    pub const RXE_DETH_BYTES: Type = ::std::mem::size_of::<RxeDeth>();
    pub const RXE_IMMDT_BYTES: Type = ::std::mem::size_of::<RxeImmdt>();
    pub const RXE_RETH_BYTES: Type = ::std::mem::size_of::<RxeReth>();
    pub const RXE_AETH_BYTES: Type = ::std::mem::size_of::<RxeAeth>();
    pub const RXE_ATMACK_BYTES: Type = ::std::mem::size_of::<RxeAtmack>();
    pub const RXE_ATMETH_BYTES: Type = ::std::mem::size_of::<RxeAtmeth>();
    pub const RXE_IETH_BYTES: Type = ::std::mem::size_of::<RxeIeth>();
    pub const RXE_RDETH_BYTES: Type = ::std::mem::size_of::<RxeRdeth>();
}

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
