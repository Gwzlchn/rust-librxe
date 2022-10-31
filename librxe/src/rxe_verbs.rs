use rdma_sys::ibv_mtu;

#[macro_export]
macro_rules! BIT {
    ($nr:expr) => {{
        1u32 << $nr
    }};
}

// defination from kernel/drivers/infiniband/sw/rxe/rxe_verbs.h

///Return >0 if psn_a > psn_b;
///	      =0 if psn_a == psn_b;
///	      <0 if psn_a < psn_b
///
#[inline]
pub fn psn_compare(psn_a: u32, psn_b: u32) -> i32 {
    let diff: i32 = (psn_a as i32 - psn_b as i32) << 8;
    diff
}

#[inline]
pub fn pkey_match(key1: u16, key2: u16) -> bool {
    return ((key1 & 0x7fff) != 0)
        && ((key1 & 0x7fff) == (key2 & 0x7fff))
        && ((key1 & 0x8000) != 0 || (key2 & 0x8000) != 0);
}

#[derive(Debug, Clone, Copy)]
pub enum WqeState {
    WqeStatePosted,
    WqeStateProcessing,
    WqeStatePending,
    WqeStateDone,
    WqeStateError,
}

impl PartialEq<u32> for WqeState {
    fn eq(&self, other: &u32) -> bool {
        *self as u32 == *other as u32
    }
}

impl PartialEq<WqeState> for u32 {
    fn eq(&self, other: &WqeState) -> bool {
        *self as u32 == *other as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum RxeMrState {
    RxeMrStateInvalid,
    RxeMrStateFree,
    RxeMrStateValid,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RxeMrCopyDir {
    RxeToMrObj,
    RxeFromMrObj,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum RxeMrLookupType {
    RxeLookupLocal,
    RxeLookupRemote,
}

#[derive(Default, Debug, Clone, Copy)]
pub enum RdatmResState {
    #[default]
    RdatmResStateNext,
    RdatmResStateNew,
    RdatmResStateReplay,
}

// defination from rdma-core/libibverbs/driver.h
#[derive(Debug, Clone, Copy)]
pub enum IbvMrType {
    IbvMrTypeMr,
    IbvMrTypeNullMr,
    IbvMrTypeImportedMr,
    IbvMrTypeDmaBufMr,
}

// defination from kernel/include/rdma/ib_verbs.h
#[derive(Debug, Clone, Copy)]
pub enum IbMrType {
    IbMrTypeMemReg,
    IbMrTypeSgGaps,
    IbMrTypeDm,
    // memory region that is used for the user-space application
    IbMrTypeUser,
    IbMrTypeDma,
    IbMrTypeIntegrity,
}

pub mod ib_rnr_timeout {
    pub type Type = u8;
    pub const IB_RNR_TIMER_655_36: Type = 0;
    pub const IB_RNR_TIMER_000_01: Type = 1;
    pub const IB_RNR_TIMER_000_02: Type = 2;
    pub const IB_RNR_TIMER_000_03: Type = 3;
    pub const IB_RNR_TIMER_000_04: Type = 4;
    pub const IB_RNR_TIMER_000_06: Type = 5;
    pub const IB_RNR_TIMER_000_08: Type = 6;
    pub const IB_RNR_TIMER_000_12: Type = 7;
    pub const IB_RNR_TIMER_000_16: Type = 8;
    pub const IB_RNR_TIMER_000_24: Type = 9;
    pub const IB_RNR_TIMER_000_32: Type = 10;
    pub const IB_RNR_TIMER_000_48: Type = 11;
    pub const IB_RNR_TIMER_000_64: Type = 12;
    pub const IB_RNR_TIMER_000_96: Type = 13;
    pub const IB_RNR_TIMER_001_28: Type = 14;
    pub const IB_RNR_TIMER_001_92: Type = 15;
    pub const IB_RNR_TIMER_002_56: Type = 16;
    pub const IB_RNR_TIMER_003_84: Type = 17;
    pub const IB_RNR_TIMER_005_12: Type = 18;
    pub const IB_RNR_TIMER_007_68: Type = 19;
    pub const IB_RNR_TIMER_010_24: Type = 20;
    pub const IB_RNR_TIMER_015_36: Type = 21;
    pub const IB_RNR_TIMER_020_48: Type = 22;
    pub const IB_RNR_TIMER_030_72: Type = 23;
    pub const IB_RNR_TIMER_040_96: Type = 24;
    pub const IB_RNR_TIMER_061_44: Type = 25;
    pub const IB_RNR_TIMER_081_92: Type = 26;
    pub const IB_RNR_TIMER_122_88: Type = 27;
    pub const IB_RNR_TIMER_163_84: Type = 28;
    pub const IB_RNR_TIMER_245_76: Type = 29;
    pub const IB_RNR_TIMER_327_68: Type = 30;
    pub const IB_RNR_TIMER_491_52: Type = 31;
}

// defination from kernel/include/rdma/ib_mad.h
pub const IB_DEFAULT_PKEY_PARTIAL: u16 = 0x7FFF;
pub const IB_DEFAULT_PKEY_FULL: u16 = 0xFFFF;

// defination from kernel/drivers/infiniband/sw/rxe/rxe.h
pub const RXE_ROCE_V2_SPORT: u16 = 0xC000;

// defination from kernel/include/rdma/ib_verbs.h
const MAX_MTU_ARRAY_ENTRY: usize = 6;
pub const IBV_MTU_ENUM_TO_U32: [u32; MAX_MTU_ARRAY_ENTRY] = {
    let mut mtu_arr = [0u32; MAX_MTU_ARRAY_ENTRY];
    mtu_arr[ibv_mtu::IBV_MTU_256 as usize] = 256;
    mtu_arr[ibv_mtu::IBV_MTU_512 as usize] = 512;
    mtu_arr[ibv_mtu::IBV_MTU_1024 as usize] = 1024;
    mtu_arr[ibv_mtu::IBV_MTU_2048 as usize] = 2048;
    mtu_arr[ibv_mtu::IBV_MTU_4096 as usize] = 4096;
    mtu_arr
};
pub const IB_MULTICAST_QPN: u32 = 0xffffff;

pub const RXE_NETWORK_TYPE_IPV4: u8 = 1;
pub const RXE_NETWORK_TYPE_IPV6: u8 = 2;
