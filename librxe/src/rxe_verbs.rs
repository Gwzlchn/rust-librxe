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

// defination from upstream-kernel/include/rdma/ib_verbs.h
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

// defination from kernel/include/rdma/ib_mad.h
pub const IB_DEFAULT_PKEY_PARTIAL: u16 = 0x7FFF;
pub const IB_DEFAULT_PKEY_FULL: u16 = 0xFFFF;

// defination from kernel/drivers/infiniband/sw/rxe/rxe.h
pub const RXE_ROCE_V2_SPORT: u16 = 0xC000;

// defination from linux-kernel/upstream-kernel/include/rdma/ib_verbs.h
const MAX_MTU_ARRAY_ENTRY: usize = 6;
pub const ibv_mtu_enum_to_u32: [u32; MAX_MTU_ARRAY_ENTRY] = {
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
