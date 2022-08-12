#[macro_export]
macro_rules! BIT {
    ($nr:expr) => {{
        1u32 << $nr
    }};
}

///Return >0 if psn_a > psn_b;
///	      =0 if psn_a == psn_b;
///	      <0 if psn_a < psn_b
///
#[inline]
pub fn psn_compare(psn_a: u32, psn_b: u32) -> i32 {
    let diff: i32 = (psn_a as i32 - psn_b as i32) << 8;
    diff
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum WqeState {
    WqeStatePosted,
    WqeStateProcessing,
    WqeStatePending,
    WqeStateDone,
    WqeStateError,
}

#[derive(Debug, Clone, Copy)]
pub enum RxeMrCopyDir {
    RxeToMrObj,
    RxeFromMrObj,
}

// defination from kernel/include/rdma/ib_mad.h
pub const IB_DEFAULT_PKEY_PARTIAL: u16 = 0x7FFF;
pub const IB_DEFAULT_PKEY_FULL: u16 = 0xFFFF;

// defination from kernel/drivers/infiniband/sw/rxe/rxe.h
pub const RXE_ROCE_V2_SPORT: u16 = 0xC000;

// defination from linux-kernel/upstream-kernel/include/rdma/ib_verbs.h
#[inline]
pub fn ibv_mtu_enum_to_u32(mtu: rdma_sys::ibv_mtu::Type) -> u32 {
    match mtu {
        IBV_MTU_256 => 256,
        IBV_MTU_512 => 512,
        IBV_MTU_1024 => 1024,
        IBV_MTU_2048 => 2048,
        IBV_MTU_4096 => 4096,
    }
}

pub const RXE_NETWORK_TYPE_IPV4: u8 = 1;
pub const RXE_NETWORK_TYPE_IPV6: u8 = 2;
