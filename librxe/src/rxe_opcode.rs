#![allow(dead_code)]
/// RXE Work request mask
pub mod rxe_wr_mask {
    use crate::BIT;
    pub type Type = u32;
    pub const WR_INLINE_MASK: Type = BIT!(0);
    pub const WR_ATOMIC_MASK: Type = BIT!(1);
    pub const WR_SEND_MASK: Type = BIT!(2);
    pub const WR_READ_MASK: Type = BIT!(3);
    pub const WR_WRITE_MASK: Type = BIT!(4);
    pub const WR_LOCAL_OP_MASK: Type = BIT!(5);
    pub const WR_READ_OR_WRITE_MASK: Type = WR_READ_MASK | WR_WRITE_MASK;
    pub const WR_WRITE_OR_SEND_MASK: Type = WR_WRITE_MASK | WR_SEND_MASK;
    pub const WR_ATOMIC_OR_READ_MASK: Type = WR_ATOMIC_MASK | WR_READ_MASK;
}

const WR_MAX_QPT: usize = 8;
const WR_MAX_OPCODE: usize = 16;

/// A two-dimensional matrix to store all work-request masks
/// The number of rows equals to WR_MAX_OPCODE, representing all Work-Request operation types
/// The number of columes equals to WR_MAX_QPT, representing all Queue-Pair types
pub const RXE_WR_OPCODE_INFO: [[rxe_wr_mask::Type; WR_MAX_QPT]; WR_MAX_OPCODE as usize] = {
    use rdma_sys::{ibv_qp_type::*, ibv_wr_opcode::*};
    use rxe_wr_mask::*;
    let mut arr = [[0x0; WR_MAX_QPT]; WR_MAX_OPCODE];
    arr[IBV_WR_RDMA_WRITE as usize][IBV_QPT_RC as usize as usize] = WR_INLINE_MASK | WR_WRITE_MASK;
    arr[IBV_WR_RDMA_WRITE as usize][IBV_QPT_UC as usize as usize] = WR_INLINE_MASK | WR_WRITE_MASK;

    arr[IBV_WR_RDMA_WRITE_WITH_IMM as usize][IBV_QPT_UC as usize as usize] =
        WR_INLINE_MASK | WR_WRITE_MASK;
    arr[IBV_WR_RDMA_WRITE_WITH_IMM as usize][IBV_QPT_UC as usize as usize] =
        WR_INLINE_MASK | WR_WRITE_MASK;

    arr[IBV_WR_SEND as usize][IBV_QPT_RC as usize as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    arr[IBV_WR_SEND as usize][IBV_QPT_UC as usize as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    arr[IBV_WR_SEND as usize][IBV_QPT_UD as usize as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    // FIXME: ignore the IB_QPT_GSI type

    arr[IBV_WR_SEND_WITH_IMM as usize][IBV_QPT_RC as usize as usize] =
        WR_INLINE_MASK | WR_SEND_MASK;
    arr[IBV_WR_SEND_WITH_IMM as usize][IBV_QPT_UC as usize as usize] =
        WR_INLINE_MASK | WR_SEND_MASK;
    arr[IBV_WR_SEND_WITH_IMM as usize][IBV_QPT_UD as usize as usize] =
        WR_INLINE_MASK | WR_SEND_MASK;
    // FIXME: ignore the IB_QPT_GSI type

    arr[IBV_WR_RDMA_READ as usize][IBV_QPT_RC as usize as usize] = WR_SEND_MASK;

    arr[IBV_WR_ATOMIC_CMP_AND_SWP as usize][IBV_QPT_RC as usize as usize] = WR_ATOMIC_MASK;

    arr[IBV_WR_ATOMIC_FETCH_AND_ADD as usize][IBV_QPT_RC as usize as usize] = WR_ATOMIC_MASK;

    // IB_WR_LSO is not supported in RXE

    arr[IBV_WR_SEND_WITH_INV as usize][IBV_QPT_RC as usize as usize] =
        WR_INLINE_MASK | WR_SEND_MASK;
    arr[IBV_WR_SEND_WITH_INV as usize][IBV_QPT_UC as usize as usize] =
        WR_INLINE_MASK | WR_SEND_MASK;
    arr[IBV_WR_SEND_WITH_INV as usize][IBV_QPT_UD as usize as usize] =
        WR_INLINE_MASK | WR_SEND_MASK;

    // IBV_WR_DRIVER1 = 11, IB_UVERBS_WR_RDMA_READ_WITH_INV = 11 also
    arr[IBV_WR_DRIVER1 as usize][IBV_QPT_UD as usize as usize] = WR_READ_MASK;

    arr[IBV_WR_LOCAL_INV as usize][IBV_QPT_UD as usize as usize] = WR_LOCAL_OP_MASK;

    arr[IBV_WR_BIND_MW as usize][IBV_QPT_RC as usize as usize] = WR_LOCAL_OP_MASK;
    arr[IBV_WR_BIND_MW as usize][IBV_QPT_UC as usize as usize] = WR_LOCAL_OP_MASK;

    // FIXME: ignore IB_WR_REG_MR  wqe type

    arr
};

/// Get WR mask by current wqe opcode and qp type
#[inline]
pub fn wr_opcode_mask(qp_type: rdma_sys::ibv_qp_type::Type, opcode: u32) -> u32 {
    RXE_WR_OPCODE_INFO[opcode as usize][qp_type as usize]
}
pub mod rxe_hdr_type {
    pub type Type = u8;
    pub const RXE_LRH: Type = 0;
    pub const RXE_GRH: Type = 1;
    pub const RXE_BTH: Type = 2;
    pub const RXE_RETH: Type = 3;
    pub const RXE_AETH: Type = 4;
    pub const RXE_ATMETH: Type = 5;
    pub const RXE_ATMACK: Type = 6;
    pub const RXE_IETH: Type = 7;
    pub const RXE_RDETH: Type = 8;
    pub const RXE_DETH: Type = 9;
    pub const RXE_IMMDT: Type = 10;
    pub const RXE_PAYLOAD: Type = 11;
    pub const NUM_HDR_TYPES: Type = 12;
}

pub mod rxe_hdr_mask {
    use super::rxe_hdr_type::*;
    use crate::BIT;
    pub type Type = u32;
    pub const RXE_LRH_MASK: Type = BIT!(RXE_LRH);
    pub const RXE_GRH_MASK: Type = BIT!(RXE_GRH);
    pub const RXE_BTH_MASK: Type = BIT!(RXE_BTH);
    pub const RXE_IMMDT_MASK: Type = BIT!(RXE_IMMDT);
    pub const RXE_RETH_MASK: Type = BIT!(RXE_RETH);
    pub const RXE_AETH_MASK: Type = BIT!(RXE_AETH);
    pub const RXE_ATMETH_MASK: Type = BIT!(RXE_ATMETH);
    pub const RXE_ATMACK_MASK: Type = BIT!(RXE_ATMACK);
    pub const RXE_IETH_MASK: Type = BIT!(RXE_IETH);
    pub const RXE_RDETH_MASK: Type = BIT!(RXE_RDETH);
    pub const RXE_DETH_MASK: Type = BIT!(RXE_DETH);
    pub const RXE_PAYLOAD_MASK: Type = BIT!(RXE_PAYLOAD);
    pub const RXE_REQ_MASK: Type = BIT!(NUM_HDR_TYPES + 0);
    pub const RXE_ACK_MASK: Type = BIT!(NUM_HDR_TYPES + 1);
    pub const RXE_SEND_MASK: Type = BIT!(NUM_HDR_TYPES + 2);
    pub const RXE_WRITE_MASK: Type = BIT!(NUM_HDR_TYPES + 3);
    pub const RXE_READ_MASK: Type = BIT!(NUM_HDR_TYPES + 4);
    pub const RXE_ATOMIC_MASK: Type = BIT!(NUM_HDR_TYPES + 5);
    pub const RXE_RWR_MASK: Type = BIT!(NUM_HDR_TYPES + 6);
    pub const RXE_COMP_MASK: Type = BIT!(NUM_HDR_TYPES + 7);
    pub const RXE_START_MASK: Type = BIT!(NUM_HDR_TYPES + 8);
    pub const RXE_MIDDLE_MASK: Type = BIT!(NUM_HDR_TYPES + 9);
    pub const RXE_END_MASK: Type = BIT!(NUM_HDR_TYPES + 10);
    pub const RXE_LOOPBACK_MASK: Type = BIT!(NUM_HDR_TYPES + 12);
    pub const RXE_READ_OR_ATOMIC_MASK: Type = RXE_READ_MASK | RXE_ATOMIC_MASK;
    pub const RXE_WRITE_OR_SEND_MASK: Type = RXE_WRITE_MASK | RXE_SEND_MASK;
    pub const RXE_READ_OR_WRITE_MASK: Type = RXE_READ_MASK | RXE_WRITE_MASK;
}

#[derive(Debug, Clone, Copy)]
pub struct RxeOpcodeInfo {
    pub name: &'static str,
    pub mask: rxe_hdr_mask::Type,
    // all IBA header length
    pub length: u8,
    pub offset: [u8; rxe_hdr_type::NUM_HDR_TYPES as usize],
}

const DEFAULT_RXE_OPCODE_INFO: RxeOpcodeInfo = RxeOpcodeInfo {
    name: "",
    mask: 0,
    length: 0,
    offset: [0; rxe_hdr_type::NUM_HDR_TYPES as usize],
};

pub const RXE_NUM_OPCODE: usize = 256;

pub const RXE_OPCODE_INFO: [RxeOpcodeInfo; RXE_NUM_OPCODE as usize] = {
    use super::rxe_hdr::rxe_hdr_length::*;
    use rdma_sys::ibv_opcode::*;
    use rxe_hdr_mask::*;
    use rxe_hdr_type::*;

    let mut arr = [DEFAULT_RXE_OPCODE_INFO; RXE_NUM_OPCODE];
    arr[IBV_OPCODE_RC_SEND_FIRST as usize].name = "IBV_OPCODE_RC_SEND_FIRST";
    arr[IBV_OPCODE_RC_SEND_FIRST as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_RWR_MASK | RXE_SEND_MASK | RXE_START_MASK;
    arr[IBV_OPCODE_RC_SEND_FIRST as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_FIRST as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_RC_SEND_MIDDLE as usize].name = "IBV_OPCODE_RC_SEND_MIDDLE";
    arr[IBV_OPCODE_RC_SEND_MIDDLE as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_SEND_MASK | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_RC_SEND_MIDDLE as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_MIDDLE as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_RC_SEND_LAST as usize].name = "IBV_OPCODE_RC_SEND_LAST";
    arr[IBV_OPCODE_RC_SEND_LAST as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK | RXE_SEND_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_SEND_LAST as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_LAST as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE as usize].mask = RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_SEND_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE as usize].length = RXE_BTH_BYTES + RXE_IMMDT_BYTES;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RC_SEND_ONLY as usize].name = "IBV_OPCODE_RC_SEND_ONLY";
    arr[IBV_OPCODE_RC_SEND_ONLY as usize].mask = RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RC_SEND_ONLY as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_ONLY as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE as usize].mask = RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE as usize].length = RXE_BTH_BYTES + RXE_IMMDT_BYTES;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RC_RDMA_WRITE_FIRST as usize].name = "IBV_OPCODE_RC_RDMA_WRITE_FIRST";
    arr[IBV_OPCODE_RC_RDMA_WRITE_FIRST as usize].mask =
        RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_START_MASK;
    arr[IBV_OPCODE_RC_RDMA_WRITE_FIRST as usize].length = RXE_BTH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_WRITE_FIRST as usize].offset[RXE_RETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_FIRST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_WRITE_MIDDLE as usize].name = "IBV_OPCODE_RC_RDMA_WRITE_MIDDLE";
    arr[IBV_OPCODE_RC_RDMA_WRITE_MIDDLE as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_RC_RDMA_WRITE_MIDDLE as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_WRITE_MIDDLE as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST as usize].name = "IBV_OPCODE_RC_RDMA_WRITE_LAST";
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].mask = RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY as usize].name = "IBV_OPCODE_RC_RDMA_WRITE_ONLY";
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY as usize].mask = RXE_RETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_START_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY as usize].length = RXE_BTH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY as usize].offset[RXE_RETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].mask = RXE_RETH_MASK
        | RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_WRITE_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_RWR_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_RETH as usize] =
        RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RC_RDMA_READ_REQUEST as usize].name = "IBV_OPCODE_RC_RDMA_READ_REQUEST";
    arr[IBV_OPCODE_RC_RDMA_READ_REQUEST as usize].mask =
        RXE_RETH_MASK | RXE_REQ_MASK | RXE_READ_MASK | RXE_START_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_RDMA_READ_REQUEST as usize].length = RXE_BTH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_REQUEST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_READ_REQUEST as usize].offset[RXE_RETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_REQUEST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as usize].name =
        "IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST";
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as usize].mask =
        RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_START_MASK;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as usize].length = RXE_BTH_BYTES + RXE_AETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as usize].offset[RXE_AETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE as usize].name =
        "IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE";
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE as usize].mask =
        RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST as usize].name =
        "IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST";
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST as usize].mask =
        RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST as usize].length = RXE_BTH_BYTES + RXE_AETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST as usize].offset[RXE_AETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as usize].name =
        "IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY";
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as usize].mask =
        RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as usize].length = RXE_BTH_BYTES + RXE_AETH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as usize].offset[RXE_AETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RC_ACKNOWLEDGE as usize].name = "IBV_OPCODE_RC_ACKNOWLEDGE";
    arr[IBV_OPCODE_RC_ACKNOWLEDGE as usize].mask =
        RXE_AETH_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_ACKNOWLEDGE as usize].length = RXE_BTH_BYTES + RXE_AETH_BYTES;
    arr[IBV_OPCODE_RC_ACKNOWLEDGE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_ACKNOWLEDGE as usize].offset[RXE_AETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_ACKNOWLEDGE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize].name = "IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE";
    arr[IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize].mask =
        RXE_AETH_MASK | RXE_ATMACK_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize].length =
        RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES;
    arr[IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_AETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_ATMACK as usize] =
        RXE_BTH_BYTES + RXE_AETH_BYTES;
    arr[IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RC_COMPARE_SWAP as usize].name = "IBV_OPCODE_RC_COMPARE_SWAP";
    arr[IBV_OPCODE_RC_COMPARE_SWAP as usize].mask =
        RXE_ATMETH_MASK | RXE_REQ_MASK | RXE_ATOMIC_MASK | RXE_START_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_COMPARE_SWAP as usize].length = RXE_BTH_BYTES + RXE_ATMETH_BYTES;
    arr[IBV_OPCODE_RC_COMPARE_SWAP as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_COMPARE_SWAP as usize].offset[RXE_ATMETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_COMPARE_SWAP as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_ATMETH_BYTES;

    arr[IBV_OPCODE_RC_FETCH_ADD as usize].name = "IBV_OPCODE_RC_FETCH_ADD";
    arr[IBV_OPCODE_RC_FETCH_ADD as usize].mask =
        RXE_ATMETH_MASK | RXE_REQ_MASK | RXE_ATOMIC_MASK | RXE_START_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RC_FETCH_ADD as usize].length = RXE_BTH_BYTES + RXE_ATMETH_BYTES;
    arr[IBV_OPCODE_RC_FETCH_ADD as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_FETCH_ADD as usize].offset[RXE_ATMETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_FETCH_ADD as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_ATMETH_BYTES;

    arr[IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as usize].name =
        "IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE";
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as usize].mask = RXE_IETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_SEND_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as usize].length = RXE_BTH_BYTES + RXE_IETH_BYTES;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as usize].offset[RXE_IETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IETH_BYTES;

    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as usize].name = "IBV_OPCODE_RC_SEND_ONLY_INV";
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as usize].mask = RXE_IETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_END_MASK
        | RXE_START_MASK;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as usize].length = RXE_BTH_BYTES + RXE_IETH_BYTES;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as usize].offset[RXE_IETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IETH_BYTES;

    /* UC */
    arr[IBV_OPCODE_UC_SEND_FIRST as usize].name = "IBV_OPCODE_UC_SEND_FIRST";
    arr[IBV_OPCODE_UC_SEND_FIRST as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_RWR_MASK | RXE_SEND_MASK | RXE_START_MASK;
    arr[IBV_OPCODE_UC_SEND_FIRST as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_SEND_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_SEND_FIRST as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_UC_SEND_MIDDLE as usize].name = "IBV_OPCODE_UC_SEND_MIDDLE";
    arr[IBV_OPCODE_UC_SEND_MIDDLE as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_SEND_MASK | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_UC_SEND_MIDDLE as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_SEND_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_SEND_MIDDLE as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_UC_SEND_LAST as usize].name = "IBV_OPCODE_UC_SEND_LAST";
    arr[IBV_OPCODE_UC_SEND_LAST as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK | RXE_SEND_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_UC_SEND_LAST as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_SEND_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_SEND_LAST as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE";
    arr[IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE as usize].mask = RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_SEND_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE as usize].length = RXE_BTH_BYTES + RXE_IMMDT_BYTES;
    arr[IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_UC_SEND_ONLY as usize].name = "IBV_OPCODE_UC_SEND_ONLY";
    arr[IBV_OPCODE_UC_SEND_ONLY as usize].mask = RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UC_SEND_ONLY as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_SEND_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_SEND_ONLY as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE";
    arr[IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE as usize].mask = RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE as usize].length = RXE_BTH_BYTES + RXE_IMMDT_BYTES;
    arr[IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_UC_RDMA_WRITE_FIRST as usize].name = "IBV_OPCODE_UC_RDMA_WRITE_FIRST";
    arr[IBV_OPCODE_UC_RDMA_WRITE_FIRST as usize].mask =
        RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_START_MASK;
    arr[IBV_OPCODE_UC_RDMA_WRITE_FIRST as usize].length = RXE_BTH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_RDMA_WRITE_FIRST as usize].offset[RXE_RETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_FIRST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES;

    arr[IBV_OPCODE_UC_RDMA_WRITE_MIDDLE as usize].name = "IBV_OPCODE_UC_RDMA_WRITE_MIDDLE";
    arr[IBV_OPCODE_UC_RDMA_WRITE_MIDDLE as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_UC_RDMA_WRITE_MIDDLE as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_RDMA_WRITE_MIDDLE as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST as usize].name = "IBV_OPCODE_UC_RDMA_WRITE_LAST";
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST as usize].mask =
        RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST as usize].length = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST as usize].offset[RXE_PAYLOAD as usize] = RXE_BTH_BYTES;

    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE";
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].mask = RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY as usize].name = "IBV_OPCODE_UC_RDMA_WRITE_ONLY";
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY as usize].mask = RXE_RETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_START_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY as usize].length = RXE_BTH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY as usize].offset[RXE_RETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES;

    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE";
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].mask = RXE_RETH_MASK
        | RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_WRITE_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_RWR_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_RETH as usize] =
        RXE_BTH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_IMMDT_BYTES;

    /* RD */
    arr[IBV_OPCODE_RD_SEND_FIRST as usize].name = "IBV_OPCODE_RD_SEND_FIRST";
    arr[IBV_OPCODE_RD_SEND_FIRST as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK;
    arr[IBV_OPCODE_RD_SEND_FIRST as usize].length =
        RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_SEND_FIRST as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_SEND_FIRST as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_FIRST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;

    arr[IBV_OPCODE_RD_SEND_MIDDLE as usize].name = "IBV_OPCODE_RD_SEND_MIDDLE";
    arr[IBV_OPCODE_RD_SEND_MIDDLE as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_SEND_MASK
        | RXE_SEND_MASK
        | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_RD_SEND_MIDDLE as usize].length =
        RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_SEND_MIDDLE as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_SEND_MIDDLE as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_MIDDLE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;

    arr[IBV_OPCODE_RD_SEND_LAST as usize].name = "IBV_OPCODE_RD_SEND_LAST";
    arr[IBV_OPCODE_RD_SEND_LAST as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_SEND_MASK
        | RXE_COMP_MASK
        | RXE_SEND_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_SEND_LAST as usize].length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_SEND_LAST as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_SEND_LAST as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_LAST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;

    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_SEND_MASK
        | RXE_SEND_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RD_SEND_ONLY as usize].name = "IBV_OPCODE_RD_SEND_ONLY";
    arr[IBV_OPCODE_RD_SEND_ONLY as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_SEND_ONLY as usize].length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_SEND_ONLY as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_SEND_ONLY as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_ONLY as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;

    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].name = "IBV_OPCODE_RD_RDMA_WRITE_FIRST";
    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_RETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_START_MASK;
    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].length =
        RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].offset[RXE_RETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_FIRST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_RETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_WRITE_MIDDLE as usize].name = "IBV_OPCODE_RD_RDMA_WRITE_MIDDLE";
    arr[IBV_OPCODE_RD_RDMA_WRITE_MIDDLE as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_WRITE_MASK
        | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_RD_RDMA_WRITE_MIDDLE as usize].length =
        RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_WRITE_MIDDLE as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_MIDDLE as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_MIDDLE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST as usize].name = "IBV_OPCODE_RD_RDMA_WRITE_LAST";
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_WRITE_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST as usize].length =
        RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_RDETH as usize] =
        RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].name = "IBV_OPCODE_RD_RDMA_WRITE_ONLY";
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_RETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_START_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].length =
        RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].offset[RXE_RETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_RETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE";
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_RETH_MASK
        | RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_WRITE_MASK
        | RXE_WRITE_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_RWR_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_RDETH as usize] =
        RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_RETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_RETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_RETH_BYTES + RXE_IMMDT_BYTES;

    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].name = "IBV_OPCODE_RD_RDMA_READ_REQUEST";
    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_RETH_MASK
        | RXE_REQ_MASK
        | RXE_READ_MASK
        | RXE_READ_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].length =
        RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].offset[RXE_RETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_REQUEST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize].name =
        "IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST";
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize].mask = RXE_RDETH_MASK
        | RXE_AETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_ACK_MASK
        | RXE_ACK_MASK
        | RXE_START_MASK;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize].length =
        RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize].offset[RXE_AETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE as usize].name =
        "IBV_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE";
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE as usize].mask =
        RXE_RDETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_MIDDLE_MASK;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE as usize].length = RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE as usize].offset[RXE_RDETH as usize] =
        RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize].name =
        "IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST";
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize].mask =
        RXE_RDETH_MASK | RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize].length =
        RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize].offset[RXE_AETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize].name =
        "IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY";
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize].mask = RXE_RDETH_MASK
        | RXE_AETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_ACK_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize].length =
        RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize].offset[RXE_AETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RD_ACKNOWLEDGE as usize].name = "IBV_OPCODE_RD_ACKNOWLEDGE";
    arr[IBV_OPCODE_RD_ACKNOWLEDGE as usize].mask =
        RXE_RDETH_MASK | RXE_AETH_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK;
    arr[IBV_OPCODE_RD_ACKNOWLEDGE as usize].length =
        RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_ACKNOWLEDGE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_ACKNOWLEDGE as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_ACKNOWLEDGE as usize].offset[RXE_AETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;

    arr[IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize].name = "IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE";
    arr[IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize].mask = RXE_RDETH_MASK
        | RXE_AETH_MASK
        | RXE_ATMACK_MASK
        | RXE_ACK_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize].length =
        RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_AETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize].offset[RXE_ATMACK as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES;

    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].name = "RD_COMPARE_SWAP";
    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_ATMETH_MASK
        | RXE_REQ_MASK
        | RXE_ATOMIC_MASK
        | RXE_ATOMIC_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].length =
        RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].offset[RXE_ATMETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_COMPARE_SWAP as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;

    arr[IBV_OPCODE_RD_FETCH_ADD as usize].name = "IBV_OPCODE_RD_FETCH_ADD";
    arr[IBV_OPCODE_RD_FETCH_ADD as usize].mask = RXE_RDETH_MASK
        | RXE_DETH_MASK
        | RXE_ATMETH_MASK
        | RXE_REQ_MASK
        | RXE_ATOMIC_MASK
        | RXE_ATOMIC_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_RD_FETCH_ADD as usize].length =
        RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_FETCH_ADD as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_RD_FETCH_ADD as usize].offset[RXE_RDETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_RD_FETCH_ADD as usize].offset[RXE_DETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES;
    arr[IBV_OPCODE_RD_FETCH_ADD as usize].offset[RXE_ATMETH as usize] =
        RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_RD_FETCH_ADD as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES;

    /* UD */
    arr[IBV_OPCODE_UD_SEND_ONLY as usize].name = "IBV_OPCODE_UD_SEND_ONLY";
    arr[IBV_OPCODE_UD_SEND_ONLY as usize].mask = RXE_DETH_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UD_SEND_ONLY as usize].length = RXE_BTH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_UD_SEND_ONLY as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UD_SEND_ONLY as usize].offset[RXE_DETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UD_SEND_ONLY as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_DETH_BYTES;

    arr[IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize].name =
        "IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE";
    arr[IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize].mask = RXE_DETH_MASK
        | RXE_IMMDT_MASK
        | RXE_PAYLOAD_MASK
        | RXE_REQ_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_COMP_MASK
        | RXE_RWR_MASK
        | RXE_SEND_MASK
        | RXE_START_MASK
        | RXE_END_MASK;
    arr[IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize].length =
        RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_BTH as usize] = 0;
    arr[IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_DETH as usize] = RXE_BTH_BYTES;
    arr[IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_IMMDT as usize] =
        RXE_BTH_BYTES + RXE_DETH_BYTES;
    arr[IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize].offset[RXE_PAYLOAD as usize] =
        RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES;

    arr
};
