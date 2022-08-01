use crate::*;
use std::os::raw::{c_int, c_uint};

// rxe_cq related union and struct types
#[repr(C)]
#[derive(Clone, Copy)]
pub union verbs_cq_union {
    pub cq: rdma_sys::ibv_cq,
    pub cq_ex: rdma_sys::ibv_cq_ex,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct verbs_cq {
    pub cq_union: verbs_cq_union,
}
#[repr(C)]
pub struct rxe_cq {
    pub vcq: verbs_cq,
    pub mmap_info: mminfo,
    pub queue: *mut rxe_queue_buf,
    pub lock: libc::pthread_spinlock_t,
    pub wc: *mut ib_uverbs_wc,
    pub wc_size: usize,
    pub cur_index: u32,
}

#[repr(C)]
pub struct rxe_ah {
    pub ibv_ah: rdma_sys::ibv_ah,
    pub av: rxe_av,
    pub ah_num: c_int,
}
// rxe_wq related union and struct types
#[repr(C)]
pub struct rxe_wq {
    pub queue: *mut rxe_queue_buf,
    pub lock: libc::pthread_spinlock_t,
    pub max_sge: c_uint,
    pub max_inline: c_uint,
}

// rxe_qp related union and struct types
#[repr(C)]
#[derive(Clone, Copy)]
pub union verbs_qp_union_t {
    pub qp: rdma_sys::ibv_qp,
    pub qp_ex: rdma_sys::ibv_qp_ex,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct verbs_xrcd {
    xrcd: rdma_sys::ibv_xrcd,
    comp_mask: u32,
    handler: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct verbs_qp {
    pub qp_union: verbs_qp_union_t,
    pub comp_mask: u32,
    pub xrcd: *mut verbs_xrcd,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum rxe_qp_state {
    QP_STATE_RESET,
    QP_STATE_INIT,
    QP_STATE_READY,
    QP_STATE_DRAIN,   /* req only */
    QP_STATE_DRAINED, /* req only */
    QP_STATE_ERROR,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct rxe_req_info {
    pub state: rxe_qp_state,
    pub wqe_index: c_int,
    pub psn: u32,
    pub opcode: c_int,
    pub rd_atomic: c_int, // as atomic_int
    pub wait_fence: c_int,
    pub need_rd_atomic: c_int,
    pub wait_psn: c_int,
    pub need_retry: c_int,
    pub noack_pkts: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rxe_comp_info {
    pub psn: u32,
    pub opcode: c_int,
    pub timeout: c_int,
    pub timeout_retry: c_int,
    pub started_retry: c_int,
    pub retry_cnt: u32,
    pub rnr_retry: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rxe_resp_info {
    pub state: rxe_qp_state,
}
#[repr(C)]
pub struct rxe_qp {
    pub vqp: verbs_qp,
    pub rq_mmap_info: mminfo,
    pub rq: rxe_wq,
    pub sq_mmap_info: mminfo,
    pub sq: rxe_wq,
    pub ssn: c_uint,
    pub cur_index: u32,
    pub err: c_int,
    // addtional variables
    pub src_port: u32,
    pub mtu: c_uint,
    pub req: rxe_req_info,
    pub comp: rxe_comp_info,
    pub resp: rxe_resp_info,
    pub valid: c_uint,
    pub attr: rdma_sys::ibv_qp_attr,
    /* guard requester and completer */
    pub state_lock: libc::pthread_spinlock_t,
}
