#![allow(unused)]
#![cfg_attr(feature = "cargo-clippy", allow(expl_impl_clone_on_copy))]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(deref_nullptr)]

use libc::*;
use std::sync::atomic::{AtomicU32, AtomicU8};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod queue;
pub mod types;

pub use crate::queue::*;
pub use crate::types::*;

#[macro_export]
macro_rules! offset_of {
    ($type:ty, $($f:tt)*) => {{
        let tmp = core::mem::MaybeUninit::<$type>::uninit();
        let outer = tmp.as_ptr();
        // To avoid warnings when nesting `unsafe` blocks.
        #[allow(unused_unsafe)]
        // SAFETY: The pointer is valid and aligned, just not initialised; `addr_of` ensures that
        // we don't actually read from `outer` (which would be UB) nor create an intermediate
        // reference.
        let inner = unsafe { core::ptr::addr_of!((*outer).$($f)*) } as *const u8;
        // To avoid warnings when nesting `unsafe` blocks.
        #[allow(unused_unsafe)]
        // SAFETY: The two pointers are within the same allocation block.
        unsafe { inner.offset_from(outer as *const u8) }
    }}
}

#[macro_export]
macro_rules! container_of {
    ($ptr:expr, $type:ty, $($f:tt)*) => {{
        let ptr = $ptr as *const _ as *const u8;
        let offset = $crate::offset_of!($type, $($f)*);
        ptr.wrapping_offset(-offset) as *const $type
    }}
}

// it is an unstable feature in std::sync::atomic
// https://doc.rust-lang.org/std/sync/atomic/struct.AtomicU32.html#method.from_mut
pub fn atomicu32_from_mut(v: &mut u32) -> &mut AtomicU32 {
    use core::mem::align_of;
    let [] = [(); align_of::<AtomicU32>() - align_of::<u32>()];
    unsafe { &mut *(v as *mut u32 as *mut AtomicU32) }
}

pub fn atomicu8_from_mut(v: &mut u8) -> &mut AtomicU8 {
    use core::mem::align_of;
    let [] = [(); align_of::<AtomicU8>() - align_of::<u8>()];
    unsafe { &mut *(v as *mut u8 as *mut AtomicU8) }
}

#[inline]
pub fn to_rcq(ibcq: *mut rdma_sys::ibv_cq) -> Option<*mut rxe_cq> {
    if ibcq.is_null() {
        None
    } else {
        let rcq = container_of!(ibcq, rxe_cq, vcq.cq_union.cq) as *mut rxe_cq;
        Some(rcq)
    }
}

#[inline]
pub fn to_rqp(ibqp: *mut rdma_sys::ibv_qp) -> Option<*mut rxe_qp> {
    if ibqp.is_null() {
        None
    } else {
        let rqp = container_of!(ibqp, rxe_qp, vqp.qp_union.qp) as *mut rxe_qp;
        Some(rqp)
    }
}

#[inline]
pub fn to_rah(ibah: *mut rdma_sys::ibv_ah) -> Option<*mut rxe_ah> {
    if ibah.is_null() {
        None
    } else {
        let rah = container_of!(ibah, rxe_ah, ibv_ah) as *mut rxe_ah;
        Some(rah)
    }
}

#[inline]
pub fn qp_type(qp: *const rxe_qp) -> rdma_sys::ibv_qp_type::Type {
    unsafe { (*qp).vqp.qp_union.qp.qp_type }
}

#[inline]
pub fn qp_num(qp: *const rxe_qp) -> u32 {
    unsafe { (*qp).vqp.qp_union.qp.qp_num }
}

#[inline]
pub unsafe fn serialize_raw<T: Sized>(src: &T) -> &[u8] {
    ::std::slice::from_raw_parts((src as *const T) as *const u8, ::std::mem::size_of::<T>())
}

const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: u32) -> u32 {
    assert!(x > 0);
    num_bits::<u32>() as u32 - x.leading_zeros() - 1
}

pub unsafe fn rxe_queue_init(num_elem: u32, elem_size: u32) -> *mut rxe_queue_buf {
    let num_slots = num_elem + 1;
    let num_slots = num_slots.next_power_of_two();
    let elem_size = elem_size.next_power_of_two();
    let buf_size = std::mem::size_of::<rxe_queue_buf>() + (num_slots * elem_size) as usize;

    let mut buf = libc::malloc(buf_size) as *mut rxe_queue_buf;
    buf.as_mut().unwrap().log2_elem_size = log_2(elem_size);
    buf.as_mut().unwrap().index_mask = num_slots - 1;
    buf
}

#[test]
fn check_qp_layout() {
    assert_eq!(
        offset_of!(rdma_sys::ibv_qp_ex, qp_base),
        0,
        "Invalid QP layout"
    );
}

#[test]
fn check_to_rqp() {
    let mut ibqp = rdma_sys::ibv_qp {
        context: core::ptr::null_mut(),
        qp_context: core::ptr::null_mut(),
        pd: core::ptr::null_mut(),
        send_cq: core::ptr::null_mut(),
        recv_cq: core::ptr::null_mut(),
        srq: core::ptr::null_mut(),
        handle: 1,
        qp_num: 2,
        state: 3 as _,
        qp_type: 4 as _,
        mutex: libc::PTHREAD_MUTEX_INITIALIZER,
        cond: libc::PTHREAD_COND_INITIALIZER,
        events_completed: 0,
    };
    let rxeqp = to_rqp(&mut ibqp).unwrap();
    assert!(std::ptr::eq(&ibqp, rxeqp as _), "Invalid RXE QP layout");
}
