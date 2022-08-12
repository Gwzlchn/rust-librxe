use std::ptr::NonNull;

use derivative::Derivative;
use librxe_sys::rxe_cq;
use nix::Error;
use rdma_sys::{ibv_cq, ibv_create_cq};

use crate::rxe_context::RxeContext;

/// Complete Queue Structure
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct RxeCompletionQueue {
    /// Real Completion Queue
    #[derivative(Default(value = "NonNull::dangling()"))]
    inner_cq: NonNull<rxe_cq>,
    /// Maximum number of completion queue entries (CQE) to poll at a time.
    /// The higher the concurrency, the bigger this value should be and more memory allocated at a time.
    max_cqe: i32,
}

impl RxeCompletionQueue {
    /// Get the internal cq ptr
    pub fn as_ptr(&self) -> *mut ibv_cq {
        unsafe { &mut (*self.inner_cq.as_ptr()).vcq.cq_union.cq as *mut ibv_cq }
    }

    /// Get `max_cqe`
    pub fn max_cqe(&self) -> i32 {
        self.max_cqe
    }

    /// Create a new completion queue and bind to the event channel `ec`, `cq_size` is the buffer
    /// size of the completion queue
    ///
    /// On failure of `ibv_create_cq`, errno indicates the failure reason:
    ///
    /// `EINVAL`    Invalid cqe, channel or `comp_vector`
    ///
    /// `ENOMEM`    Not enough resources to complete this operation
    pub fn create(
        ctx: &RxeContext,
        cq_size: u32,
        max_cqe: i32,
    ) -> Result<RxeCompletionQueue, Error> {
        // SAFETY: ffi
        // TODO: check safety
        let ibcq = NonNull::new(unsafe {
            ibv_create_cq(
                ctx.as_ptr(),
                cq_size as _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        })
        .expect("create cq failed");
        let rcq = librxe_sys::to_rcq(ibcq.as_ptr()).unwrap();
        let rcq_ptr = NonNull::new(rcq).unwrap();

        Ok(Self {
            inner_cq: rcq_ptr,
            max_cqe,
        })
    }
    // TODO poll cq
}

unsafe impl Sync for RxeCompletionQueue {}

unsafe impl Send for RxeCompletionQueue {}
