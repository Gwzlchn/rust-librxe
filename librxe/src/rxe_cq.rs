use std::ptr::NonNull;

use derivative::Derivative;
use librxe_sys::{advance_producer, producer_addr, queue_full, rxe_cq};
use nix::Error;
use rdma_sys::{ibv_cq, ibv_create_cq, ibv_poll_cq};

use crate::rxe_context::RxeContext;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RxeCqe {
    pub wc: rdma_sys::ibv_wc,
}

impl Default for RxeCqe {
    // like malloc and memset to 0
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

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

    #[inline]
    pub fn poll<'c>(
        &self,
        completions: &'c mut [rdma_sys::ibv_wc],
        userspace: bool,
    ) -> Result<&'c mut [rdma_sys::ibv_wc], ()> {
        let n = if !userspace {
            // just for debug
            // TODO: from http://www.rdmamojo.com/2013/02/15/ibv_poll_cq/
            //
            //   One should consume Work Completions at a rate that prevents the CQ from being overrun
            //   (hold more Work Completions than the CQ size). In case of an CQ overrun, the async
            //   event `IBV_EVENT_CQ_ERR` will be triggered, and the CQ cannot be used anymore.
            //
            unsafe {
                ibv_poll_cq(
                    self.as_ptr(),
                    completions.len() as i32,
                    completions.as_mut_ptr(),
                )
            }
        } else {
            crate::rxe_poll_cq(
                self.as_ptr(),
                completions.len() as i32,
                completions.as_mut_ptr(),
            )
        };
        if n < 0 {
            Err(())
        } else {
            Ok(&mut completions[0..n as usize])
        }
    }

    #[inline]
    pub unsafe fn cq_post(
        cq: &mut NonNull<rxe_cq>,
        cqe: &mut RxeCqe,
        _solicited: bool,
    ) -> Result<(), Error> {
        libc::pthread_spin_lock(&mut cq.as_mut().lock);
        if queue_full(cq.as_ref().queue) {
            libc::pthread_spin_unlock(&mut cq.as_mut().lock);
            return Err(Error::EBUSY);
        }
        let dst_addr: *mut rdma_sys::ibv_wc = producer_addr(cq.as_mut().queue);
        std::ptr::copy_nonoverlapping(&cqe.wc as *const rdma_sys::ibv_wc, dst_addr, 1);
        advance_producer(cq.as_mut().queue);

        libc::pthread_spin_unlock(&mut cq.as_mut().lock);
        // should call comp_task here when solicited is true
        Ok(())
    }
}

unsafe impl Sync for RxeCompletionQueue {}

unsafe impl Send for RxeCompletionQueue {}
