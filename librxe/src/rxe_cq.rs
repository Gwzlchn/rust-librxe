use crate::rxe_context::RxeContext;
use librxe_sys::{advance_producer, producer_addr, queue_full, rxe_cq, rxe_queue_init};
use nix::Error;
use rdma_sys::{ibv_cq, ibv_poll_cq};
use std::ptr::NonNull;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RxeCqe {
    pub wc: rdma_sys::ibv_wc,
}

impl Default for RxeCqe {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

/// Complete Queue Structure
pub struct RxeCompletionQueue {
    /// Real Completion Queue
    inner_cq: rxe_cq,
    /// Maximum number of completion queue entries (CQE) to poll at a time.
    /// The higher the concurrency, the bigger this value should be and more memory allocated at a time.
    max_cqe: i32,
}

impl RxeCompletionQueue {
    /// Get the internal cq ptr
    pub fn as_ptr(&mut self) -> *mut ibv_cq {
        unsafe { &mut self.inner_cq.vcq.cq_union.cq as *mut ibv_cq }
    }

    /// Get `max_cqe`
    pub fn max_cqe(&self) -> i32 {
        self.max_cqe
    }

    /// Create a new completion queue and bind to the event channel `ec`, `cq_size` is the buffer
    /// size of the completion queue
    pub fn create(
        ctx: &mut RxeContext,
        cq_size: u32,
        max_cqe: i32,
    ) -> Result<RxeCompletionQueue, Error> {
        let mut cq = rxe_cq::default();
        cq.queue =
            unsafe { rxe_queue_init(std::mem::size_of::<rdma_sys::ibv_wc>() as u32, cq_size) };
        unsafe { libc::pthread_spin_init(&mut cq.lock, libc::PTHREAD_PROCESS_PRIVATE) };
        cq.wc_size = 1usize << unsafe { (*cq.queue).log2_elem_size };

        // FIXME cq.vcq union is not completely filled
        cq.vcq.cq_union.cq.context = ctx.as_ptr();

        Ok(Self {
            inner_cq: cq,
            max_cqe,
        })
    }

    #[inline]
    pub fn poll<'c>(
        &mut self,
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
