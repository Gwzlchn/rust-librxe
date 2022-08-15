use crate::{rxe_context::RxeContext, rxe_mr::RxeMr, rxe_qp::RxeQueuePair};
use async_rdma::queue_pair::QueuePairInitAttr;
use nix::{errno::Errno, Error};
use rdma_sys::{ibv_access_flags, ibv_alloc_pd, ibv_dealloc_pd, ibv_pd};
use std::{cell::RefCell, ptr::NonNull, rc::Rc, sync::Arc};

/// Protection Domain Wrapper
#[derive(Debug, Clone)]
pub struct RxePd {
    /// The device context
    pub(crate) ctx: NonNull<RxeContext>,
    /// Internal `ibv_pd` pointer
    inner_pd: NonNull<ibv_pd>,
}

impl RxePd {
    /// Get pointer to the internal `ibv_pd`
    pub(crate) fn as_ptr(&self) -> *mut ibv_pd {
        self.inner_pd.as_ptr()
    }

    /// Create a protection domain
    pub(crate) fn create(ctx: NonNull<RxeContext>) -> Result<RxePd, Error> {
        // SAFETY: ffi
        // TODO: check safety
        let inner_pd = NonNull::new(unsafe { ibv_alloc_pd(ctx.as_ref().as_ptr()) }).unwrap();
        Ok(Self { ctx: ctx, inner_pd })
    }
    // register mr
    pub fn rxe_reg_mr(
        self: &mut Self,
        addr: *mut u8,
        len: usize,
        access: ibv_access_flags,
    ) -> Result<RxeMr, Error> {
        let pd_ptr = NonNull::new(self as *mut _).unwrap();
        let reg_mr = RxeMr::register_from_pd(pd_ptr, addr, len, access).unwrap();
        let rkey = reg_mr.rkey();
        let reg_cell = Rc::new(RefCell::new(reg_mr.clone()));
        unsafe { self.ctx.as_mut().mr_pool.insert(rkey, reg_cell) };
        Ok(reg_mr)
    }

    // create qp
    pub fn rxe_create_qp(
        self: &mut Self,
        qp_init_attr: &mut QueuePairInitAttr,
    ) -> Result<RxeQueuePair, Error> {
        let pd_ptr = NonNull::new(self as *mut _).unwrap();
        let mut qp = RxeQueuePair::create_qp(pd_ptr, qp_init_attr).unwrap();
        let qpn = qp.qp_num();
        let qp_cell = Rc::new(RefCell::new(qp.clone()));
        unsafe {
            // init qp state lock
            libc::pthread_spin_init(&mut qp.state_lock, libc::PTHREAD_PROCESS_SHARED);
            self.ctx.as_mut().qp_pool.insert(qpn, qp_cell);
        }
        Ok(qp)
    }
}

impl Drop for RxePd {
    fn drop(&mut self) {
        // SAFETY: ffi
        // TODO: check safety
        unsafe { ibv_dealloc_pd(self.as_ptr()) };
    }
}

unsafe impl Send for RxePd {}

unsafe impl Sync for RxePd {}
