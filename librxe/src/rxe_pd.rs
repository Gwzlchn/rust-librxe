use crate::{
    rxe_context::RxeContext,
    rxe_mr::RxeMr,
    rxe_qp::RxeQueuePair,
    rxe_verbs::{RxeMrCopyDir, RxeMrLookupType, RxeMrState},
};
use async_rdma::queue_pair::QueuePairInitAttr;
use nix::{errno::Errno, Error};
use rdma_sys::{ibv_access_flags, ibv_pd};
use std::{cell::RefCell, ptr::NonNull, rc::Rc};

/// Protection Domain Wrapper
#[derive(Clone)]
pub struct RxePd {
    /// Internal `ibv_pd` pointer
    pub inner_pd: ibv_pd,
    /// The device context
    pub ctx: NonNull<RxeContext>,
}

impl RxePd {
    /// Get pointer to the internal `ibv_pd`
    pub fn as_ptr(&mut self) -> *mut ibv_pd {
        &mut self.inner_pd as *mut ibv_pd
    }

    /// Create a protection domain
    pub fn create(mut ctx: NonNull<RxeContext>) -> Result<RxePd, Error> {
        let inner_pd = unsafe {
            ibv_pd {
                context: ctx.as_mut().as_ptr(),
                handle: 0xFFFF, // FIXME
            }
        };
        Ok(Self { ctx, inner_pd })
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
        let mr_index = reg_mr.rkey() >> 8;
        let mr_cell = Rc::new(RefCell::new(reg_mr.clone()));
        unsafe { self.ctx.as_mut().rxe_pool_add_mr(mr_index, mr_cell) };
        Ok(reg_mr)
    }

    // create qp
    pub fn rxe_create_qp(
        self: &mut Self,
        qp_init_attr: &mut QueuePairInitAttr,
    ) -> Result<Rc<RefCell<RxeQueuePair>>, Error> {
        let pd_ptr = NonNull::new(self as *mut _).unwrap();
        let qp = RxeQueuePair::create_qp(pd_ptr, qp_init_attr).unwrap();
        let qpn = qp.qp_num();
        let qp_cell = Rc::new(RefCell::new(qp));
        unsafe {
            // init qp state lock
            libc::pthread_spin_init(
                &mut (*qp_cell.as_ptr()).state_lock,
                libc::PTHREAD_PROCESS_SHARED,
            );
            self.ctx.as_mut().qp_pool.insert(qpn, qp_cell.clone());
        }
        Ok(qp_cell)
    }

    /// lookup a mr
    /// (1) find the mr corresponding to lkey/rkey
    ///     depending on lookup_type
    /// (2) verify that the (qp) pd matches the mr pd
    /// (3) verify that the mr can support the requested access
    /// (4) verify that mr state is valid
    pub fn lookup_mr(
        &self,
        access: u32,
        key: u32,
        lookup_type: RxeMrLookupType,
    ) -> Option<&Rc<RefCell<RxeMr>>> {
        match unsafe { self.ctx.as_ref().rxe_pool_get_mr(key >> 8) } {
            None => None,
            Some(mr) => {
                if (lookup_type == RxeMrLookupType::RxeLookupLocal
                    && mr.as_ref().borrow().lkey() != key)
                    || (lookup_type == RxeMrLookupType::RxeLookupRemote
                        && mr.as_ref().borrow().rkey() != key)
                    || (access != 0 && (access & mr.as_ref().borrow().access.0) == 0)
                    || mr.as_ref().borrow().state != RxeMrState::RxeMrStateValid
                {
                    None
                } else {
                    Some(mr)
                }
            }
        }
    }

    /// copy data in or out of a wqe, i.e. sg list
    /// under the control of a dma descriptor
    ///
    /// # Arguments
    /// * `dma`     - A DMA SG list
    /// * `addr`    - data start address
    /// * `length`  - data read/write bytes
    /// * `access`  - checking the memory region access permission
    /// * `dir`     
    ///     - RXE_TO_MR_OBJ means copy data from \[addr, addr + length - 1\] to addr recorded in DMA SG list
    ///     - RXE_FROM_MR_OBJ means copy data from addr recorded in DMA SG list to [addr, addr + length)
    pub fn copy_data(
        &self,
        access: u32,
        dma: &mut librxe_sys::rxe_dma_info,
        addr: *mut u8,
        length: u32,
        dir: RxeMrCopyDir,
    ) -> Result<(), Error> {
        // the `addr` in funcion parameter is a constant
        let mut addr = addr;
        if length == 0 {
            return Ok(());
        }
        // MAYBE use sge_slice is more elegent
        // get current SG entry
        let mut sge_ptr = unsafe {
            dma.__bindgen_anon_1
                .__bindgen_anon_2
                .as_mut()
                .sge
                .as_mut_ptr()
                .add(dma.cur_sge as _)
        };
        let mut sge = match unsafe { sge_ptr.as_mut() } {
            None => return Err(Errno::EINVAL),
            Some(sge) => sge,
        };

        let mut dma_offset = dma.sge_offset;
        let mut dma_resid = dma.resid;
        // current length can only be less than or equal to residual length
        if length > dma_resid {
            return Err(Errno::EINVAL);
        }
        // current SG entry is valid
        let mut mr = if sge.length != 0 && dma_offset < sge.length {
            let _mr = self.lookup_mr(access, sge.lkey, RxeMrLookupType::RxeLookupLocal);
            if _mr.is_none() {
                return Err(Errno::EINVAL);
            }
            _mr
        } else {
            None
        };

        let mut res_length = length;
        while res_length > 0 {
            let mut bytes = res_length;
            if dma_offset >= sge.length {
                if mr.is_some() {
                    mr = None;
                }
                // current SG entry is finished
                // get next sge, it may be in another memory region
                dma.cur_sge += 1;
                sge_ptr = unsafe { sge_ptr.add(1) };

                dma_offset = 0;
                if dma.cur_sge >= dma.num_sge {
                    return Err(Errno::ENOSPC);
                }
                // sge_ptr here should point to a valid SG entry
                sge = unsafe { sge_ptr.as_mut().unwrap() };
                // mr is always valid
                if sge.length != 0 {
                    mr = self.lookup_mr(access, sge.lkey, RxeMrLookupType::RxeLookupLocal);
                    if mr.is_none() {
                        return Err(Errno::EINVAL);
                    }
                } else {
                    continue;
                }
            }
            // bytes is the actual length to make a copy from SG entry
            if bytes > (sge.length - dma_offset) {
                bytes = sge.length - dma_offset;
            }
            if bytes > 0 {
                let iova = sge.addr + dma_offset as u64;
                mr.unwrap()
                    .as_ref()
                    .borrow()
                    .rxe_mr_copy(iova, addr, bytes as usize, dir)?;

                dma_offset += bytes;
                dma_resid -= bytes;
                res_length -= bytes;
                addr = unsafe { addr.add(bytes as usize) };
            }
        }
        dma.sge_offset = dma_offset;
        dma.resid = dma_resid;

        Ok(())
    }
}

unsafe impl Send for RxePd {}

unsafe impl Sync for RxePd {}
