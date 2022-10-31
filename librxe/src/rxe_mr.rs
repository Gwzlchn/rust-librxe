use crate::rxe_context::RxeContext;
use crate::rxe_pd::RxePd;
use crate::rxe_verbs::{IbvMrType, RxeMrCopyDir, RxeMrState};
use nix::{errno::Errno, Error};
use rand;
use rdma_sys::{ibv_access_flags, ibv_mr};
use std::fmt::Debug;
use std::ptr::NonNull;
use tracing::debug;

#[inline]
pub fn rkey_is_mw(rkey: u32) -> bool {
    let index = rkey >> 8;
    index >= librxe_sys::rxe_device_param::RXE_MIN_MW_INDEX as u32
        && index <= librxe_sys::rxe_device_param::RXE_MAX_MW_INDEX as u32
}
#[derive(Clone)]
pub struct RxeMr {
    /// the internal `ibv_mr` pointer
    pub inner_mr: ibv_mr,
    /// the protection domain the raw memory region belongs to
    pub pd: NonNull<RxePd>,
    pub lkey: u32,
    pub rkey: u32,
    pub state: RxeMrState,
    pub access: ibv_access_flags,
    pub addr: *mut u8, // the userspace address start
    pub length: usize, // the userspace address length in bytes
    pub vmr_type: IbvMrType,
}

impl RxeMr {
    /// Register a raw memory region from protection domain
    pub fn register_from_pd(
        pd: NonNull<RxePd>,
        addr: *mut u8,
        len: usize,
        access: ibv_access_flags,
    ) -> Result<RxeMr, Error> {
        let mut mr = unsafe {
            let mut _mr = std::mem::MaybeUninit::<ibv_mr>::uninit();
            std::ptr::write_bytes(_mr.as_mut_ptr(), 0, 1);
            _mr.assume_init()
        };
        // init ibv_mr
        mr.context = unsafe { (*pd.as_ptr()).ctx.as_mut().as_ptr() };
        mr.pd = unsafe { (*pd.as_ptr()).as_ptr() };
        mr.addr = addr as *mut libc::c_void;
        mr.length = len;
        mr.lkey = unsafe { RxeMr::gen_next_mr_key(pd.as_ref().ctx) };
        let ib_access_remote = ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC
            | ibv_access_flags::IBV_ACCESS_REMOTE_READ
            | ibv_access_flags::IBV_ACCESS_REMOTE_WRITE;
        mr.rkey = if access & ib_access_remote != ibv_access_flags(0) {
            mr.lkey
        } else {
            0
        };

        Ok(Self {
            pd: pd,
            inner_mr: mr,
            lkey: mr.lkey,
            rkey: mr.rkey,
            state: RxeMrState::RxeMrStateValid,
            addr: addr,
            length: len,
            // keep the same assignment in rdma-core/libibverbs/cmd.c
            vmr_type: IbvMrType::IbvMrTypeMr,
            access: access,
        })
    }
    /// Get local key of memory region
    pub fn lkey(&self) -> u32 {
        self.lkey
    }

    /// Get remote key of memory region
    pub fn rkey(&self) -> u32 {
        self.rkey
    }

    /// generate a new memory region key, used for mr lkey and rkey
    fn gen_next_mr_key(ctx: NonNull<RxeContext>) -> u32 {
        loop {
            let key = rand::random::<u32>();
            if !unsafe { ctx.as_ref() }.mr_pool.contains_key(&key) {
                return key;
            }
        }
    }

    /// return true means iova and length is in the memory region
    /// return false means it is out of
    pub fn mr_check_range(&self, iova: u64, length: usize) -> bool {
        let addr = self.addr as usize;
        return if (iova as usize) < addr
            || length > self.length
            || (iova as usize) > addr + self.length - length
        {
            false
        } else {
            true
        };
    }

    /// copy data from a range \[addr, addr+length-1\] to or from
    /// a mr object starting at iova.
    ///
    /// # Arguments
    /// * `iova`    - the address recorded in a DMA SG list
    /// * `addr`    - data start address
    /// * `length`  - data read/write bytes
    /// * `dir`     
    ///     - RXE_TO_MR_OBJ means copy data from [addr, addr + length - 1] to addr recorded in DMA SG list
    ///     - RXE_FROM_MR_OBJ means copy data from addr recorded in DMA SG list to [addr, addr + length)
    pub fn rxe_mr_copy(
        &self,
        iova: u64,
        addr: *mut u8,
        length: usize,
        dir: RxeMrCopyDir,
    ) -> Result<(), Error> {
        if length == 0 {
            return Ok(());
        }
        if !self.mr_check_range(iova, length) {
            return Err(Error::EFAULT);
        }
        let src = if dir == RxeMrCopyDir::RxeToMrObj {
            addr
        } else {
            iova as *const u8
        };
        let dst = if dir == RxeMrCopyDir::RxeToMrObj {
            iova as *mut u8
        } else {
            addr
        };
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, length);
        }

        Ok(())
    }

    pub fn advance_dma_data(dma: &mut librxe_sys::rxe_dma_info, length: u32) -> Result<(), Error> {
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

        let mut res_length = length;
        while res_length != 0 {
            if dma_offset >= sge.length {
                dma.cur_sge += 1;
                sge_ptr = unsafe { sge_ptr.add(1) };

                dma_offset = 0;
                if dma.cur_sge >= dma.num_sge {
                    return Err(Errno::ENOSPC);
                }
                // sge_ptr here should point to a valid SG entry
                sge = unsafe { sge_ptr.as_mut().unwrap() };
            }
            let bytes = if res_length > sge.length - dma_offset {
                sge.length - dma_offset
            } else {
                res_length
            };
            dma_offset += bytes;
            dma_resid -= bytes;
            res_length -= bytes;
        }
        dma.sge_offset = dma_offset;
        dma.resid = dma_resid;
        Ok(())
    }
}

impl Debug for RxeMr {
    #[allow(clippy::as_conversions)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rxe MR")
            .field("addr", &(self.addr as usize))
            .field("len", &self.length)
            .field("pd", &self.pd)
            .finish()
    }
}

unsafe impl Sync for RxeMr {}

unsafe impl Send for RxeMr {}

impl Drop for RxeMr {
    fn drop(&mut self) {
        debug!("dereg_mr {:?}", &self);
        // // SAFETY: ffi
        // // TODO: check only call once
        // let errno = unsafe { ibv_dereg_mr(self.inner_mr.as_ptr()) };
        // assert_eq!(errno, 0_i32);
    }
}
