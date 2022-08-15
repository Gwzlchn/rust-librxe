use std::ptr::NonNull;

use crate::rxe_hdr::RxePktInfo;
use crate::rxe_pd::RxePd;
use crate::rxe_verbs::RxeMrCopyDir;
use nix::errno::Errno;
use nix::Error;
use rdma_sys::{ibv_access_flags, ibv_dereg_mr, ibv_mr, ibv_reg_mr};
use std::fmt::Debug;
use tracing::{debug, error};

impl RxePktInfo {
    /// Copy data from Scatter Gather List to IBA Pacekt buffer
    /// simulating DMA operations with memcpy
    ///
    /// # Arguments
    /// * `dma`     - A SG list in rxe_dma_info
    /// * `addr`    - payload base offset in IBA packet
    /// * `length`  - IBA packet payload length, equals to min(MTU or dma.resid)
    /// * `access` and `dir` TODO: is used for checking MemoryRegion
    pub fn copy_data(
        &mut self,
        _access: u32,
        dma: &mut librxe_sys::rxe_dma_info,
        addr: usize,
        length: u32,
        _dir: RxeMrCopyDir,
    ) -> Result<(), Error> {
        // FIXME: no available rxe_mr for checking LKEY
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
        let mut sge = unsafe { &mut *sge_ptr };

        let mut offset = dma.sge_offset;
        let mut resid = dma.resid;
        // length is only possible less than or equal to resid
        if length > resid {
            return Err(Errno::EINVAL);
        }

        // filling the whole [0~length) iba payload buffer
        let mut res_length = length;
        let mut payload_buf = self.split_iba_pkt(addr);
        let mut payload_buf_addr = payload_buf.as_mut_ptr();
        while res_length > 0 {
            let mut bytes = res_length;
            if offset >= sge.length {
                // current SG entry is finished
                dma.cur_sge += dma.cur_sge + 1;
                sge_ptr = unsafe { sge_ptr.add(1) };
                sge = unsafe { &mut *sge_ptr };
                offset = 0;
                if dma.cur_sge >= dma.num_sge {
                    return Err(Errno::ENOSPC);
                }
                continue;
            }
            // bytes is the actual length to make a copy from SG entry
            if bytes > (sge.length - offset) {
                bytes = sge.length - offset;
            }
            if bytes > 0 {
                let iova = sge.addr + offset as u64;
                unsafe {
                    std::ptr::copy_nonoverlapping(iova as *const u8, payload_buf_addr, bytes as _);
                }
                offset = offset + bytes;
                resid = resid - bytes;
                res_length = res_length - bytes;
                payload_buf_addr = unsafe { payload_buf_addr.add(bytes as _) };
            }
        }
        self.unsplit_iba_pkt(payload_buf);
        dma.sge_offset = offset;
        dma.resid = resid;

        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum IBVMrType {
    IBV_MR_TYPE_MR,
    IBV_MR_TYPE_NULL_MR,
    IBV_MR_TYPE_IMPORTED_MR,
    IBV_MR_TYPE_DMABUF_MR,
}

#[derive(Clone)]
pub struct RxeMr {
    /// the protection domain the raw memory region belongs to
    pd: NonNull<RxePd>,
    /// the internal `ibv_mr` pointer
    inner_mr: NonNull<ibv_mr>,
    /// the addr of the raw memory region
    addr: *mut u8,
    /// the len of the raw memory region
    pub len: usize,
    // RXE, ibv_cmd_reg_mr: libibverbs/cmd.c
    mr_type: IBVMrType,
    access: ibv_access_flags,
}

impl RxeMr {
    /// Register a raw memory region from protection domain
    pub(crate) fn register_from_pd(
        pd: NonNull<RxePd>,
        addr: *mut u8,
        len: usize,
        access: ibv_access_flags,
    ) -> Result<RxeMr, Error> {
        // SAFETY: ffi
        // TODO: check safety
        let inner_mr =
        NonNull::new(unsafe { ibv_reg_mr(pd.as_ref().as_ptr(), addr.cast(), len, access.0 as _) })
        .ok_or_else(|| {
            let err = Error::last();
                    error!(
                "ibv_reg_mr err, arguments:\n pd:{:?},\n addr:{:?},\n len:{:?},\n access:{:?}\n, err info:{:?}",
                pd, addr, len, access, err
            );
            err
        })?;
        Ok(Self {
            inner_mr,
            addr,
            len,
            pd: pd,
            mr_type: IBVMrType::IBV_MR_TYPE_MR,
            access: access,
        })
    }
    /// Get local key of memory region
    pub fn lkey(&self) -> u32 {
        unsafe { self.inner_mr.as_ref().lkey }
    }

    /// Get remote key of memory region
    pub fn rkey(&self) -> u32 {
        unsafe { self.inner_mr.as_ref().rkey }
    }
}

impl Debug for RxeMr {
    #[allow(clippy::as_conversions)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rxe MR")
            .field("inner_mr", &self.inner_mr)
            .field("addr", &(self.addr as usize))
            .field("len", &self.len)
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
