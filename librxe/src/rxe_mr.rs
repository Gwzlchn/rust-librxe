use std::cell::RefCell;
use std::ptr::NonNull;
use std::rc::Rc;

use crate::rxe_pd::RxePd;
use crate::rxe_verbs::{IbvMrType, RxeMrCopyDir, RxeMrState};
use crate::{rxe_hdr::RxePktInfo, rxe_verbs::IbMrType};
use nix::errno::Errno;
use nix::Error;
use rand;
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

// assume a page is 4kb
pub const DUMMY_PAGE_SIZE: usize = 1 << 12;

pub const RXE_BUF_PER_MAP: usize = DUMMY_PAGE_SIZE / std::mem::size_of::<RxePhysBuf>();

#[derive(Debug, Clone, Copy)]
struct RxePhysBuf {
    pub addr: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
struct RxeMap {
    pub buf: [RxePhysBuf; RXE_BUF_PER_MAP],
}

#[derive(Default, Debug, Clone, Copy)]
struct RxeMapSet {
    pub va: u64,
    pub iova: u64,
    pub length: usize,
    pub nbuf: u32,
    pub page_shift: usize,
    pub page_mask: usize,
}

#[inline]
pub fn rkey_is_mw(rkey: u32) -> bool {
    let index = rkey >> 8;
    index >= librxe_sys::rxe_device_param::RXE_MIN_MW_INDEX as u32
        && index <= librxe_sys::rxe_device_param::RXE_MAX_MW_INDEX as u32
}
#[derive(Clone)]
pub struct RxeMr {
    /// the protection domain the raw memory region belongs to
    pub pd: NonNull<RxePd>,
    /// the internal `ibv_mr` pointer
    pub inner_mr: NonNull<ibv_mr>,
    pub lkey: u32,
    pub rkey: u32,
    pub state: RxeMrState,
    pub mr_type: IbMrType,
    pub access: ibv_access_flags,
    pub addr: *mut u8, // the userspace address start
    pub length: usize, // the userspace address length in bytes
    // pub map_shift: usize,
    // pub map_mask: usize,
    // pub num_buf: u32,

    // pub max_buf: u32,
    // pub num_map: u32,

    // pub cur_map_set: Option<Rc<RefCell<RxeMapSet>>>,
    // pub next_map_set: Option<Rc<RefCell<RxeMapSet>>>,
    pub vmr_type: IbvMrType,
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
            pd: pd,
            inner_mr: inner_mr,
            lkey: unsafe { inner_mr.as_ref().lkey },
            rkey: unsafe { inner_mr.as_ref().rkey },
            state: RxeMrState::RxeMrStateValid,

            addr,
            length: len,

            // keep the same assignment in rdma-core/libibverbs/cmd.c
            vmr_type: IbvMrType::IbvMrTypeMr,
            // keep the same assignment  in rxe_mr.c/rxe_mr_init_user
            mr_type: IbMrType::IbMrTypeUser,
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

    pub fn rxe_get_next_key(last_key: u32) -> u8 {
        let mut key = 0;
        loop {
            key = rand::random::<u8>();
            if key != (last_key as u8) {
                break;
            }
        }
        key
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
}

impl Debug for RxeMr {
    #[allow(clippy::as_conversions)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rxe MR")
            .field("inner_mr", &self.inner_mr)
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
