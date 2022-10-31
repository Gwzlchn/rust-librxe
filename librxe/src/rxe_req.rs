use crate::rxe_av::rxe_get_av;
use crate::rxe_hdr::*;
use crate::rxe_mr::RxeMr;
use crate::rxe_net::RxeSkb;
use crate::rxe_opcode::{rxe_hdr_mask, rxe_wr_mask, wr_opcode_mask, RXE_OPCODE_INFO};
use crate::rxe_qp::{RxeQpState, RxeQueuePair};
use crate::rxe_verbs::{self, psn_compare, RxeMrCopyDir, WqeState};
use librxe_sys::{load_consumer_index, rxe_device_param, rxe_send_wqe};
use likely_stable::unlikely;
use nix::errno::Errno;
use nix::Error;
use rdma_sys::ibv_opcode::IBV_OPCODE_RC_COMPARE_SWAP;
use rdma_sys::{ibv_opcode, ibv_qp_type, ibv_send_flags, ibv_wc_status, ibv_wr_opcode};
use std::cell::RefCell;
use std::ptr::NonNull;
use std::rc::Rc;
use tracing::{debug, error};

impl RxeQueuePair {
    fn retry_first_write_send(&mut self, wqe: &mut librxe_sys::rxe_send_wqe, npsn: u32) {
        for _ in 0..npsn {
            let to_send = if wqe.dma.resid > self.mtu {
                self.mtu
            } else {
                wqe.dma.resid
            };
            self.req.opcode = self.next_opcode(wqe, wqe.wr.opcode).unwrap() as _;
            if (wqe.wr.send_flags & ibv_send_flags::IBV_SEND_INLINE.0) != 0 {
                wqe.dma.resid -= to_send;
                wqe.dma.sge_offset += to_send;
            } else {
                RxeMr::advance_dma_data(&mut wqe.dma, to_send).unwrap();
            }
        }
    }

    fn req_retry(&mut self) {
        let sq_buf = self.sq_queue();
        let prod = librxe_sys::load_producer_index(sq_buf);
        let cons = librxe_sys::load_consumer_index(sq_buf);
        self.req.wqe_index = cons;
        self.req.psn = self.comp.psn;
        self.req.opcode = -1;
        let mut first = true;

        let mut wqe_index = cons;
        while wqe_index != prod {
            let wqe = unsafe {
                &mut *(librxe_sys::addr_from_index::<librxe_sys::rxe_send_wqe>(sq_buf, wqe_index))
            };
            let mask = wr_opcode_mask(self.qp_type(), wqe.wr.opcode);
            if wqe.state == WqeState::WqeStatePosted {
                break;
            }
            if wqe.state == WqeState::WqeStateDone {
                continue;
            }
            wqe.iova = if mask & rxe_wr_mask::WR_ATOMIC_MASK != 0 {
                unsafe { wqe.wr.wr.atomic.remote_addr }
            } else if mask & rxe_wr_mask::WR_READ_OR_WRITE_MASK != 0 {
                unsafe { wqe.wr.wr.rdma.remote_addr }
            } else {
                0
            };
            if !first || mask & rxe_wr_mask::WR_READ_MASK != 0 {
                wqe.dma.resid = wqe.dma.length;
                wqe.dma.cur_sge = 0;
                wqe.dma.sge_offset = 0;
            }
            if first {
                first = false;

                if mask & rxe_wr_mask::WR_WRITE_OR_SEND_MASK != 0 {
                    let npsn = (self.comp.psn - wqe.first_psn) & bth_mask::BTH_PSN_MASK;
                    self.retry_first_write_send(wqe, npsn);
                }

                if mask & rxe_wr_mask::WR_READ_MASK != 0 {
                    let npsn = (wqe.dma.length - wqe.dma.resid) / self.mtu;
                    wqe.iova = (npsn * self.mtu) as u64;
                }
            }

            wqe.state = WqeState::WqeStatePosted as _;

            // get next wqe index
            wqe_index = librxe_sys::queue_next_index(sq_buf, wqe_index as i32) as u32;
        }
    }

    fn next_opcode(
        &self,
        wqe: &librxe_sys::rxe_send_wqe,
        opcode: rdma_sys::ibv_wr_opcode::Type,
    ) -> Result<ibv_opcode::Type, Error> {
        let fits = wqe.dma.resid <= self.mtu;
        match self.qp_type() {
            ibv_qp_type::IBV_QPT_RC => self.next_opcode_rc(opcode, fits),
            ibv_qp_type::IBV_QPT_UC => self.next_opcode_uc(opcode, fits),
            ibv_qp_type::IBV_QPT_UD => match opcode {
                ibv_wr_opcode::IBV_WR_SEND => Ok(ibv_opcode::IBV_OPCODE_UD_SEND_ONLY),
                ibv_wr_opcode::IBV_WR_SEND_WITH_IMM => {
                    Ok(ibv_opcode::IBV_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE)
                }
                _ => Err(Error::EINVAL),
            },
            // FIXME: IB_QPT_GSI is only available in the kernel
            // and it should behave the same as IB_QPT_UD
            _ => Err(Error::EINVAL),
        }
    }

    fn next_opcode_rc(
        &self,
        opcode: rdma_sys::ibv_wr_opcode::Type,
        fits: bool,
    ) -> Result<ibv_opcode::Type, Error> {
        let req_op = self.req.opcode as ibv_opcode::Type;
        match opcode {
            ibv_wr_opcode::IBV_WR_RDMA_WRITE => {
                if (req_op == ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_ONLY)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_FIRST)
                    };
                }
            }
            ibv_wr_opcode::IBV_WR_RDMA_WRITE_WITH_IMM => {
                if (req_op == ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_FIRST)
                    };
                }
            }
            ibv_wr_opcode::IBV_WR_SEND => {
                if (req_op == ibv_opcode::IBV_OPCODE_RC_SEND_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_LAST)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_ONLY)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_FIRST)
                    };
                }
            }
            ibv_wr_opcode::IBV_WR_SEND_WITH_IMM => {
                if (req_op == ibv_opcode::IBV_OPCODE_RC_SEND_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_FIRST)
                    };
                }
            }
            ibv_wr_opcode::IBV_WR_RDMA_READ => Ok(ibv_opcode::IBV_OPCODE_RC_RDMA_READ_REQUEST),
            ibv_wr_opcode::IBV_WR_ATOMIC_CMP_AND_SWP => Ok(ibv_opcode::IBV_OPCODE_RC_COMPARE_SWAP),
            ibv_wr_opcode::IBV_WR_ATOMIC_FETCH_AND_ADD => Ok(ibv_opcode::IBV_OPCODE_RC_FETCH_ADD),
            ibv_wr_opcode::IBV_WR_SEND_WITH_INV => {
                if (req_op == ibv_opcode::IBV_OPCODE_RC_SEND_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_RC_SEND_FIRST)
                    };
                }
            }
            // FIXME: work request opcode IB_WR_REG_MR and IB_WR_LOCAL_INV are only avaliable in kernel space
            _ => Err(Error::EINVAL),
        }
    }

    fn next_opcode_uc(
        &self,
        opcode: rdma_sys::ibv_wr_opcode::Type,
        fits: bool,
    ) -> Result<ibv_opcode::Type, Error> {
        let req_op = self.req.opcode as ibv_opcode::Type;
        match opcode {
            ibv_wr_opcode::IBV_WR_RDMA_WRITE => {
                if (req_op == ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_ONLY)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_FIRST)
                    };
                }
            }
            ibv_wr_opcode::IBV_WR_RDMA_WRITE_WITH_IMM => {
                if (req_op == ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_FIRST)
                    };
                }
            }
            ibv_wr_opcode::IBV_WR_SEND => {
                if (req_op == ibv_opcode::IBV_OPCODE_UC_SEND_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_LAST)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_ONLY)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_FIRST)
                    };
                }
            }
            ibv_wr_opcode::IBV_WR_SEND_WITH_IMM => {
                if (req_op == ibv_opcode::IBV_OPCODE_UC_SEND_FIRST)
                    || (req_op == ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE)
                {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE)
                    };
                } else {
                    return if fits {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE)
                    } else {
                        Ok(ibv_opcode::IBV_OPCODE_UC_SEND_FIRST)
                    };
                }
            }
            _ => Err(Error::EINVAL),
        }
    }

    #[inline]
    fn get_mtu(&self) -> u32 {
        if self.qp_type() == ibv_qp_type::IBV_QPT_RC || self.qp_type() == ibv_qp_type::IBV_QPT_UC {
            self.mtu
        } else {
            1024 // FIXME it should be the max mtu value: to_rdev(qp->ibqp.device)->port.mtu_cap
        }
    }

    #[inline]
    fn check_init_depth(&mut self, wqe: &mut librxe_sys::rxe_send_wqe) -> Result<(), Error> {
        if wqe.has_rd_atomic != 0 {
            return Ok(());
        }
        self.req.need_rd_atomic = 1;
        let depth = self.dec_return_req_rd_atomic();
        if depth >= 0 {
            self.req.need_rd_atomic = 0;
            wqe.has_rd_atomic = 1;
            return Ok(());
        }
        self.inc_req_rd_atomic();

        Err(Error::EAGAIN)
    }

    fn req_next_wqe(&mut self) -> Option<*mut librxe_sys::rxe_send_wqe> {
        let sq_buf = self.sq_queue();
        let wqe = librxe_sys::queue_head::<librxe_sys::rxe_send_wqe>(sq_buf);
        let index = self.req.wqe_index as u32;
        let prod = librxe_sys::load_producer_index(sq_buf);
        let cons = librxe_sys::load_consumer_index(sq_buf);

        if unlikely(self.req.state == RxeQpState::QpStateDrain) {
            // check to see if we are drained;
            // state_lock used by requester and completer
            unsafe {
                libc::pthread_spin_lock(&mut self.state_lock);
            }
            loop {
                if self.req.state != RxeQpState::QpStateDrain {
                    /* comp just finished */
                    unsafe {
                        libc::pthread_spin_unlock(&mut self.state_lock);
                    }
                    break;
                }
                if let Some(wqe) = wqe {
                    unsafe {
                        if (index != cons) || (*wqe).state != WqeState::WqeStatePosted {
                            libc::pthread_spin_unlock(&mut self.state_lock);
                        }
                    }
                    break;
                }
                self.req.state = RxeQpState::QpStateDrained;
                unsafe {
                    libc::pthread_spin_unlock(&mut self.state_lock);
                }
                // TODO qp->ibqp.event_handler
                break;
            }
        }
        if index == prod {
            return None;
        }
        let wqe = unsafe {
            &mut *(librxe_sys::addr_from_index::<librxe_sys::rxe_send_wqe>(sq_buf, index))
        };
        if unlikely(
            (self.req.state == RxeQpState::QpStateDrain
                || self.req.state == RxeQpState::QpStateDrained)
                && wqe.state != WqeState::WqeStateProcessing,
        ) {
            return None;
        }
        wqe.mask = wr_opcode_mask(self.qp_type(), wqe.wr.opcode);

        Some(wqe)
    }

    /// check if next wqe is fenced
    ///
    /// returns 1 if wqe needs to wait
    ///         0 if wqe is ready to go
    fn rxe_wqe_is_fenced(&mut self, wqe: &mut librxe_sys::rxe_send_wqe) -> bool {
        // Local invalidate fence (LIF) see IBA 10.6.5.1
        // Requires ALL previous operations on the send queue
        // are complete. Make mandatory for the rxe driver.
        return if wqe.wr.send_flags == ibv_wr_opcode::IBV_WR_LOCAL_INV {
            self.req.wqe_index != librxe_sys::load_producer_index(self.sq_queue())
        } else {
            // Fence see IBA 10.8.3.3
            // Requires that all previous read and atomic operations are complete.
            wqe.wr.send_flags & ibv_send_flags::IBV_SEND_FENCE.0 != 0
                && self.load_req_rd_atomic() != unsafe { self.attr.as_ref().max_rd_atomic }
        };
    }

    fn init_req_packet(
        &mut self,
        wqe: &mut librxe_sys::rxe_send_wqe,
        opcode: u8,
        payload: u32, // payload length
        pkt_info: &mut RxePktInfo,
    ) {
        use rxe_hdr_mask::*;
        // pad length, truncate u32 to u8
        let pad: u8 = ((0 - payload as i32) as u8) & 0x3;
        /* length from start of bth to end of icrc */
        let paylen =
            RXE_OPCODE_INFO[opcode as usize].length as u32 + payload + pad as u32 + RXE_ICRC_SIZE;
        pkt_info.paylen = paylen as _;

        // init iba pkt buffer
        pkt_info.set_iba_pkt_len(paylen as _);
        pkt_info.mask = pkt_info.mask | RXE_GRH_MASK;

        let ibwr = &wqe.wr;
        let solicited: bool = ((ibwr.send_flags & ibv_send_flags::IBV_SEND_SOLICITED.0) != 0)
            && ((pkt_info.mask & RXE_END_MASK) != 0)
            && (((pkt_info.mask & RXE_SEND_MASK) != 0)
                || (pkt_info.mask & (RXE_WRITE_MASK | RXE_IMMDT_MASK))
                    == (RXE_WRITE_MASK | RXE_IMMDT_MASK));

        let dest_qp_num: u32 = unsafe {
            if pkt_info.mask & RXE_DETH_MASK != 0 {
                ibwr.wr.ud.remote_qpn
            } else {
                self.attr.as_ref().dest_qp_num
            }
        };
        self.req.noack_pkts = self.req.noack_pkts + 1;
        let ack_req = ((pkt_info.mask & RXE_END_MASK) != 0)
            || ((self.req.noack_pkts + 1) > rxe_device_param::RXE_MAX_PKT_PER_ACK as _);
        if ack_req {
            self.req.noack_pkts = 0;
        }

        // init base transport header
        pkt_info.bth_init(
            opcode,
            solicited,
            false,
            pad,
            rxe_verbs::IB_DEFAULT_PKEY_FULL,
            dest_qp_num,
            ack_req,
            pkt_info.psn,
        );
        // init optional headers
        if (pkt_info.mask & RXE_RETH_MASK) != 0 {
            pkt_info.reth_set_rkey(unsafe { ibwr.wr.rdma.rkey });
            pkt_info.reth_set_va(wqe.iova);
            pkt_info.reth_set_len(wqe.dma.resid);
        }
        if (pkt_info.mask & RXE_IMMDT_MASK) != 0 {
            pkt_info.immdt_set_imm(unsafe { ibwr.ex.imm_data });
        }
        if (pkt_info.mask & RXE_ATMETH_MASK) != 0 {
            pkt_info.atmeth_set_va(wqe.iova);
            if opcode == IBV_OPCODE_RC_COMPARE_SWAP {
                pkt_info.atmeth_set_swap_add(unsafe { ibwr.wr.atomic.swap });
                pkt_info.atmeth_set_comp(unsafe { ibwr.wr.atomic.compare_add });
            } else {
                pkt_info.atmeth_set_swap_add(unsafe { ibwr.wr.atomic.compare_add });
            }
            pkt_info.atmeth_set_rkey(unsafe { ibwr.wr.atomic.rkey });
        }
        let src_qp_num = self.qp_num();
        if (pkt_info.mask & RXE_DETH_MASK) != 0 {
            if src_qp_num == 1 {
                pkt_info.deth_set_qkey(GSI_QKEY);
            } else {
                pkt_info.deth_set_qkey(unsafe { ibwr.wr.ud.remote_qkey });
            }
            pkt_info.deth_set_sqp(src_qp_num);
        }
    }

    // fill the IBA content only,
    // the IP/UDP headers, these will be filled in the kernel
    // the IBA headers has been populated
    pub fn finish_packet(
        &mut self,
        wqe: &mut librxe_sys::rxe_send_wqe,
        pkt_info: &mut RxePktInfo,
        payload: usize,
    ) -> Result<(), Error> {
        if (pkt_info.mask & rxe_hdr_mask::RXE_WRITE_OR_SEND_MASK) != 0 {
            if (wqe.wr.send_flags & ibv_send_flags::IBV_SEND_INLINE.0) != 0 {
                unsafe {
                    let inline_data_base = wqe
                        .dma
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .as_mut()
                        .inline_data
                        .as_mut_ptr();
                    let inline_data = inline_data_base.add(wqe.dma.sge_offset as usize);
                    let slice = std::slice::from_raw_parts(inline_data, payload);
                    let mut tmp_view = pkt_info.split_iba_pkt(pkt_info.get_iba_hdr_len());
                    tmp_view.copy_from_slice(slice);
                    pkt_info.unsplit_iba_pkt(tmp_view);
                }
            } else {
                unsafe {
                    self.pd.as_ref().copy_data(
                        0,
                        &mut wqe.dma,
                        pkt_info.payload_addr(),
                        payload as u32,
                        RxeMrCopyDir::RxeFromMrObj,
                    )?
                };
            }
        }
        Ok(())
    }
    #[inline]
    fn save_state(
        &self,
        wqe: &rxe_send_wqe,
        rollback_wqe: &mut rxe_send_wqe,
        rollback_psn: &mut u32,
    ) {
        rollback_wqe.state = wqe.state;
        rollback_wqe.first_psn = wqe.first_psn;
        rollback_wqe.last_psn = wqe.last_psn;
        *rollback_psn = self.req.psn;
    }
    #[inline]
    fn rollback_state(
        &mut self,
        wqe: &mut rxe_send_wqe,
        rollback_wqe: &rxe_send_wqe,
        rollback_psn: u32,
    ) {
        wqe.state = rollback_wqe.state;
        wqe.first_psn = rollback_wqe.first_psn;
        wqe.last_psn = rollback_wqe.last_psn;
        self.req.psn = rollback_psn;
    }

    #[inline]
    fn update_wqe_state(&self, pkt: &RxePktInfo, wqe: &mut librxe_sys::rxe_send_wqe) {
        if pkt.mask & rxe_hdr_mask::RXE_END_MASK != 0 {
            if self.qp_type() == ibv_qp_type::IBV_QPT_RC {
                wqe.state = WqeState::WqeStatePending as _;
            } else {
                wqe.state = WqeState::WqeStateProcessing as _;
            }
        }
    }

    #[inline]
    fn update_state(&mut self, pkt: &RxePktInfo) {
        self.req.opcode = pkt.opcode as _;
        if (pkt.mask & rxe_hdr_mask::RXE_END_MASK) != 0 {
            self.req.wqe_index =
                librxe_sys::queue_next_index(self.sq_queue(), self.req.wqe_index as _) as _;
        }
        // TODO check timers
    }
    #[inline]
    fn update_wqe_psn(
        &mut self,
        wqe: &mut librxe_sys::rxe_send_wqe,
        pkt: &RxePktInfo,
        payload: u32,
    ) {
        // number of packets left to send including current one
        let _num_pkt = (wqe.dma.resid + payload + self.mtu - 1) / self.mtu;
        let num_pkt = if _num_pkt == 0 { 1 } else { _num_pkt };
        if (pkt.mask & rxe_hdr_mask::RXE_START_MASK) != 0 {
            wqe.first_psn = self.req.psn;
            wqe.last_psn = (self.req.psn + num_pkt - 1) & bth_mask::BTH_PSN_MASK;
        }
        if (pkt.mask & rxe_hdr_mask::RXE_READ_MASK) != 0 {
            self.req.psn = (wqe.first_psn + num_pkt) & bth_mask::BTH_PSN_MASK;
        } else {
            self.req.psn = (self.req.psn + 1) & bth_mask::BTH_PSN_MASK;
        }
    }

    /// the behavior is same as `goto err` in rxe_requester
    ///
    /// update wqe_index for each wqe completion
    fn rxe_requester_err(&mut self, wqe: &mut librxe_sys::rxe_send_wqe) {
        self.req.wqe_index =
            librxe_sys::queue_next_index(self.sq_queue(), self.req.wqe_index as _) as _;
        wqe.state = WqeState::WqeStateError as _;
        self.req.state = RxeQpState::QpStateError;
        // TODO rxe_run_task(&qp->comp.task, 0);
    }
    pub fn rxe_requester(&mut self) -> Result<(), Error> {
        // break the loop only if the current work request element is illegal
        loop {
            if unlikely(!self.valid) {
                break;
            }
            if unlikely(self.req.state == RxeQpState::QpStateError) {
                if let Some(wqe) = self.req_next_wqe() {
                    self.rxe_requester_err(unsafe { &mut (*wqe) });
                }
                break;
            }

            // we come here if the retransmit timer has fired
            // or if the rnr timer has fired. If the retransmit
            // timer fires while we are processing an RNR NAK wait
            // until the rnr timer has fired before starting the
            // retry flow
            if unlikely(self.req.state == RxeQpState::QpStateReset) {
                self.req.wqe_index = load_consumer_index(self.sq_queue());
                self.req.opcode = -1;
                self.req.need_rd_atomic = 0;
                self.req.wait_psn = 0;
                self.req.need_retry = 0;
                self.req.wait_for_rnr_timer = 0;
                break;
            }
            if unlikely(self.req.need_retry == 1 && self.req.wait_for_rnr_timer != 0) {
                self.req_retry();
                self.req.need_retry = 0;
            }

            let mut wqe = match self.req_next_wqe() {
                Some(wqe) => unsafe { &mut (*wqe) },
                // TODO: should be unlikely
                None => break,
            };

            if self.rxe_wqe_is_fenced(wqe) {
                self.req.wait_fence = 1;
                break;
            }
            if (wqe.mask & rxe_wr_mask::WR_LOCAL_OP_MASK as u32) != 0 {
                // TODO: impl rxe_do_local_ops()
                // skip this wqe
                break;
            }

            if unlikely(
                self.qp_type() == ibv_qp_type::IBV_QPT_RC
                    && psn_compare(
                        self.req.psn,
                        self.comp.psn + rxe_device_param::RXE_MAX_UNACKED_PSNS as u32,
                    ) > 0,
            ) {
                self.req.wait_psn = 1;
                break;
            }

            let opcode = match self.next_opcode(&wqe, wqe.wr.opcode) {
                Ok(opcode) => opcode,
                Err(_) => {
                    wqe.state = WqeState::WqeStateError as _;
                    self.rxe_requester_err(wqe);
                    break;
                }
            };

            let mask = RXE_OPCODE_INFO[opcode as usize].mask;
            if unlikely((mask & rxe_hdr_mask::RXE_READ_OR_ATOMIC_MASK) != 0) {
                if self.check_init_depth(wqe).is_err() {
                    break;
                }
            }
            let mut payload = if (mask & rxe_hdr_mask::RXE_WRITE_OR_SEND_MASK) != 0 {
                wqe.dma.resid
            } else {
                0
            };
            let mtu = self.get_mtu();
            if payload > mtu {
                if self.qp_type() == ibv_qp_type::IBV_QPT_UD {
                    /* C10-93.1.1: If the total sum of all the buffer lengths specified for a
                     * UD message exceeds the MTU of the port as returned by QueryHCA, the CI
                     * shall not emit any packets for this message. Further, the CI shall not
                     * generate an error due to this condition.
                     */
                    // fake a successful UD send and return
                    wqe.first_psn = self.req.psn;
                    wqe.last_psn = self.req.psn;
                    self.req.psn = (self.req.psn + 1) & bth_mask::BTH_PSN_MASK;
                    self.req.opcode = ibv_opcode::IBV_OPCODE_UD_SEND_ONLY as _;
                    self.req.wqe_index =
                        librxe_sys::queue_next_index(self.sq_queue(), self.req.wqe_index as _) as _;
                    wqe.state = WqeState::WqeStateDone as _;
                    wqe.status = ibv_wc_status::IBV_WC_SUCCESS;
                    // TODO: 	__rxe_do_task(&qp->comp.task);
                    return Ok(());
                }
                payload = self.mtu;
            }
            let pkt_info = Rc::new(RefCell::new(RxePktInfo::new_requester(
                Some(Rc::new(RefCell::new(self.clone()))),
                Some(NonNull::new(wqe).unwrap()),
                RXE_OPCODE_INFO[opcode as usize].mask as _,
                self.req.psn,
                0,
                0,
                1, // always 1 in RXE
                opcode as u8,
                self.mtu,
            )));
            let av = if let Some(av) = rxe_get_av(&pkt_info.borrow()) {
                av
            } else {
                error!("QP#{} failed to get no address vector", self.qp_num());
                wqe.status = ibv_wc_status::IBV_WC_LOC_QP_OP_ERR;
                self.rxe_requester_err(wqe);
                break;
            };
            // init iba packet buffer and header
            self.init_req_packet(&mut wqe, opcode, payload, &mut pkt_info.borrow_mut());
            // fill the iba packet content
            if let Err(ret) = self.finish_packet(wqe, &mut pkt_info.borrow_mut(), payload as _) {
                error!("QP#{} error during finish packet", self.qp_num());
                if ret == Errno::EFAULT {
                    wqe.status = ibv_wc_status::IBV_WC_LOC_PROT_ERR;
                } else {
                    wqe.status = ibv_wc_status::IBV_WC_LOC_QP_OP_ERR;
                }
                self.rxe_requester_err(wqe);
                break;
            }
            // save state
            let mut rollback_wqe = librxe_sys::rxe_send_wqe::default();
            let mut rollback_psn = 0;
            self.save_state(wqe, &mut rollback_wqe, &mut rollback_psn);
            self.update_wqe_state(&pkt_info.borrow(), wqe);
            self.update_wqe_psn(wqe, &pkt_info.borrow(), payload);
            // transmit this packet
            let rxe_skb = RxeSkb::new(pkt_info.clone(), &self, &av);
            rxe_skb.rxe_xmit_packet();
            self.update_state(&pkt_info.borrow());
            return Ok(());
        }

        Err(Error::EAGAIN)
    }
}
