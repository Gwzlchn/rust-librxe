use crate::{
    rxe_cq::{RxeCompletionQueue, RxeCqe},
    rxe_hdr::{aeth_syndrome, bth_mask, RxePktInfo},
    rxe_opcode::{rxe_hdr_mask, rxe_wr_mask},
    rxe_qp::{RxeQpState, RxeQueuePair},
    rxe_verbs::{psn_compare, RxeMrCopyDir, WqeState},
};
use librxe_sys::{self, advance_consumer, queue_head};
use nix::Error;
use rdma_sys::{
    ibv_access_flags, ibv_opcode::*, ibv_qp_type, ibv_send_flags, ibv_wc_flags, ibv_wc_opcode,
    ibv_wc_status, ibv_wr_opcode,
};
use std::fmt;
use tracing::{debug, warn};

enum CompState {
    CompstGetAck,
    CompstGetWqe,
    CompstCompWqe,
    CompstCompAck,
    CompstCheckPsn,
    CompstCheckAck,
    CompstRead,
    CompstAtomic,
    CompstWriteSend,
    CompstUpdateComp,
    CompstErrorRetry,
    CompstRnrRetry,
    CompstError,
    // We have an issue, and we want to rerun the completer
    CompstExit,
    // The completer finished successflly
    CompstDone,
}

impl fmt::Display for CompState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CompState::CompstGetAck => write!(f, "GET ACK"),
            CompState::CompstGetWqe => write!(f, "GET WQE"),
            CompState::CompstCompWqe => write!(f, "COMP WQE"),
            CompState::CompstCompAck => write!(f, "COMP ACK"),
            CompState::CompstCheckPsn => write!(f, "CHECK PSN"),
            CompState::CompstCheckAck => write!(f, "CHECK ACK"),
            CompState::CompstRead => write!(f, "READ"),
            CompState::CompstAtomic => write!(f, "ATOMIC"),
            CompState::CompstWriteSend => write!(f, "WRITE/SEND"),
            CompState::CompstUpdateComp => write!(f, "UPDATE COMP"),
            CompState::CompstErrorRetry => write!(f, "ERROR RETRY"),
            CompState::CompstRnrRetry => write!(f, "RNR RETRY"),
            CompState::CompstError => write!(f, "ERROR"),
            CompState::CompstExit => write!(f, "EXIT"),
            CompState::CompstDone => write!(f, "DONE"),
        }
    }
}

pub fn wr_to_wc_opcode(opcode: ibv_wr_opcode::Type) -> ibv_wc_opcode::Type {
    match opcode {
        ibv_wr_opcode::IBV_WR_RDMA_WRITE => ibv_wc_opcode::IBV_WC_RDMA_WRITE,
        ibv_wr_opcode::IBV_WR_RDMA_WRITE_WITH_IMM => ibv_wc_opcode::IBV_WC_RDMA_WRITE,
        ibv_wr_opcode::IBV_WR_SEND => ibv_wc_opcode::IBV_WC_SEND,
        ibv_wr_opcode::IBV_WR_SEND_WITH_IMM => ibv_wc_opcode::IBV_WC_SEND,
        ibv_wr_opcode::IBV_WR_RDMA_READ => ibv_wc_opcode::IBV_WC_RDMA_READ,
        ibv_wr_opcode::IBV_WR_ATOMIC_CMP_AND_SWP => ibv_wc_opcode::IBV_WC_COMP_SWAP,
        ibv_wr_opcode::IBV_WR_ATOMIC_FETCH_AND_ADD => ibv_wc_opcode::IBV_WC_FETCH_ADD,
        //ibv_wr_opcode::IBV_WR_LSO => ibv_wc_opcode::IBV_WC_LSO,
        ibv_wr_opcode::IBV_WR_SEND_WITH_INV => ibv_wc_opcode::IBV_WC_SEND,
        //ibv_wr_opcode::IBV_WR_RDMA_READ_WITH_INV => ibv_wc_opcode::IBV_WC_RDMA_READ,
        ibv_wr_opcode::IBV_WR_LOCAL_INV => ibv_wc_opcode::IBV_WC_LOCAL_INV,
        //ibv_wr_opcode::IBV_WR_REG_MR => ibv_wc_opcode::IBV_WC_REG_MR,
        //ibv_wr_opcode::IBV_WR_BIND_MW => ibv_wc_opcode::IB_WC_BIND_MW,
        _ => 0xff,
    }
}

impl RxeQueuePair {
    #[inline]
    fn get_wqe_comp(
        &mut self,
        pkt_info: Option<&RxePktInfo>,
        mut wqe: &mut librxe_sys::rxe_send_wqe,
    ) -> CompState {
        let _wqe = queue_head::<librxe_sys::rxe_send_wqe>(self.sq_queue());
        if _wqe.is_none() {
            return if pkt_info.is_some() {
                CompState::CompstDone
            } else {
                CompState::CompstExit
            };
        }
        wqe = unsafe { &mut *_wqe.unwrap() };
        if wqe.state == WqeState::WqeStatePosted as u32 {
            return if pkt_info.is_some() {
                CompState::CompstDone
            } else {
                CompState::CompstExit
            };
        }
        if wqe.state == WqeState::WqeStateDone as u32 {
            return CompState::CompstCompWqe;
        }
        if wqe.state == WqeState::WqeStateError as u32 {
            return CompState::CompstError;
        }
        return if pkt_info.is_some() {
            CompState::CompstCheckPsn
        } else {
            CompState::CompstExit
        };
    }

    #[inline]
    fn reset_retry_counters(&mut self) {
        self.comp.retry_cnt = unsafe { self.attr.as_ref().retry_cnt as u32 };
        self.comp.rnr_retry = unsafe { self.attr.as_ref().rnr_retry as u32 };
        self.comp.started_retry = 0;
    }

    #[inline]
    fn check_psn_comp(
        &mut self,
        pkt_info: &RxePktInfo,
        wqe: &librxe_sys::rxe_send_wqe,
    ) -> CompState {
        /* check to see if response is past the oldest WQE. if it is, complete
         * send/write or error read/atomic
         */
        let diff = psn_compare(pkt_info.psn, wqe.last_psn);
        if diff > 0 {
            if wqe.state == WqeState::WqeStatePending as u32 {
                if wqe.mask & rxe_wr_mask::WR_ATOMIC_OR_READ_MASK != 0 {
                    return CompState::CompstErrorRetry;
                }
                self.reset_retry_counters();
                return CompState::CompstCompWqe;
            } else {
                return CompState::CompstDone;
            }
        }
        /* compare response packet to expected response */
        let diff = psn_compare(pkt_info.psn, self.comp.psn);
        if diff < 0 {
            return if pkt_info.psn == wqe.last_psn {
                CompState::CompstCompAck
            } else {
                CompState::CompstDone
            };
        } else if (diff > 0) && wqe.mask & rxe_wr_mask::WR_ATOMIC_OR_READ_MASK != 0 {
            return CompState::CompstDone;
        }
        return CompState::CompstCheckAck;
    }

    #[inline]
    fn check_ack_comp(
        &mut self,
        pkt_info: &RxePktInfo,
        wqe: &mut librxe_sys::rxe_send_wqe,
    ) -> CompState {
        let mask = pkt_info.mask;
        let comp_opcode = self.comp.opcode;

        if comp_opcode == -1 && (mask & rxe_hdr_mask::RXE_START_MASK == 0) {
            return CompState::CompstError;
        } else if comp_opcode == IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as i32
            || comp_opcode == IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE as i32
        {
            if (pkt_info.opcode != IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE)
                && (pkt_info.opcode != IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST)
            {
                /* read retries of partial data may restart from
                 * read response first or response only.
                 */
                if !((pkt_info.psn == wqe.first_psn
                    && pkt_info.opcode == IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST)
                    || (wqe.first_psn == wqe.last_psn
                        && pkt_info.opcode == IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY))
                {
                    return CompState::CompstError;
                }
            }
        }
        /* Check operation validity. */
        let opcode = pkt_info.opcode;
        match opcode {
            IBV_OPCODE_RC_RDMA_READ_RESPONSE_FIRST
            | IBV_OPCODE_RC_RDMA_READ_RESPONSE_LAST
            | IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY
            | IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE => {
                //  (IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE doesn't have an AETH)
                if opcode != IBV_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE {
                    let syn = pkt_info.aeth_syn();
                    if (syn & aeth_syndrome::AETH_TYPE_MASK) != aeth_syndrome::AETH_ACK {
                        return CompState::CompstError;
                    }
                }
                if wqe.wr.opcode != ibv_wr_opcode::IBV_WR_RDMA_READ
                    && wqe.wr.opcode != ibv_wr_opcode::IBV_WR_DRIVER1
                {
                    wqe.status = ibv_wc_status::IBV_WC_FATAL_ERR;
                    return CompState::CompstError;
                }
                self.reset_retry_counters();
                return CompState::CompstRead;
            }
            IBV_OPCODE_RC_ATOMIC_ACKNOWLEDGE => {
                let syn = pkt_info.aeth_syn();
                if (syn & aeth_syndrome::AETH_TYPE_MASK) != aeth_syndrome::AETH_ACK {
                    return CompState::CompstError;
                }
                if wqe.wr.opcode != ibv_wr_opcode::IBV_WR_ATOMIC_CMP_AND_SWP
                    && wqe.wr.opcode != ibv_wr_opcode::IBV_WR_ATOMIC_FETCH_AND_ADD
                {
                    return CompState::CompstError;
                }
                self.reset_retry_counters();

                return CompState::CompstAtomic;
            }
            IBV_OPCODE_RC_ACKNOWLEDGE => {
                let syn = pkt_info.aeth_syn();
                let aeth_type = syn & aeth_syndrome::AETH_TYPE_MASK;
                match aeth_type {
                    aeth_syndrome::AETH_ACK => {
                        self.reset_retry_counters();
                        return CompState::CompstWriteSend;
                    }
                    aeth_syndrome::AETH_RNR_NAK => {
                        return CompState::CompstRnrRetry;
                    }
                    aeth_syndrome::AETH_NAK => match syn {
                        aeth_syndrome::AETH_NAK_PSN_SEQ_ERROR => {
                            if psn_compare(pkt_info.psn, self.comp.psn) > 0 {
                                self.comp.psn = pkt_info.psn;
                                if self.req.wait_psn != 0 {
                                    self.req.wait_psn = 0;
                                    // TODO: rxe_run_task(&qp->req.task, 0);
                                }
                            }
                            return CompState::CompstErrorRetry;
                        }
                        aeth_syndrome::AETH_NAK_INVALID_REQ => {
                            wqe.status = ibv_wc_status::IBV_WC_REM_INV_REQ_ERR;
                            return CompState::CompstError;
                        }
                        aeth_syndrome::AETH_NAK_REM_ACC_ERR => {
                            wqe.status = ibv_wc_status::IBV_WC_REM_ACCESS_ERR;
                            return CompState::CompstError;
                        }
                        aeth_syndrome::AETH_NAK_REM_OP_ERR => {
                            wqe.status = ibv_wc_status::IBV_WC_REM_OP_ERR;
                            return CompState::CompstError;
                        }
                        _ => {
                            warn!("unexpected nak {:x}", syn);
                            wqe.status = ibv_wc_status::IBV_WC_REM_OP_ERR;
                            return CompState::CompstError;
                        }
                    },
                    _ => return CompState::CompstError,
                }
            }
            _ => warn!("unexpected opcode"),
        }
        return CompState::CompstError;
    }

    #[inline]
    fn do_read(
        &mut self,
        pkt_info: &mut RxePktInfo,
        wqe: &mut librxe_sys::rxe_send_wqe,
    ) -> CompState {
        if let Err(_) = unsafe {
            self.pd.as_ref().copy_data(
                ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0,
                &mut wqe.dma,
                pkt_info.payload_addr(),
                pkt_info.payload_size() as u32,
                RxeMrCopyDir::RxeToMrObj,
            )
        } {
            wqe.status = ibv_wc_status::IBV_WC_LOC_PROT_ERR;
            return CompState::CompstError;
        }
        if wqe.dma.resid == 0 && pkt_info.mask & rxe_hdr_mask::RXE_END_MASK != 0 {
            return CompState::CompstCompAck;
        }
        return CompState::CompstUpdateComp;
    }

    #[inline]
    fn do_atomic(
        &mut self,
        pkt_info: &mut RxePktInfo,
        wqe: &mut librxe_sys::rxe_send_wqe,
    ) -> CompState {
        let mut atomic_orig: u64 = pkt_info.atmack_orig();

        if let Err(_) = unsafe {
            self.pd.as_ref().copy_data(
                ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0,
                &mut wqe.dma,
                &mut atomic_orig as *mut u64 as *mut u8,
                std::mem::size_of::<u64>() as u32,
                RxeMrCopyDir::RxeToMrObj,
            )
        } {
            wqe.status = ibv_wc_status::IBV_WC_LOC_PROT_ERR;
            return CompState::CompstError;
        }
        return CompState::CompstCompAck;
    }

    #[inline]
    fn make_send_cqe(&mut self, wqe: &librxe_sys::rxe_send_wqe, cqe: &mut RxeCqe) {
        // RxeCqe initialize outside
        cqe.wc.wr_id = wqe.wr.wr_id;
        cqe.wc.status = wqe.status;
        cqe.wc.qp_num = self.qp_num();
        if wqe.status == ibv_wc_status::IBV_WC_SUCCESS {
            cqe.wc.opcode = wr_to_wc_opcode(wqe.wr.opcode);
            if wqe.wr.opcode == ibv_wr_opcode::IBV_WR_RDMA_WRITE_WITH_IMM
                || wqe.wr.opcode == ibv_wr_opcode::IBV_WR_SEND_WITH_IMM
            {
                cqe.wc.wc_flags = ibv_wc_flags::IBV_WC_WITH_IMM.0;
            }
            cqe.wc.byte_len = wqe.dma.length;
        }
    }

    #[inline]
    fn do_complete_comp(&mut self, wqe: &librxe_sys::rxe_send_wqe) {
        let _post = wqe.wr.send_flags & ibv_send_flags::IBV_SEND_SIGNALED.0 != 0
            || wqe.status != ibv_wc_status::IBV_WC_SUCCESS;
        let mut cqe = RxeCqe::default();
        if _post {
            self.make_send_cqe(wqe, &mut cqe);
        }
        advance_consumer(self.sq_queue());
        if _post {
            unsafe { RxeCompletionQueue::cq_post(&mut self.scq, &mut cqe, false).unwrap() };
        }
        // TODO rxe_run_task
    }

    #[inline]
    fn complete_ack(
        &mut self,
        pkt_info: &mut RxePktInfo,
        wqe: &mut librxe_sys::rxe_send_wqe,
    ) -> CompState {
        if wqe.has_rd_atomic != 0 {
            wqe.has_rd_atomic = 0;
            self.req.rd_atomic += 1; // TODO should use atomic_inc here
            if self.req.need_rd_atomic != 0 {
                self.comp.timeout_retry = 0;
                self.req.need_rd_atomic = 0;
                // TODO rxe_run_task(&qp->req.task, 0);
            }
        }
        unsafe {
            if self.req.state == RxeQpState::QpStateDrain {
                libc::pthread_spin_lock(&mut self.state_lock);
                if self.req.state == RxeQpState::QpStateDrain && self.comp.psn == self.req.psn {
                    self.req.state = RxeQpState::QpStateDrained;
                    libc::pthread_spin_unlock(&mut self.state_lock);
                    //TODO: event_handler
                } else {
                    libc::pthread_spin_unlock(&mut self.state_lock);
                }
            }
        }
        self.do_complete_comp(wqe);

        return if psn_compare(pkt_info.psn, self.comp.psn) >= 0 {
            CompState::CompstUpdateComp
        } else {
            CompState::CompstDone
        };
    }

    #[inline]
    fn complete_wqe(
        &mut self,
        pkt_info: &mut RxePktInfo,
        wqe: &mut librxe_sys::rxe_send_wqe,
    ) -> CompState {
        if wqe.state == WqeState::WqeStatePending as u32 {
            if psn_compare(wqe.last_psn, self.comp.psn) > 0 {
                self.comp.psn = (wqe.last_psn + 1) & bth_mask::BTH_PSN_MASK;
                self.comp.opcode = -1;
            }
            if self.req.wait_psn != 0 {
                self.req.wait_psn = 0;
                // TODO rxe_run_task(&qp->req.task, 1);
            }
        }
        self.do_complete_comp(wqe);
        return CompState::CompstGetWqe;
    }

    #[inline]
    fn rxe_drain_resp_pkts(&mut self, notify: bool) {
        loop {
            let _wqe = queue_head::<librxe_sys::rxe_send_wqe>(self.sq_queue());
            if let Some(wqe) = _wqe {
                if notify {
                    unsafe {
                        (*wqe).state = ibv_wc_status::IBV_WC_WR_FLUSH_ERR;
                        self.do_complete_comp(&*wqe);
                    }
                } else {
                    advance_consumer(self.sq_queue());
                }
            } else {
                break; // if return null ptr, means no send_wqe in send queue, break the loop
            }
        }
    }

    pub fn rxe_completer(&mut self, pkt_info: *mut RxePktInfo) -> Result<(), Error> {
        let pkt_info = unsafe { &mut *pkt_info };

        if !self.valid
            || self.req.state == RxeQpState::QpStateError
            || self.req.state == RxeQpState::QpStateReset
        {
            self.rxe_drain_resp_pkts(self.valid && self.req.state == RxeQpState::QpStateError);
            return Err(Error::EAGAIN);
        }
        if self.comp.timeout != 0 {
            self.comp.timeout_retry = 1;
            self.comp.timeout = 0;
        } else {
            self.comp.timeout_retry = 0;
        }
        if self.req.need_retry != 0 {
            return Err(Error::EAGAIN);
        }
        let mut state = CompState::CompstGetAck;
        let mut wqe = librxe_sys::rxe_send_wqe::default();
        loop {
            debug!("QP #{}, State {}", self.qp_num(), state);
            match state {
                CompState::CompstGetAck => {
                    self.comp.timeout_retry = 0;
                    state = CompState::CompstGetWqe;
                }
                CompState::CompstGetWqe => {
                    state = self.get_wqe_comp(Some(pkt_info), &mut wqe);
                }
                CompState::CompstCheckPsn => {
                    state = self.check_psn_comp(pkt_info, &wqe);
                }
                CompState::CompstCheckAck => {
                    state = self.check_ack_comp(pkt_info, &mut wqe);
                }
                CompState::CompstRead => {
                    state = self.do_read(pkt_info, &mut wqe);
                }
                CompState::CompstAtomic => {
                    state = self.do_atomic(pkt_info, &mut wqe);
                }
                CompState::CompstWriteSend => {
                    state =
                        if wqe.state == WqeState::WqeStatePending && wqe.last_psn == pkt_info.psn {
                            CompState::CompstCompAck
                        } else {
                            CompState::CompstUpdateComp
                        }
                }
                CompState::CompstCompAck => state = self.complete_ack(pkt_info, &mut wqe),
                CompState::CompstCompWqe => state = self.complete_wqe(pkt_info, &mut wqe),
                CompState::CompstUpdateComp => {
                    if pkt_info.mask & rxe_hdr_mask::RXE_END_MASK != 0 {
                        self.comp.opcode = -1;
                    } else {
                        self.comp.opcode = pkt_info.opcode as i32;
                    }
                    if psn_compare(pkt_info.psn, self.comp.psn) >= 0 {
                        self.comp.psn = (pkt_info.psn + 1) & bth_mask::BTH_PSN_MASK;
                    }
                    if self.req.wait_psn != 0 {
                        self.req.wait_psn = 0;
                        // TODO rxe_run_task(&qp->req.task, 1);
                    }
                    state = CompState::CompstDone;
                }
                CompState::CompstRnrRetry => {}
                CompState::CompstError => todo!(),
                CompState::CompstExit => {
                    if self.comp.timeout_retry != 0 {
                        state = CompState::CompstErrorRetry;
                        continue;
                    }

                    /* re reset the timeout counter if
                     * (1) QP is type RC
                     * (2) the QP is alive
                     * (3) there is a packet sent by the requester that
                     *     might be acked (we still might get spurious
                     *     timeouts but try to keep them as few as possible)
                     * (4) the timeout parameter is set
                     */
                    if (self.qp_type() == ibv_qp_type::IBV_QPT_RC)
                        && (self.req.state == RxeQpState::QpStateReady)
                        && (psn_compare(self.req.psn, self.comp.psn) > 0)
                    /* && qp->qp_timeout_jiffies*/
                    { // TODO mod_timer(&qp->retrans_timer,
                         //       jiffies + qp->qp_timeout_jiffies);
                    }
                    break;
                }
                CompState::CompstErrorRetry => todo!(),
                CompState::CompstDone => return Ok(()),
            }
        }

        return Err(Error::EAGAIN);
    }
}
