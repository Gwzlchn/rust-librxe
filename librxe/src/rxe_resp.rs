use crate::{
    rxe_cq::{RxeCompletionQueue, RxeCqe},
    rxe_hdr::{
        aeth_syndrome,
        bth_mask::{self},
        RxePktInfo, RXE_ICRC_SIZE,
    },
    rxe_mr,
    rxe_net::RxeSkb,
    rxe_opcode::{
        rxe_hdr_mask::{self, RXE_GRH_MASK},
        RXE_OPCODE_INFO,
    },
    rxe_qp::{self, RxeQpState, RxeQueuePair},
    rxe_verbs::{
        psn_compare, RdatmResState, RxeMrCopyDir, RxeMrLookupType, RxeMrState, IB_DEFAULT_PKEY_FULL,
    },
};
use bytes::BytesMut;
use libc::c_int;
use librxe_sys::{advance_consumer, queue_head};
use nix::Error;
use rdma_sys::{
    ibv_access_flags, ibv_opcode, ibv_qp_type, ibv_wc_flags, ibv_wc_opcode, ibv_wc_status,
};
use std::{cell::RefCell, fmt, ptr::NonNull, rc::Rc};
use tracing::{debug, error, warn};

#[derive(PartialEq)]
enum RespState {
    RespstNone,
    RespstGetReq,
    RespstChkPsn,
    RespstChkOpSeq,
    RespstChkOpValid,
    RespstChkResource,
    RespstChkLength,
    RespstChkRkey,
    RespstExecute,
    RespstReadReply,
    RespstAtomicReply,
    RespstComplete,
    RespstAcknowledge,
    RespstCleanup,
    RespstDuplicateRequest,
    RespstErrMalformedWqe,
    RespstErrUnsupportedOpcode,
    RespstErrMisalignedAtomic,
    RespstErrPsnOutOfSeq,
    RespstErrMissingOpcodeFirst,
    RespstErrMissingOpcodeLastC,
    RespstErrMissingOpcodeLastD1e,
    RespstErrTooManyRdmaAtmReq,
    RespstErrRnr,
    RespstErrRkeyViolation,
    RespstErrInvalidateRkey,
    RespstErrLength,
    RespstErrCqOverflow,
    RespstError,
    RespstReset,
    RespstDone,
    RespstExit,
}

impl Default for RespState {
    fn default() -> Self {
        Self::RespstErrTooManyRdmaAtmReq
    }
}

impl fmt::Display for RespState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RespState::RespstNone => write!(f, "NONE"),
            RespState::RespstGetReq => write!(f, "GET REQ"),
            RespState::RespstChkPsn => write!(f, "CHK_PSN"),
            RespState::RespstChkOpSeq => write!(f, "CHK_OP_SEQ"),
            RespState::RespstChkOpValid => write!(f, "CHK_OP_VALID"),
            RespState::RespstChkResource => write!(f, "CHK_RESOURCE"),
            RespState::RespstChkLength => write!(f, "CHK_LENGTH"),
            RespState::RespstChkRkey => write!(f, "CHK_RKEY"),
            RespState::RespstExecute => write!(f, "EXECUTE"),
            RespState::RespstReadReply => write!(f, "READ_REPLY"),
            RespState::RespstAtomicReply => write!(f, "RESPST_ATOMIC_REPLY"),
            RespState::RespstComplete => write!(f, "COMPLETE"),
            RespState::RespstAcknowledge => write!(f, "ACKNOWLEDGE"),
            RespState::RespstCleanup => write!(f, "CLEANUP"),
            RespState::RespstDuplicateRequest => write!(f, "DUPLICATE_REQUEST"),
            RespState::RespstErrMalformedWqe => write!(f, "ERR_MALFORMED_WQE"),
            RespState::RespstErrUnsupportedOpcode => write!(f, "ERR_UNSUPPORTED_OPCODE"),
            RespState::RespstErrMisalignedAtomic => write!(f, "ERR_MISALIGNED_ATOMIC"),
            RespState::RespstErrPsnOutOfSeq => write!(f, "ERR_PSN_OUT_OF_SEQ"),
            RespState::RespstErrMissingOpcodeFirst => write!(f, "ERR_MISSING_OPCODE_FIRST"),
            RespState::RespstErrMissingOpcodeLastC => write!(f, "ERR_MISSING_OPCODE_LAST_C"),
            RespState::RespstErrMissingOpcodeLastD1e => {
                write!(f, "ERR_MISSING_OPCODE_LAST_D1E")
            }
            RespState::RespstErrTooManyRdmaAtmReq => write!(f, "ERR_TOO_MANY_RDMA_ATM_REQ"),
            RespState::RespstErrRnr => write!(f, "ERR_RNR"),
            RespState::RespstErrRkeyViolation => write!(f, "ERR_RKEY_VIOLATION"),
            RespState::RespstErrInvalidateRkey => write!(f, "ERR_INVALIDATE_RKEY"),
            RespState::RespstErrLength => write!(f, "ERR_LENGTH"),
            RespState::RespstErrCqOverflow => write!(f, "ERR_CQ_OVERFLOW"),
            RespState::RespstError => write!(f, "ERROR"),
            RespState::RespstReset => write!(f, "RESET"),
            RespState::RespstDone => write!(f, "DONE"),
            RespState::RespstExit => write!(f, "EXIT"),
        }
    }
}
impl RxeQueuePair {
    #[inline]
    fn get_req(&self) -> RespState {
        if self.resp.state == RxeQpState::QpStateError {
            return RespState::RespstChkResource;
        }
        return if self.resp.res.is_some() {
            RespState::RespstReadReply
        } else {
            RespState::RespstChkPsn
        };
    }

    #[inline]
    fn check_psn(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        let diff = psn_compare(pkt_info.psn, self.resp.psn);
        match self.qp_type() {
            ibv_qp_type::IBV_QPT_RC => {
                if diff > 0 {
                    if self.resp.sent_psn_nak != 0 {
                        return RespState::RespstCleanup;
                    }
                    self.resp.sent_psn_nak = 1;
                    return RespState::RespstErrPsnOutOfSeq;
                } else if diff < 0 {
                    return RespState::RespstDuplicateRequest;
                }
                if self.resp.sent_psn_nak != 0 {
                    self.resp.sent_psn_nak = 0;
                }
            }
            ibv_qp_type::IBV_QPT_UC => {
                if self.resp.drop_msg != 0 || diff != 0 {
                    if (pkt_info.mask & rxe_hdr_mask::RXE_START_MASK) != 0 {
                        self.resp.drop_msg = 0;
                        return RespState::RespstChkOpSeq;
                    }
                    self.resp.drop_msg = 1;
                    return RespState::RespstCleanup;
                }
            }
            _ => {}
        }
        return RespState::RespstChkOpSeq;
    }

    #[inline]
    fn check_op_seq(&mut self, pkt_info: &RxePktInfo) -> RespState {
        let resp_op = self.resp.opcode as ibv_opcode::Type;
        let pkt_op = pkt_info.opcode;
        match self.qp_type() {
            ibv_qp_type::IBV_QPT_RC => match resp_op {
                ibv_opcode::IBV_OPCODE_RC_SEND_FIRST | ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE => {
                    match pkt_op {
                        ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE
                        | ibv_opcode::IBV_OPCODE_RC_SEND_LAST
                        | ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE
                        | ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE => {
                            RespState::RespstChkOpValid
                        }
                        _ => RespState::RespstErrMissingOpcodeLastC,
                    }
                }
                ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_FIRST
                | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE => match pkt_op {
                    ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        RespState::RespstChkOpValid
                    }
                    _ => RespState::RespstErrMissingOpcodeLastC,
                },
                _ => match pkt_op {
                    ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE
                    | ibv_opcode::IBV_OPCODE_RC_SEND_LAST
                    | ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE
                    | ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        RespState::RespstErrMissingOpcodeFirst
                    }
                    _ => RespState::RespstChkOpValid,
                },
            },
            ibv_qp_type::IBV_QPT_UC => match resp_op {
                ibv_opcode::IBV_OPCODE_UC_SEND_FIRST | ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE => {
                    match pkt_op {
                        ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE
                        | ibv_opcode::IBV_OPCODE_UC_SEND_LAST
                        | ibv_opcode::IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE => {
                            RespState::RespstChkOpValid
                        }
                        _ => RespState::RespstErrMissingOpcodeLastD1e,
                    }
                }
                ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_FIRST
                | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE => match pkt_op {
                    ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        RespState::RespstChkOpValid
                    }
                    _ => RespState::RespstErrMissingOpcodeLastD1e,
                },
                _ => match pkt_op {
                    ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE
                    | ibv_opcode::IBV_OPCODE_UC_SEND_LAST
                    | ibv_opcode::IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        self.resp.drop_msg = 1;
                        RespState::RespstCleanup
                    }
                    _ => RespState::RespstChkOpValid,
                },
            },
            _ => RespState::RespstChkOpValid,
        }
    }

    #[inline]
    fn check_op_valid(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        match self.qp_type() {
            ibv_qp_type::IBV_QPT_RC => {
                if ((pkt_info.mask & rxe_hdr_mask::RXE_READ_MASK) != 0
                    && (self.attr_ref().qp_access_flags
                        & ibv_access_flags::IBV_ACCESS_REMOTE_READ.0)
                        == 0)
                    || ((pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK) != 0
                        && (self.attr_ref().qp_access_flags
                            & ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0)
                            == 0)
                    || ((pkt_info.mask & rxe_hdr_mask::RXE_ATOMIC_MASK) != 0
                        && (self.attr_ref().qp_access_flags
                            & ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC.0)
                            == 0)
                {
                    return RespState::RespstErrUnsupportedOpcode;
                }
            }
            ibv_qp_type::IBV_QPT_UC => {
                if (pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK) != 0
                    && (self.attr_ref().qp_access_flags
                        & ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0)
                        == 0
                {
                    self.resp.drop_msg = 1;
                    return RespState::RespstCleanup;
                }
            }
            _ => {}
        }
        RespState::RespstChkResource
    }

    /// here shared recv queue is valid
    #[inline]
    fn get_srq_wqe(&mut self) -> RespState {
        todo!()
    }

    #[inline]
    fn check_resource(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        let srq = self.srq;
        if self.resp.state == RxeQpState::QpStateError {
            if self.resp.wqe.is_some() {
                self.resp.status = ibv_wc_status::IBV_WC_WR_FLUSH_ERR;
                return RespState::RespstComplete;
            } else if srq.is_none() {
                if let Some(wqe) = queue_head::<librxe_sys::rxe_recv_wqe>(self.rq_queue()) {
                    self.resp.wqe = NonNull::new(wqe);
                    self.resp.status = ibv_wc_status::IBV_WC_WR_FLUSH_ERR;
                    return RespState::RespstComplete;
                } else {
                    return RespState::RespstExit;
                }
            } else {
                return RespState::RespstExit;
            }
        }
        if pkt_info.mask & rxe_hdr_mask::RXE_READ_OR_ATOMIC_MASK != 0 {
            if self.attr_ref().max_dest_rd_atomic > 0 {
                return RespState::RespstChkLength;
            } else {
                return RespState::RespstErrTooManyRdmaAtmReq;
            }
        }
        if pkt_info.mask & rxe_hdr_mask::RXE_RWR_MASK != 0 {
            if srq.is_some() {
                return self.get_srq_wqe();
            }
            if let Some(wqe) = queue_head::<librxe_sys::rxe_recv_wqe>(self.rq_queue()) {
                self.resp.wqe = NonNull::new(wqe);
                return RespState::RespstChkLength;
            } else {
                return RespState::RespstErrRnr;
            }
        }
        return RespState::RespstChkLength;
    }

    #[inline]
    fn check_length(&self) -> RespState {
        RespState::RespstChkRkey
    }

    #[inline]
    fn check_rkey(&mut self, pkt_info: &RxePktInfo) -> RespState {
        let mut access = 0;
        if pkt_info.mask & rxe_hdr_mask::RXE_READ_OR_WRITE_MASK != 0 {
            if pkt_info.mask & rxe_hdr_mask::RXE_RETH_MASK != 0 {
                self.resp.va = pkt_info.reth_va();
                self.resp.offset = 0;
                self.resp.rkey = pkt_info.reth_rkey();
                self.resp.resid = pkt_info.reth_len();
                self.resp.length = pkt_info.reth_len();
            }
            access = if pkt_info.mask & rxe_hdr_mask::RXE_READ_MASK != 0 {
                ibv_access_flags::IBV_ACCESS_REMOTE_READ.0
            } else {
                ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0
            };
        } else if pkt_info.mask & rxe_hdr_mask::RXE_ATOMIC_MASK != 0 {
            self.resp.va = pkt_info.atmeth_va();
            self.resp.offset = 0;
            self.resp.rkey = pkt_info.atmeth_rkey();
            self.resp.resid = std::mem::size_of::<u64>() as u32;

            access = ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC.0;
        } else {
            return RespState::RespstExecute;
        }

        if pkt_info.mask & rxe_hdr_mask::RXE_READ_OR_WRITE_MASK != 0
            && pkt_info.mask & rxe_hdr_mask::RXE_RETH_MASK != 0
            && pkt_info.reth_len() == 0
        {
            return RespState::RespstExecute;
        }
        let mtu = self.mtu;
        let va = self.resp.va;
        let rkey = self.resp.rkey;
        let resid = self.resp.resid;
        let pktlen = pkt_info.payload_size();

        let mr = if rxe_mr::rkey_is_mw(rkey) {
            // TODO check mw
            todo!()
        } else {
            // rkey is belongs to a mr
            let _mr = unsafe {
                self.pd
                    .as_ref()
                    .lookup_mr(access, rkey, RxeMrLookupType::RxeLookupRemote)
            };
            if _mr.is_none() {
                error!("no mr matches rkey {:x}", rkey);
                return RespState::RespstErrRkeyViolation;
            }
            let mr = _mr.unwrap();
            if !mr
                .as_ref()
                .borrow()
                .mr_check_range(va + self.resp.offset, resid as usize)
            {
                error!("out of memory region range {:x}", rkey);
                return RespState::RespstErrRkeyViolation;
            }
            mr
        };

        if pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK != 0 {
            if resid > mtu {
                if pktlen != mtu as usize || pkt_info.bth_pad() != 0 {
                    return RespState::RespstErrLength;
                }
            } else {
                if pktlen != resid as usize {
                    return RespState::RespstErrLength;
                }
                if pkt_info.bth_pad() != ((0 - resid as i32) as u8) & 0x3 {
                    return RespState::RespstErrLength;
                }
            }
        }
        self.resp.mr = Some(mr.clone());

        return RespState::RespstExecute;
    }

    #[inline]
    fn send_data_in(&mut self, data_addr: *mut u8, data_len: u32) -> RespState {
        if let Err(e) = unsafe {
            self.pd.as_ref().copy_data(
                ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0,
                &mut self.resp.wqe.unwrap().as_mut().dma,
                data_addr,
                data_len,
                RxeMrCopyDir::RxeToMrObj,
            )
        } {
            return if e == Error::ENOSPC {
                RespState::RespstErrLength
            } else {
                RespState::RespstErrMalformedWqe
            };
        }
        return RespState::RespstNone;
    }

    #[inline]
    fn write_data_in(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        let data_len = pkt_info.payload_size();
        if let Err(_) = self
            .resp
            .mr
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .rxe_mr_copy(
                self.resp.va + self.resp.offset as u64,
                pkt_info.payload_addr(),
                data_len,
                RxeMrCopyDir::RxeToMrObj,
            )
        {
            return RespState::RespstErrRkeyViolation;
        }
        self.resp.va += data_len as u64;
        self.resp.resid -= data_len as u32;

        return RespState::RespstNone;
    }

    fn rxe_prepare_res(
        &mut self,
        pkt_info: &mut RxePktInfo,
        rxe_type: u32,
    ) -> Rc<RefCell<rxe_qp::RespRes>> {
        let mut res = self.resp.resources.get_mut(self.resp.res_head).unwrap();
        // self.rxe_advance_resp_resource();
        self.resp.res_head += 1;
        if unsafe { self.resp.res_head == self.attr.as_ref().max_dest_rd_atomic as usize } {
            self.resp.res_head = 0;
        }

        res.resp_type = 0; // free_rd_atomic_resource
        res.resp_type = rxe_type;
        res.replay = 0;
        match rxe_type {
            rxe_hdr_mask::RXE_READ_MASK => {
                res.read.va = self.resp.va + self.resp.offset;
                res.read.va_org = self.resp.va + self.resp.offset;
                res.read.resid = self.resp.resid;
                res.read.length = self.resp.resid;
                res.read.rkey = self.resp.rkey;

                let pkts = std::cmp::max((pkt_info.reth_len() + self.mtu - 1) / self.mtu, 1);
                res.first_psn = pkt_info.psn;
                res.cur_psn = pkt_info.psn;
                res.last_psn = (pkt_info.psn + pkts - 1) & bth_mask::BTH_PSN_MASK;
                res.state = RdatmResState::RdatmResStateNew;
            }
            rxe_hdr_mask::RXE_ATOMIC_MASK => {
                res.first_psn = pkt_info.psn;
                res.last_psn = pkt_info.psn;
                res.cur_psn = pkt_info.psn;
            }
            _ => {}
        };
        return Rc::new(RefCell::new(*res));
    }

    fn prepare_ack_packet(
        &self,
        pkt_info: &mut RxePktInfo,
        ack_pkt_info: &mut RxePktInfo,
        opcode: u8,
        payload: u32,
        psn: u32,
        syndrome: u8,
    ) -> RxeSkb {
        // pad length, truncate u32 to u8
        let pad: u8 = ((0 - payload as i32) as u8) & 0x3;
        /* length from start of bth to end of icrc */
        let paylen =
            RXE_OPCODE_INFO[opcode as usize].length as u32 + payload + pad as u32 + RXE_ICRC_SIZE;

        // init iba pkt buffer
        ack_pkt_info.hdr = BytesMut::zeroed(paylen as _);
        ack_pkt_info.mask = pkt_info.mask | RXE_GRH_MASK;
        // set ack pkt_info fields
        ack_pkt_info.qp = Some(Rc::new(RefCell::new(self.clone())));
        ack_pkt_info.opcode = opcode;
        ack_pkt_info.mask |= RXE_OPCODE_INFO[opcode as usize].mask;
        ack_pkt_info.paylen = paylen as u16;
        ack_pkt_info.psn = psn;
        ack_pkt_info.port_num = 1;
        ack_pkt_info.bth_init(
            opcode,
            false,
            false,
            pad,
            IB_DEFAULT_PKEY_FULL,
            self.attr_ref().dest_qp_num,
            false,
            psn,
        );
        if ack_pkt_info.mask & rxe_hdr_mask::RXE_AETH_MASK != 0 {
            ack_pkt_info.aeth_set_syn(syndrome);
            ack_pkt_info.aeth_set_msn(self.resp.msn);
        }
        if ack_pkt_info.mask & rxe_hdr_mask::RXE_ATMACK_MASK != 0 {
            ack_pkt_info.atmack_set_orig(self.resp.atomic_orig);
        }

        RxeSkb::new(
            Rc::new(RefCell::new(ack_pkt_info.clone())),
            self,
            &self.pri_av,
        )
    }

    fn rxe_recheck_mr(&mut self, rkey: u32) -> Option<Rc<RefCell<rxe_mr::RxeMr>>> {
        if rxe_mr::rkey_is_mw(rkey) {
            // TODO
            return None;
        }
        let mr = unsafe { self.pd.as_ref().ctx.as_ref().rxe_pool_get_mr(rkey >> 8) };
        // TODO
        return None;
        //return Some(*mr.unwrap());
    }

    fn read_reply(&mut self, req_pkt: &mut RxePktInfo) -> RespState {
        todo!()
    }

    fn atomic_reply(&mut self, pkt: &mut RxePktInfo) -> RespState {
        todo!()
    }
    #[inline]
    fn send_ack(&mut self, pkt_info: &mut RxePktInfo, syndrome: u8, psn: u32) {
        let mut ack_pkt = RxePktInfo::default();
        let skb = self.prepare_ack_packet(
            pkt_info,
            &mut ack_pkt,
            ibv_opcode::IBV_OPCODE_RC_ACKNOWLEDGE,
            0,
            psn,
            syndrome,
        );
        skb.rxe_xmit_packet();
    }

    #[inline]
    fn acknowledge(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        if self.qp_type() != ibv_qp_type::IBV_QPT_RC {
            return RespState::RespstCleanup;
        }
        if self.resp.aeth_syndrome != aeth_syndrome::AETH_ACK_UNLIMITED {
            self.send_ack(pkt_info, self.resp.aeth_syndrome, pkt_info.psn);
        } else if pkt_info.mask & rxe_hdr_mask::RXE_ATOMIC_MASK != 0 {
            todo!() // TODO send_atomic_ack
        } else if pkt_info.bth_ack() {
            self.send_ack(pkt_info, aeth_syndrome::AETH_ACK_UNLIMITED, pkt_info.psn);
        }
        return RespState::RespstCleanup;
    }

    #[inline]
    fn cleanup(&mut self) -> RespState {
        if self.resp.mr.is_some() {
            self.resp.mr = None;
        }
        return RespState::RespstDone;
    }
    #[inline]
    fn rxe_drain_req_pkts(&mut self, notify: bool) {
        let q = self.rq_queue();
        if notify {
            return;
        }
        while self.srq.is_none()
            && !q.is_null()
            && queue_head::<librxe_sys::rxe_recv_wqe>(q).is_some()
        {
            advance_consumer(q);
        }
    }
    fn execute(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        if pkt_info.mask & rxe_hdr_mask::RXE_SEND_MASK != 0 {
            // TODO IB_QPT_UD type
            let err = self.send_data_in(pkt_info.payload_addr(), pkt_info.payload_size() as u32);
            if err != RespState::RespstNone {
                return err;
            }
        } else if pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK != 0 {
            let err = self.write_data_in(pkt_info);
            if err != RespState::RespstNone {
                return err;
            }
        } else if pkt_info.mask & rxe_hdr_mask::RXE_READ_MASK != 0 {
            self.resp.msn += 1;
            return RespState::RespstReadReply;
        } else if pkt_info.mask & rxe_hdr_mask::RXE_ATOMIC_MASK != 0 {
            return RespState::RespstAtomicReply;
        } else {
            warn!("execute funtion should not reach this branch");
        }
        if pkt_info.mask & rxe_hdr_mask::RXE_IETH_MASK != 0 {
            todo!() // TODO invalidate_rkey
        }
        if pkt_info.mask & rxe_hdr_mask::RXE_END_MASK != 0 {
            /* We successfully processed this new request. */
            self.resp.msn += 1;
        }
        /* next expected psn, read handles this separately */
        self.resp.psn = (pkt_info.psn + 1) & bth_mask::BTH_PSN_MASK;
        self.resp.ack_psn = self.resp.psn;
        self.resp.opcode = pkt_info.opcode as c_int;
        self.resp.status = ibv_wc_status::IBV_WC_SUCCESS;

        if pkt_info.mask & rxe_hdr_mask::RXE_COMP_MASK != 0 {
            RespState::RespstComplete
        } else if self.qp_type() == ibv_qp_type::IBV_QPT_RC {
            RespState::RespstAcknowledge
        } else {
            RespState::RespstCleanup
        }
    }

    /* Process a class A or C. Both are treated the same in this implementation. */
    #[inline]
    fn do_class_ac_error(&mut self, syndrome: u8, status: ibv_wc_status::Type) {
        self.resp.aeth_syndrome = syndrome;
        self.resp.status = status;
        /* indicate that we should go through the ERROR state */
        self.resp.goto_error = 1;
    }

    // avoid use goto: lable
    fn do_complete_finish(&mut self) -> RespState {
        if self.resp.state == RxeQpState::QpStateError {
            return RespState::RespstChkResource;
        } else if self.qp_type() == ibv_qp_type::IBV_QPT_RC {
            return RespState::RespstAcknowledge;
        } else {
            return RespState::RespstCleanup;
        }
        // ignore the unlikely(!pkt) branch
    }
    fn do_complete(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        let wqe = if self.resp.wqe.is_none() {
            return self.do_complete_finish();
        } else {
            self.resp.wqe.unwrap()
        };
        let mut cqe = RxeCqe::default();
        cqe.wc.status = self.resp.status;
        cqe.wc.qp_num = self.qp_num();
        cqe.wc.wr_id = unsafe { wqe.as_ref().wr_id };
        if cqe.wc.status == ibv_wc_status::IBV_WC_SUCCESS {
            cqe.wc.opcode = if (pkt_info.mask & rxe_hdr_mask::RXE_IMMDT_MASK != 0)
                && (pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK != 0)
            {
                ibv_wc_opcode::IBV_WC_RECV_RDMA_WITH_IMM
            } else {
                ibv_wc_opcode::IBV_WC_RECV
            };
            cqe.wc.byte_len = if (pkt_info.mask & rxe_hdr_mask::RXE_IMMDT_MASK != 0)
                && (pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK != 0)
            {
                self.resp.length
            } else {
                unsafe { wqe.as_ref().dma.length - wqe.as_ref().dma.resid }
            };
            cqe.wc.wc_flags = ibv_wc_flags::IBV_WC_GRH.0;

            if pkt_info.mask & rxe_hdr_mask::RXE_IMMDT_MASK != 0 {
                cqe.wc.wc_flags |= ibv_wc_flags::IBV_WC_WITH_IMM.0;
                cqe.wc.imm_data_invalidated_rkey_union.imm_data = pkt_info.immdt_imm();
            }

            if pkt_info.mask & rxe_hdr_mask::RXE_IETH_MASK != 0 {
                cqe.wc.wc_flags |= ibv_wc_flags::IBV_WC_WITH_INV.0;
                cqe.wc.imm_data_invalidated_rkey_union.invalidated_rkey = pkt_info.ieth_rkey();
            }

            if pkt_info.mask & rxe_hdr_mask::RXE_DETH_MASK != 0 {
                cqe.wc.src_qp = pkt_info.deth_sqp();
            }
            // No port_num field in ibv_wc
        }
        if self.srq.is_none() {
            librxe_sys::advance_consumer(self.rq_queue());
        }
        self.resp.wqe = None;
        if let Err(_) =
            unsafe { RxeCompletionQueue::cq_post(&mut self.rcq, &mut cqe, pkt_info.bth_se()) }
        {
            return RespState::RespstErrCqOverflow;
        }
        self.do_complete_finish()
    }

    pub fn rxe_responder(&mut self, pkt_info: *mut RxePktInfo) -> Result<(), Error> {
        let pkt_info = unsafe { &mut *pkt_info };
        self.resp.aeth_syndrome = aeth_syndrome::AETH_ACK_UNLIMITED;
        if !self.valid {
            return Err(Error::EINVAL);
        }
        let mut state = if self.resp.state == RxeQpState::QpStateReset {
            RespState::RespstReset
        } else {
            RespState::RespstGetReq
        };
        loop {
            debug!("QP #{}, State {}", self.qp_num(), state);
            match state {
                RespState::RespstGetReq => state = self.get_req(),
                RespState::RespstChkPsn => state = self.check_psn(pkt_info),
                RespState::RespstChkOpSeq => state = self.check_op_seq(pkt_info),
                RespState::RespstChkOpValid => state = self.check_op_valid(pkt_info),
                RespState::RespstChkResource => state = self.check_resource(pkt_info),
                RespState::RespstChkLength => state = self.check_length(),
                RespState::RespstChkRkey => state = self.check_rkey(pkt_info),
                RespState::RespstExecute => state = self.execute(pkt_info),
                RespState::RespstComplete => state = self.do_complete(pkt_info),
                RespState::RespstReadReply => state = self.read_reply(pkt_info),
                RespState::RespstAtomicReply => state = self.atomic_reply(pkt_info),
                RespState::RespstAcknowledge => state = self.acknowledge(pkt_info),
                RespState::RespstCleanup => state = self.cleanup(),
                RespState::RespstDuplicateRequest => todo!(),
                RespState::RespstErrPsnOutOfSeq => {
                    self.send_ack(
                        pkt_info,
                        aeth_syndrome::AETH_NAK_PSN_SEQ_ERROR,
                        self.resp.psn,
                    );
                    state = RespState::RespstCleanup;
                }
                RespState::RespstErrMalformedWqe => {
                    self.do_class_ac_error(
                        aeth_syndrome::AETH_NAK_REM_OP_ERR,
                        ibv_wc_status::IBV_WC_LOC_QP_OP_ERR,
                    );
                    state = RespState::RespstComplete;
                }
                RespState::RespstErrTooManyRdmaAtmReq
                | RespState::RespstErrMissingOpcodeFirst
                | RespState::RespstErrMissingOpcodeLastC
                | RespState::RespstErrUnsupportedOpcode
                | RespState::RespstErrMisalignedAtomic => {
                    self.do_class_ac_error(
                        aeth_syndrome::AETH_NAK_INVALID_REQ,
                        ibv_wc_status::IBV_WC_REM_INV_REQ_ERR,
                    );
                    state = RespState::RespstComplete;
                },
                RespState::RespstErrMissingOpcodeLastD1e => todo!(),
                RespState::RespstErrRnr => todo!(),
                RespState::RespstErrRkeyViolation => {
                    if self.qp_type() == ibv_qp_type::IBV_QPT_RC {
                        self.do_class_ac_error(
                            aeth_syndrome::AETH_NAK_REM_ACC_ERR,
                            ibv_wc_status::IBV_WC_REM_ACCESS_ERR,
                        );
                        state = RespState::RespstComplete;
                    };
                    // TODO SRQ/UD
                }
                RespState::RespstErrInvalidateRkey => todo!(),
                RespState::RespstErrLength => {
                    if self.qp_type() == ibv_qp_type::IBV_QPT_RC {
                        self.do_class_ac_error(
                            aeth_syndrome::AETH_NAK_INVALID_REQ,
                            ibv_wc_status::IBV_WC_REM_INV_REQ_ERR,
                        );
                        state = RespState::RespstComplete;
                    };
                    // TODO SRQ/UD
                }
                RespState::RespstErrCqOverflow => todo!(),
                RespState::RespstError => {
                    self.resp.goto_error = 0;
                    warn!("qp #{} moved to error state", self.qp_num());
                    self.set_error_state();
                    return Err(Error::EAGAIN);
                }
                RespState::RespstReset => {
                    self.resp.wqe = None;
                    self.rxe_drain_req_pkts(false);
                    return Err(Error::EAGAIN);
                }
                RespState::RespstDone => {
                    if self.resp.goto_error != 0 {
                        state = RespState::RespstError;
                    } else {
                        return Ok(());
                    }
                }
                RespState::RespstExit => {
                    if self.resp.goto_error != 0 {
                        state = RespState::RespstError;
                    } else {
                        return Err(Error::EAGAIN);
                    }
                }

                RespState::RespstNone => {
                    // this branch should not reach
                    panic!("qp #{} moved to none state", self.qp_num());
                }
            }
        }
    }
}
