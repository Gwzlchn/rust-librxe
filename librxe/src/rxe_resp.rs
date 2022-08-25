use crate::{
    rxe_cq::{RxeCompletionQueue, RxeCqe},
    rxe_hdr::{aeth_syndrome, bth_mask, RxePktInfo, RXE_ICRC_SIZE},
    rxe_mr,
    rxe_net::RxeSkb,
    rxe_opcode::{
        rxe_hdr_mask::{self, RXE_GRH_MASK},
        RXE_OPCODE_INFO,
    },
    rxe_qp::{RxeQpState, RxeQueuePair},
    rxe_verbs::{psn_compare, RxeMrCopyDir, RxeMrLookupType, IB_DEFAULT_PKEY_FULL},
};
use bytes::BytesMut;
use libc::c_int;
use librxe_sys::{advance_consumer, qp_num, qp_type, queue_head, rxe_qp_state};
use nix::Error;
use rdma_sys::{
    ibv_access_flags, ibv_opcode, ibv_qp_type, ibv_wc_flags, ibv_wc_opcode, ibv_wc_status,
};
use std::{cell::RefCell, fmt, ptr::NonNull, rc::Rc};
use tracing::{debug, error, warn};

#[derive(PartialEq)]
enum RespState {
    RESPST_NONE,
    RESPST_GET_REQ,
    RESPST_CHK_PSN,
    RESPST_CHK_OP_SEQ,
    RESPST_CHK_OP_VALID,
    RESPST_CHK_RESOURCE,
    RESPST_CHK_LENGTH,
    RESPST_CHK_RKEY,
    RESPST_EXECUTE,
    RESPST_READ_REPLY,
    RESPST_COMPLETE,
    RESPST_ACKNOWLEDGE,
    RESPST_CLEANUP,
    RESPST_DUPLICATE_REQUEST,
    RESPST_ERR_MALFORMED_WQE,
    RESPST_ERR_UNSUPPORTED_OPCODE,
    RESPST_ERR_MISALIGNED_ATOMIC,
    RESPST_ERR_PSN_OUT_OF_SEQ,
    RESPST_ERR_MISSING_OPCODE_FIRST,
    RESPST_ERR_MISSING_OPCODE_LAST_C,
    RESPST_ERR_MISSING_OPCODE_LAST_D1E,
    RESPST_ERR_TOO_MANY_RDMA_ATM_REQ,
    RESPST_ERR_RNR,
    RESPST_ERR_RKEY_VIOLATION,
    RESPST_ERR_INVALIDATE_RKEY,
    RESPST_ERR_LENGTH,
    RESPST_ERR_CQ_OVERFLOW,
    RESPST_ERROR,
    RESPST_RESET,
    RESPST_DONE,
    RESPST_EXIT,
}

impl fmt::Display for RespState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RespState::RESPST_NONE => write!(f, "NONE"),
            RespState::RESPST_GET_REQ => write!(f, "GET REQ"),
            RespState::RESPST_CHK_PSN => write!(f, "CHK_PSN"),
            RespState::RESPST_CHK_OP_SEQ => write!(f, "CHK_OP_SEQ"),
            RespState::RESPST_CHK_OP_VALID => write!(f, "CHK_OP_VALID"),
            RespState::RESPST_CHK_RESOURCE => write!(f, "CHK_RESOURCE"),
            RespState::RESPST_CHK_LENGTH => write!(f, "CHK_LENGTH"),
            RespState::RESPST_CHK_RKEY => write!(f, "CHK_RKEY"),
            RespState::RESPST_EXECUTE => write!(f, "EXECUTE"),
            RespState::RESPST_READ_REPLY => write!(f, "READ_REPLY"),
            RespState::RESPST_COMPLETE => write!(f, "COMPLETE"),
            RespState::RESPST_ACKNOWLEDGE => write!(f, "ACKNOWLEDGE"),
            RespState::RESPST_CLEANUP => write!(f, "CLEANUP"),
            RespState::RESPST_DUPLICATE_REQUEST => write!(f, "DUPLICATE_REQUEST"),
            RespState::RESPST_ERR_MALFORMED_WQE => write!(f, "ERR_MALFORMED_WQE"),
            RespState::RESPST_ERR_UNSUPPORTED_OPCODE => write!(f, "ERR_UNSUPPORTED_OPCODE"),
            RespState::RESPST_ERR_MISALIGNED_ATOMIC => write!(f, "ERR_MISALIGNED_ATOMIC"),
            RespState::RESPST_ERR_PSN_OUT_OF_SEQ => write!(f, "ERR_PSN_OUT_OF_SEQ"),
            RespState::RESPST_ERR_MISSING_OPCODE_FIRST => write!(f, "ERR_MISSING_OPCODE_FIRST"),
            RespState::RESPST_ERR_MISSING_OPCODE_LAST_C => write!(f, "ERR_MISSING_OPCODE_LAST_C"),
            RespState::RESPST_ERR_MISSING_OPCODE_LAST_D1E => {
                write!(f, "ERR_MISSING_OPCODE_LAST_D1E")
            }
            RespState::RESPST_ERR_TOO_MANY_RDMA_ATM_REQ => write!(f, "ERR_TOO_MANY_RDMA_ATM_REQ"),
            RespState::RESPST_ERR_RNR => write!(f, "ERR_RNR"),
            RespState::RESPST_ERR_RKEY_VIOLATION => write!(f, "ERR_RKEY_VIOLATION"),
            RespState::RESPST_ERR_INVALIDATE_RKEY => write!(f, "ERR_INVALIDATE_RKEY"),
            RespState::RESPST_ERR_LENGTH => write!(f, "ERR_LENGTH"),
            RespState::RESPST_ERR_CQ_OVERFLOW => write!(f, "ERR_CQ_OVERFLOW"),
            RespState::RESPST_ERROR => write!(f, "ERROR"),
            RespState::RESPST_RESET => write!(f, "RESET"),
            RespState::RESPST_DONE => write!(f, "DONE"),
            RespState::RESPST_EXIT => write!(f, "EXIT"),
        }
    }
}
impl RxeQueuePair {
    #[inline]
    fn get_req(&self) -> RespState {
        if self.resp.state == RxeQpState::QP_STATE_ERROR {
            return RespState::RESPST_CHK_RESOURCE;
        }
        return if self.resp.res.is_some() {
            RespState::RESPST_READ_REPLY
        } else {
            RespState::RESPST_CHK_PSN
        };
    }

    #[inline]
    fn check_psn(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        let diff = psn_compare(pkt_info.psn, self.resp.psn);
        match self.qp_type() {
            ibv_qp_type::IBV_QPT_RC => {
                if diff > 0 {
                    if self.resp.sent_psn_nak != 0 {
                        return RespState::RESPST_CLEANUP;
                    }
                    self.resp.sent_psn_nak = 1;
                    return RespState::RESPST_ERR_PSN_OUT_OF_SEQ;
                } else if diff < 0 {
                    return RespState::RESPST_DUPLICATE_REQUEST;
                }
                if self.resp.sent_psn_nak != 0 {
                    self.resp.sent_psn_nak = 0;
                }
            }
            ibv_qp_type::IBV_QPT_UC => {
                if self.resp.drop_msg != 0 || diff != 0 {
                    if (pkt_info.mask & rxe_hdr_mask::RXE_START_MASK) != 0 {
                        self.resp.drop_msg = 0;
                        return RespState::RESPST_CHK_OP_SEQ;
                    }
                    self.resp.drop_msg = 1;
                    return RespState::RESPST_CLEANUP;
                }
            }
            _ => {}
        }
        return RespState::RESPST_CHK_OP_SEQ;
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
                            RespState::RESPST_CHK_OP_VALID
                        }
                        _ => RespState::RESPST_ERR_MISSING_OPCODE_LAST_C,
                    }
                }
                ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_FIRST
                | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE => match pkt_op {
                    ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        RespState::RESPST_CHK_OP_VALID
                    }
                    _ => RespState::RESPST_ERR_MISSING_OPCODE_LAST_C,
                },
                _ => match pkt_op {
                    ibv_opcode::IBV_OPCODE_RC_SEND_MIDDLE
                    | ibv_opcode::IBV_OPCODE_RC_SEND_LAST
                    | ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE
                    | ibv_opcode::IBV_OPCODE_RC_SEND_LAST_WITH_INVALIDATE
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        RespState::RESPST_ERR_MISSING_OPCODE_FIRST
                    }
                    _ => RespState::RESPST_CHK_OP_VALID,
                },
            },
            ibv_qp_type::IBV_QPT_UC => match resp_op {
                ibv_opcode::IBV_OPCODE_UC_SEND_FIRST | ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE => {
                    match pkt_op {
                        ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE
                        | ibv_opcode::IBV_OPCODE_UC_SEND_LAST
                        | ibv_opcode::IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE => {
                            RespState::RESPST_CHK_OP_VALID
                        }
                        _ => RespState::RESPST_ERR_MISSING_OPCODE_LAST_D1E,
                    }
                }
                ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_FIRST
                | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE => match pkt_op {
                    ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        RespState::RESPST_CHK_OP_VALID
                    }
                    _ => RespState::RESPST_ERR_MISSING_OPCODE_LAST_D1E,
                },
                _ => match pkt_op {
                    ibv_opcode::IBV_OPCODE_UC_SEND_MIDDLE
                    | ibv_opcode::IBV_OPCODE_UC_SEND_LAST
                    | ibv_opcode::IBV_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_MIDDLE
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST
                    | ibv_opcode::IBV_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE => {
                        self.resp.drop_msg = 1;
                        RespState::RESPST_CLEANUP
                    }
                    _ => RespState::RESPST_CHK_OP_VALID,
                },
            },
            _ => RespState::RESPST_CHK_OP_VALID,
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
                    return RespState::RESPST_ERR_UNSUPPORTED_OPCODE;
                }
            }
            ibv_qp_type::IBV_QPT_UC => {
                if (pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK) != 0
                    && (self.attr_ref().qp_access_flags
                        & ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0)
                        == 0
                {
                    self.resp.drop_msg = 1;
                    return RespState::RESPST_CLEANUP;
                }
            }
            _ => {}
        }
        RespState::RESPST_CHK_RESOURCE
    }

    /// here shared recv queue is valid
    #[inline]
    fn get_srq_wqe(&mut self) -> RespState {
        todo!()
    }

    #[inline]
    fn check_resource(&mut self, pkt_info: &mut RxePktInfo) -> RespState {
        let srq = self.srq;
        if self.resp.state == RxeQpState::QP_STATE_ERROR {
            if self.resp.wqe.is_some() {
                self.resp.status = ibv_wc_status::IBV_WC_WR_FLUSH_ERR;
                return RespState::RESPST_COMPLETE;
            } else if srq.is_none() {
                if let Some(wqe) = queue_head::<librxe_sys::rxe_recv_wqe>(self.rq_queue()) {
                    self.resp.wqe = NonNull::new(wqe);
                    self.resp.status = ibv_wc_status::IBV_WC_WR_FLUSH_ERR;
                    return RespState::RESPST_COMPLETE;
                } else {
                    return RespState::RESPST_EXIT;
                }
            } else {
                return RespState::RESPST_EXIT;
            }
        }
        if pkt_info.mask & rxe_hdr_mask::RXE_READ_OR_ATOMIC_MASK != 0 {
            if self.attr_ref().max_dest_rd_atomic > 0 {
                return RespState::RESPST_CHK_LENGTH;
            } else {
                return RespState::RESPST_ERR_TOO_MANY_RDMA_ATM_REQ;
            }
        }
        if pkt_info.mask & rxe_hdr_mask::RXE_RWR_MASK != 0 {
            if srq.is_some() {
                return self.get_srq_wqe();
            }
            if let Some(wqe) = queue_head::<librxe_sys::rxe_recv_wqe>(self.rq_queue()) {
                self.resp.wqe = NonNull::new(wqe);
                return RespState::RESPST_CHK_LENGTH;
            } else {
                return RespState::RESPST_ERR_RNR;
            }
        }
        return RespState::RESPST_CHK_LENGTH;
    }

    #[inline]
    fn check_length(&self) -> RespState {
        RespState::RESPST_CHK_RKEY
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
            return RespState::RESPST_EXECUTE;
        }

        if pkt_info.mask & rxe_hdr_mask::RXE_READ_OR_WRITE_MASK != 0
            && pkt_info.mask & rxe_hdr_mask::RXE_RETH_MASK != 0
            && pkt_info.reth_len() == 0
        {
            return RespState::RESPST_EXECUTE;
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
                return RespState::RESPST_ERR_RKEY_VIOLATION;
            }
            let mr = _mr.unwrap();
            if !mr
                .as_ref()
                .borrow()
                .mr_check_range(va + self.resp.offset, resid as usize)
            {
                error!("out of memory region range {:x}", rkey);
                return RespState::RESPST_ERR_RKEY_VIOLATION;
            }
            mr
        };

        if pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK != 0 {
            if resid > mtu {
                if pktlen != mtu as usize || pkt_info.bth_pad() != 0 {
                    return RespState::RESPST_ERR_LENGTH;
                }
            } else {
                if pktlen != resid as usize {
                    return RespState::RESPST_ERR_LENGTH;
                }
                if pkt_info.bth_pad() != ((0 - resid as i32) as u8) & 0x3 {
                    return RespState::RESPST_ERR_LENGTH;
                }
            }
        }
        self.resp.mr = Some(mr.clone());

        return RespState::RESPST_EXECUTE;
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
                RespState::RESPST_ERR_LENGTH
            } else {
                RespState::RESPST_ERR_MALFORMED_WQE
            };
        }
        return RespState::RESPST_NONE;
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
            return RespState::RESPST_ERR_RKEY_VIOLATION;
        }
        self.resp.va = self.resp.va + data_len as u64;
        self.resp.resid = self.resp.resid - data_len as u32;

        return RespState::RESPST_NONE;
    }

    #[inline]
    fn process_atomic(&mut self, pkt_info: &RxePktInfo) -> RespState {
        // TODO
        return RespState::RESPST_NONE;
    }

    #[inline]
    fn read_reply(&mut self, pkt_info: &RxePktInfo) -> RespState {
        todo!()
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
            return RespState::RESPST_CLEANUP;
        }
        if self.resp.aeth_syndrome != aeth_syndrome::AETH_ACK_UNLIMITED {
            self.send_ack(pkt_info, self.resp.aeth_syndrome, pkt_info.psn);
        } else if pkt_info.mask & rxe_hdr_mask::RXE_ATOMIC_MASK != 0 {
            todo!() // TODO send_atomic_ack
        } else if pkt_info.bth_ack() {
            self.send_ack(pkt_info, aeth_syndrome::AETH_ACK_UNLIMITED, pkt_info.psn);
        }
        return RespState::RESPST_CLEANUP;
    }

    #[inline]
    fn cleanup(&mut self) -> RespState {
        if self.resp.mr.is_some() {
            self.resp.mr = None;
        }
        return RespState::RESPST_DONE;
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
            if err != RespState::RESPST_NONE {
                return err;
            }
        } else if pkt_info.mask & rxe_hdr_mask::RXE_WRITE_MASK != 0 {
            let err = self.write_data_in(pkt_info);
            if err != RespState::RESPST_NONE {
                return err;
            }
        } else if pkt_info.mask & rxe_hdr_mask::RXE_READ_MASK != 0 {
            self.resp.msn += 1;
        } else if pkt_info.mask & rxe_hdr_mask::RXE_ATOMIC_MASK != 0 {
            let err = self.process_atomic(pkt_info);
            if err != RespState::RESPST_NONE {
                return err;
            }
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
            RespState::RESPST_COMPLETE
        } else if self.qp_type() == ibv_qp_type::IBV_QPT_RC {
            RespState::RESPST_ACKNOWLEDGE
        } else {
            RespState::RESPST_CLEANUP
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
        if self.resp.state == RxeQpState::QP_STATE_ERROR {
            return RespState::RESPST_CHK_RESOURCE;
        } else if self.qp_type() == ibv_qp_type::IBV_QPT_RC {
            return RespState::RESPST_ACKNOWLEDGE;
        } else {
            return RespState::RESPST_CLEANUP;
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
            return RespState::RESPST_ERR_CQ_OVERFLOW;
        }
        self.do_complete_finish()
    }

    pub fn rxe_responder(&mut self, pkt_info: *mut RxePktInfo) -> Result<(), Error> {
        let pkt_info = unsafe { &mut *pkt_info };
        self.resp.aeth_syndrome = aeth_syndrome::AETH_ACK_UNLIMITED;
        if !self.valid {
            return Err(Error::EINVAL);
        }
        let mut state = if self.resp.state == RxeQpState::QP_STATE_RESET {
            RespState::RESPST_RESET
        } else {
            RespState::RESPST_GET_REQ
        };
        loop {
            debug!("QP #{}, State {}", self.qp_num(), state);
            match state {
                RespState::RESPST_GET_REQ => state = self.get_req(),
                RespState::RESPST_CHK_PSN => state = self.check_psn(pkt_info),
                RespState::RESPST_CHK_OP_SEQ => state = self.check_op_seq(pkt_info),
                RespState::RESPST_CHK_OP_VALID => state = self.check_op_valid(pkt_info),
                RespState::RESPST_CHK_RESOURCE => state = self.check_resource(pkt_info),
                RespState::RESPST_CHK_LENGTH => state = self.check_length(),
                RespState::RESPST_CHK_RKEY => state = self.check_rkey(pkt_info),
                RespState::RESPST_EXECUTE => state = self.execute(pkt_info),
                RespState::RESPST_COMPLETE => state = self.do_complete(pkt_info),
                RespState::RESPST_READ_REPLY => state = self.read_reply(pkt_info),
                RespState::RESPST_ACKNOWLEDGE => state = self.acknowledge(pkt_info),
                RespState::RESPST_CLEANUP => state = self.cleanup(),
                RespState::RESPST_DUPLICATE_REQUEST => todo!(),
                RespState::RESPST_ERR_MALFORMED_WQE => todo!(),
                RespState::RESPST_ERR_UNSUPPORTED_OPCODE => todo!(),
                RespState::RESPST_ERR_MISALIGNED_ATOMIC => todo!(),
                RespState::RESPST_ERR_PSN_OUT_OF_SEQ => todo!(),
                RespState::RESPST_ERR_MISSING_OPCODE_FIRST => todo!(),
                RespState::RESPST_ERR_MISSING_OPCODE_LAST_C => todo!(),
                RespState::RESPST_ERR_MISSING_OPCODE_LAST_D1E => todo!(),
                RespState::RESPST_ERR_TOO_MANY_RDMA_ATM_REQ => todo!(),
                RespState::RESPST_ERR_RNR => todo!(),
                RespState::RESPST_ERR_RKEY_VIOLATION => todo!(),
                RespState::RESPST_ERR_INVALIDATE_RKEY => todo!(),
                RespState::RESPST_ERR_LENGTH => todo!(),
                RespState::RESPST_ERR_CQ_OVERFLOW => todo!(),
                RespState::RESPST_ERROR => {
                    self.resp.goto_error = 0;
                    warn!("qp #{} moved to error state", self.qp_num());
                    self.set_error_state();
                    return Err(Error::EAGAIN);
                }
                RespState::RESPST_RESET => {
                    self.resp.wqe = None;
                    self.rxe_drain_req_pkts(false);
                    return Err(Error::EAGAIN);
                }
                RespState::RESPST_DONE => {
                    if self.resp.goto_error != 0 {
                        state = RespState::RESPST_ERROR;
                    } else {
                        return Ok(());
                    }
                }
                RespState::RESPST_EXIT => {
                    if self.resp.goto_error != 0 {
                        state = RespState::RESPST_ERROR;
                    } else {
                        return Err(Error::EAGAIN);
                    }
                }

                RespState::RESPST_NONE => {
                    // this branch should not reach
                    panic!("qp #{} moved to none state", self.qp_num());
                }
            }
        }
    }
}
