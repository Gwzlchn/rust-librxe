use crate::rxe_hdr::bth_mask;
use crate::rxe_pd::RxePd;
use crate::{rxe_av::rxe_init_av, rxe_mr::RxeMr};
use crate::{rxe_post_recv, rxe_post_send, rxe_verbs};
use async_rdma::queue_pair::{QueuePairEndpoint, QueuePairInitAttr};
use derivative::Derivative;
use libc::c_int;
use nix::Error;
use rdma_sys::{
    ibv_access_flags, ibv_modify_qp, ibv_qp, ibv_qp_attr, ibv_qp_attr_mask, ibv_qp_state,
    ibv_send_wr, ibv_sge,
};
use std::ptr::NonNull;
use tracing::{debug, warn};

pub struct RxeRq {
    pub max_wr: c_int,
    pub max_sge: c_int,
    pub producer_lock: libc::pthread_spinlock_t,
    pub consumer_lock: libc::pthread_spinlock_t,
}

pub struct RxeSrq {
    pub ibv_srq: rdma_sys::ibv_srq,
    pub rq: RxeRq,
    pub srq_num: u32,
    pub limit: c_int,
    pub error: c_int,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RxeQpState {
    #[default]
    QP_STATE_RESET,
    QP_STATE_INIT,
    QP_STATE_READY,
    QP_STATE_DRAIN,   /* req only */
    QP_STATE_DRAINED, /* req only */
    QP_STATE_ERROR,
}
#[repr(C)]
#[derive(Clone, Copy, Derivative)]
#[derivative(Default)]
pub struct RxeReqInfo {
    pub state: RxeQpState,
    pub wqe_index: u32,
    pub psn: u32,
    #[derivative(Default(value = "-1"))]
    pub opcode: c_int,
    pub rd_atomic: c_int, // as atomic_int
    pub wait_fence: c_int,
    pub need_rd_atomic: c_int,
    pub wait_psn: c_int,
    pub need_retry: c_int,
    pub noack_pkts: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Derivative)]
#[derivative(Default)]
pub struct RxeCompInfo {
    pub psn: u32,
    #[derivative(Default(value = "-1"))]
    pub opcode: c_int,
    pub timeout: c_int,
    pub timeout_retry: c_int,
    pub started_retry: c_int,
    pub retry_cnt: u32,
    pub rnr_retry: u32,
}

#[repr(C)]
#[derive(Clone, Derivative)]
#[derivative(Default)]
pub struct RxeRespInfo {
    pub state: RxeQpState,
    pub msn: u32,
    pub psn: u32,
    pub ack_psn: u32,
    pub opcode: c_int,
    pub drop_msg: c_int,
    pub sent_psn_nak: c_int,
    pub status: rdma_sys::ibv_wc_status::Type,
    pub aeth_syndrome: u8,
    // receive only
    #[derivative(Default(value = "NonNull::dangling()"))]
    pub wqe: NonNull<librxe_sys::rxe_recv_wqe>,
    // RDMA read/ atomic only
    pub va: u64,
    pub offset: u64,
    pub resid: u32,
    pub rkey: u32,
    pub length: u32,
    pub atomic_orig: u64,
    // SRQ only
    //pub srq_wqe: rxe_resp_srq_wqe,
}

#[derive(Clone)]
pub struct RxeQueuePair {
    pub pd: NonNull<RxePd>,
    // This variable should be deprecated in the future
    pub inner_qp: NonNull<librxe_sys::rxe_qp>,
    pub qpn: u32,
    pub attr: NonNull<rdma_sys::ibv_qp_attr>,

    pub valid: bool,
    pub srq: NonNull<librxe_sys::rxe_srq>,
    pub scq: NonNull<librxe_sys::rxe_cq>,
    pub rcq: NonNull<librxe_sys::rxe_cq>,

    pub src_port: u16,

    pub pri_av: NonNull<librxe_sys::rxe_av>,
    pub alt_av: NonNull<librxe_sys::rxe_av>,

    pub mtu: u32,
    pub req: RxeReqInfo,
    pub comp: RxeCompInfo,
    pub resp: RxeRespInfo,
    /* guard requester and completer */
    // pub state_lock: spin::mutex::Mutex<u32>,
}

impl RxeQueuePair {
    /// get `ibv_qp` pointer
    pub fn as_ptr(&self) -> *mut ibv_qp {
        unsafe { &mut (*self.inner_qp.as_ptr()).vqp.qp_union.qp as *mut ibv_qp }
    }

    /// get queue pair endpoint
    pub fn endpoint(&self) -> QueuePairEndpoint {
        QueuePairEndpoint {
            qp_num: self.qpn,
            lid: unsafe { self.pd.as_ref().ctx.as_ref().get_lid() },
            gid: unsafe { self.pd.as_ref().ctx.as_ref().get_gid() },
        }
    }

    pub fn create_qp(
        pd: NonNull<RxePd>,
        qp_init_attr: &mut QueuePairInitAttr,
    ) -> Result<RxeQueuePair, Error> {
        let pd_ptr = unsafe { pd.as_ref().as_ptr() };
        let ibv_qp = NonNull::new(unsafe {
            rdma_sys::ibv_create_qp(pd_ptr, &mut qp_init_attr.qp_init_attr_inner)
        })
        .expect("create qp failed");
        let rqp = librxe_sys::to_rqp(ibv_qp.as_ptr()).unwrap();
        let rqp_ptr = NonNull::new(rqp).unwrap();
        let qpn = librxe_sys::qp_num(rqp);

        let mut attr = unsafe {
            let mut attr = std::mem::zeroed::<rdma_sys::ibv_qp_attr>();
            rdma_sys::ibv_query_qp(
                ibv_qp.as_ptr(),
                &mut attr,
                rdma_sys::ibv_qp_attr_mask::IBV_QP_STATE.0 as _,
                &mut qp_init_attr.qp_init_attr_inner,
            );
            attr
        };
        let attr_ptr = NonNull::new(&mut attr as *mut rdma_sys::ibv_qp_attr).unwrap();
        let src_port = ((fxhash::hash32(&qpn) as u16) & 0x3FFF) + rxe_verbs::RXE_ROCE_V2_SPORT;
        let mtu = rxe_verbs::ibv_mtu_enum_to_u32(attr.path_mtu as u32);
        let mut req = RxeReqInfo::default();
        req.wqe_index = unsafe { librxe_sys::load_producer_index((*rqp).sq.queue) };

        // cq
        let rcq =
            NonNull::new(librxe_sys::to_rcq(qp_init_attr.qp_init_attr_inner.recv_cq).unwrap())
                .unwrap();
        let scq =
            NonNull::new(librxe_sys::to_rcq(qp_init_attr.qp_init_attr_inner.send_cq).unwrap())
                .unwrap();

        let mut priv_av = unsafe { std::mem::zeroed::<librxe_sys::rxe_av>() };
        let mut alt_av = unsafe { std::mem::zeroed::<librxe_sys::rxe_av>() };
        let priv_av_ptr = NonNull::new(&mut priv_av as *mut librxe_sys::rxe_av).unwrap();
        let alt_av_ptr = NonNull::new(&mut alt_av as *mut librxe_sys::rxe_av).unwrap();
        Ok(RxeQueuePair {
            pd: pd,
            inner_qp: rqp_ptr,
            qpn: qpn,
            attr: attr_ptr,
            srq: NonNull::dangling(),
            scq: scq,
            rcq: rcq,
            src_port: src_port,
            pri_av: priv_av_ptr,
            alt_av: alt_av_ptr,
            mtu: mtu,
            req: req,
            comp: RxeCompInfo::default(),
            resp: RxeRespInfo::default(),
            valid: true,
        })
    }

    pub fn modify_qp(
        &mut self,
        attr: &mut ibv_qp_attr,
        attr_mask: ibv_qp_attr_mask,
    ) -> Result<(), Error> {
        let errno = unsafe { ibv_modify_qp(self.as_ptr(), attr, attr_mask.0 as i32) };
        if errno != 0_i32 {
            return Err(Error::last());
        }
        // modify userspace rxe qp
        if (attr_mask & ibv_qp_attr_mask::IBV_QP_CUR_STATE) != ibv_qp_attr_mask(0) {
            unsafe { self.attr.as_mut().cur_qp_state = attr.qp_state };
        }
        if (attr_mask & ibv_qp_attr_mask::IBV_QP_EN_SQD_ASYNC_NOTIFY) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().en_sqd_async_notify = attr.en_sqd_async_notify;
            };
        }
        if (attr_mask & ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().qp_access_flags = attr.qp_access_flags;
            }
        }
        if (attr_mask & ibv_qp_attr_mask::IBV_QP_PKEY_INDEX) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().pkey_index = attr.pkey_index;
            }
        }
        if (attr_mask & ibv_qp_attr_mask::IBV_QP_PORT) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().port_num = attr.port_num;
            }
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_AV) != ibv_qp_attr_mask(0) {
            unsafe {
                rxe_init_av(&attr.ah_attr, self.pd, self.pri_av.as_mut());
            }
        }
        if (attr_mask & ibv_qp_attr_mask::IBV_QP_ALT_PATH) != ibv_qp_attr_mask(0) {
            unsafe {
                rxe_init_av(&attr.alt_ah_attr, self.pd, self.alt_av.as_mut());
                self.attr.as_mut().alt_port_num = attr.alt_port_num;
                self.attr.as_mut().alt_pkey_index = attr.alt_pkey_index;
                self.attr.as_mut().alt_timeout = attr.alt_timeout;
            }
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_PATH_MTU) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().path_mtu = attr.path_mtu;
                self.mtu = rxe_verbs::ibv_mtu_enum_to_u32(attr.path_mtu as u32);
            }
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_TIMEOUT) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().timeout = attr.timeout;
                // TODO qp_timeout_jiffies
            }
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_RETRY_CNT) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().retry_cnt = attr.retry_cnt;
                self.comp.retry_cnt = attr.retry_cnt as u32;
            }
            debug!("QP#{} set retry count {}", self.qpn, attr.retry_cnt);
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_RNR_RETRY) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().rnr_retry = attr.rnr_retry;
                self.comp.rnr_retry = attr.rnr_retry as u32;
            }
            debug!("QP#{} set rnr retry count {}", self.qpn, attr.rnr_retry);
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_RQ_PSN) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().rq_psn = attr.rq_psn & bth_mask::BTH_PSN_MASK;
                self.resp.psn = attr.rq_psn & bth_mask::BTH_PSN_MASK;
            }
            debug!("QP#{} set resp psn {}", self.qpn, self.resp.psn);
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().min_rnr_timer = attr.min_rnr_timer;
            }
            debug!("QP#{} set min rnr timer {:x}", self.qpn, attr.min_rnr_timer);
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_SQ_PSN) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().sq_psn = attr.sq_psn & bth_mask::BTH_PSN_MASK;
                self.req.psn = self.attr.as_ref().sq_psn;
                self.comp.psn = self.attr.as_ref().sq_psn;
            }
            debug!("QP#{} set req psn {}", self.qpn, self.req.psn);
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_PATH_MIG_STATE) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().path_mig_state = attr.path_mig_state;
            }
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_DEST_QPN) != ibv_qp_attr_mask(0) {
            unsafe {
                self.attr.as_mut().dest_qp_num = attr.dest_qp_num;
            }
            debug!("QP#{} set dest QP#{}", self.qpn, attr.dest_qp_num);
        }

        if (attr_mask & ibv_qp_attr_mask::IBV_QP_STATE) != ibv_qp_attr_mask(0) {
            unsafe { self.attr.as_mut().qp_state = attr.qp_state };
            match attr.qp_state {
                ibv_qp_state::IBV_QPS_RESET => {
                    self.req = RxeReqInfo::default();
                    self.resp = RxeRespInfo::default();
                    debug!("QP#{} state -> RESET", self.qpn);
                }
                ibv_qp_state::IBV_QPS_INIT => {
                    self.req.state = RxeQpState::QP_STATE_INIT;
                    self.resp.state = RxeQpState::QP_STATE_INIT;
                    debug!("QP#{} state -> INIT", self.qpn);
                }
                ibv_qp_state::IBV_QPS_RTR => {
                    self.resp.state = RxeQpState::QP_STATE_READY;
                    debug!("QP#{} state -> RTR", self.qpn);
                }
                ibv_qp_state::IBV_QPS_RTS => {
                    self.req.state = RxeQpState::QP_STATE_READY;
                    debug!("QP#{} state -> RTR", self.qpn);
                }
                ibv_qp_state::IBV_QPS_SQD => {
                    // TODO drain QP
                    debug!("QP#{} state -> SQD", self.qpn);
                }
                ibv_qp_state::IBV_QPS_SQE => {
                    /* Not possible from modify_qp. */
                    warn!("QP#{} state -> SQE, unexpected state", self.qpn);
                }
                ibv_qp_state::IBV_QPS_ERR => {
                    self.req.state = RxeQpState::QP_STATE_ERROR;
                    self.resp.state = RxeQpState::QP_STATE_ERROR;
                    unsafe {
                        self.attr.as_mut().qp_state = ibv_qp_state::IBV_QPS_ERR;
                    }
                }
                _ => {
                    warn!("unexpected qp state");
                }
            }
        }

        Ok(())
    }

    pub fn generate_modify_to_init_attr(
        &self,
        flag: ibv_access_flags,
        port_num: u8,
    ) -> (ibv_qp_attr, ibv_qp_attr_mask) {
        let mut attr = unsafe { std::mem::zeroed::<ibv_qp_attr>() };
        attr.pkey_index = 0;
        attr.port_num = port_num;
        attr.qp_state = ibv_qp_state::IBV_QPS_INIT;
        attr.qp_access_flags = flag.0;

        let attr_mask = ibv_qp_attr_mask::IBV_QP_PKEY_INDEX
            | ibv_qp_attr_mask::IBV_QP_STATE
            | ibv_qp_attr_mask::IBV_QP_PORT
            | ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS;
        (attr, attr_mask)
    }

    pub fn generate_modify_to_rtr_attr(
        &self,
        remote: QueuePairEndpoint,
        start_psn: u32,
        max_dest_rd_atomic: u8,
        min_rnr_timer: u8,
        port_num: u8,
        gid_index: u8,
    ) -> (ibv_qp_attr, ibv_qp_attr_mask) {
        let mut attr = unsafe { std::mem::zeroed::<ibv_qp_attr>() };
        attr.qp_state = ibv_qp_state::IBV_QPS_RTR;
        attr.path_mtu = unsafe { self.pd.as_ref().ctx.as_ref().get_active_mtu() };
        attr.dest_qp_num = remote.qp_num;
        attr.rq_psn = start_psn;
        attr.max_dest_rd_atomic = max_dest_rd_atomic;
        attr.min_rnr_timer = min_rnr_timer;
        attr.ah_attr.dlid = remote.lid;
        attr.ah_attr.sl = 0;
        attr.ah_attr.src_path_bits = 0;
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = port_num;
        attr.ah_attr.grh.dgid = remote.gid.into();
        attr.ah_attr.grh.hop_limit = 0xff;
        attr.ah_attr.grh.sgid_index = gid_index;
        let attr_mask = ibv_qp_attr_mask::IBV_QP_STATE
            | ibv_qp_attr_mask::IBV_QP_AV
            | ibv_qp_attr_mask::IBV_QP_PATH_MTU
            | ibv_qp_attr_mask::IBV_QP_DEST_QPN
            | ibv_qp_attr_mask::IBV_QP_RQ_PSN
            | ibv_qp_attr_mask::IBV_QP_MAX_DEST_RD_ATOMIC
            | ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER;
        (attr, attr_mask)
    }

    pub fn generate_modify_to_rts_attr(
        &self,
        timeout: u8,
        retry_cnt: u8,
        rnr_retry: u8,
        start_psn: u32,
        max_rd_atomic: u8,
    ) -> (ibv_qp_attr, ibv_qp_attr_mask) {
        let mut attr = unsafe { std::mem::zeroed::<ibv_qp_attr>() };
        attr.qp_state = ibv_qp_state::IBV_QPS_RTS;
        attr.timeout = timeout;
        attr.retry_cnt = retry_cnt;
        attr.rnr_retry = rnr_retry;
        attr.sq_psn = start_psn;
        attr.max_rd_atomic = max_rd_atomic;
        let attr_mask = ibv_qp_attr_mask::IBV_QP_STATE
            | ibv_qp_attr_mask::IBV_QP_TIMEOUT
            | ibv_qp_attr_mask::IBV_QP_RETRY_CNT
            | ibv_qp_attr_mask::IBV_QP_RNR_RETRY
            | ibv_qp_attr_mask::IBV_QP_SQ_PSN
            | ibv_qp_attr_mask::IBV_QP_MAX_QP_RD_ATOMIC;
        (attr, attr_mask)
    }

    pub fn qp_num(self: &Self) -> u32 {
        self.qpn
    }

    // post a single receive request
    // use system call to kernel
    #[inline]
    pub fn post_receive(
        &self,
        mr: &RxeMr,
        data_addr: *mut u8,
        data_length: u32, // in bytes
        wr_id: u64,
    ) -> Result<(), nix::Error> {
        let mut sge = ibv_sge {
            addr: data_addr as u64,
            length: data_length,
            lkey: mr.lkey(),
        };
        let mut wr = rdma_sys::ibv_recv_wr {
            wr_id: wr_id,
            next: std::ptr::null::<rdma_sys::ibv_send_wr>() as *mut _,
            sg_list: &mut sge as *mut _,
            num_sge: 1,
        };
        let mut bad_wr: *mut rdma_sys::ibv_recv_wr =
            std::ptr::null::<rdma_sys::ibv_recv_wr>() as *mut _;
        let qp = self.as_ptr();
        rxe_post_recv(qp, &mut wr as *mut _, &mut bad_wr as *mut _)
    }

    // post a single send request
    // use system call to kernel
    #[inline]
    pub fn post_send(
        &self,
        mr: &RxeMr,
        data_addr: *mut u8,
        data_length: u32, // in bytes
        wr_id: u64,
    ) -> Result<(), nix::Error> {
        let mut sge = ibv_sge {
            addr: data_addr as u64,
            length: data_length,
            lkey: mr.lkey(),
        };
        let mut wr = unsafe {
            ibv_send_wr {
                wr_id: wr_id,
                next: std::ptr::null::<rdma_sys::ibv_send_wr>() as *mut _,
                sg_list: &mut sge as *mut _,
                num_sge: 1,
                opcode: rdma_sys::ibv_wr_opcode::IBV_WR_SEND,
                send_flags: rdma_sys::ibv_send_flags::IBV_SEND_SIGNALED.0,
                wr: std::mem::zeroed(),
                qp_type: std::mem::zeroed(),
                imm_data_invalidated_rkey_union: std::mem::zeroed(),
                bind_mw_tso_union: std::mem::zeroed(),
            }
        };
        let mut bad_wr: *mut rdma_sys::ibv_send_wr = std::ptr::null_mut::<rdma_sys::ibv_send_wr>();
        let qp = self.as_ptr();
        rxe_post_send(
            qp,
            &mut wr as *mut ibv_send_wr,
            &mut bad_wr as *mut *mut ibv_send_wr,
        )
    }
}
