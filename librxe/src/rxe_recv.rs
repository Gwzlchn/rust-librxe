use std::{
    borrow::{Borrow, BorrowMut},
    cell::RefCell,
    rc::Rc,
};

use crate::{
    rxe_context::RxeContext,
    rxe_hdr::{self, RxePktInfo, GSI_QKEY},
    rxe_net::{self, RxeSkb},
    rxe_opcode::{
        self,
        rxe_hdr_mask::{self, RXE_GRH_MASK},
    },
    rxe_qp::{RxeQpState, RxeQueuePair},
    rxe_verbs::{self, pkey_match, IB_DEFAULT_PKEY_FULL},
};
use nix::{errno::Errno, Error};
use rdma_sys::{ibv_opcode, ibv_qp_type};
use tracing::{error, warn};

impl RxePktInfo {
    /// check that QP matches packet opcode type and is in a valid state
    pub fn check_type_state(&self, qp: &RxeQueuePair) -> Result<(), Error> {
        if !qp.valid {
            return Err(Errno::EINVAL);
        }
        let pkt_type = self.opcode & 0xE0;
        match qp.qp_type() {
            ibv_qp_type::IBV_QPT_RC => {
                if pkt_type != ibv_opcode::IBV_OPCODE_RC {
                    warn!("bad qp type\n");
                    return Err(Errno::EINVAL);
                }
            }
            ibv_qp_type::IBV_QPT_UC => {
                if pkt_type != ibv_opcode::IBV_OPCODE_UC {
                    warn!("bad qp type\n");
                    return Err(Errno::EINVAL);
                }
            }
            ibv_qp_type::IBV_QPT_UD => {
                //IB_QPT_GSI ignored
                if pkt_type != ibv_opcode::IBV_OPCODE_UD {
                    warn!("bad qp type\n");
                    return Err(Errno::EINVAL);
                }
            }
            _ => {
                warn!("unsupported qp type");
                return Err(Errno::EINVAL);
            }
        }
        if self.mask & rxe_hdr_mask::RXE_REQ_MASK != 0 {
            if qp.resp.state != RxeQpState::QP_STATE_READY {
                return Err(Errno::EINVAL);
            }
        } else if qp.req.state == RxeQpState::QP_STATE_RESET
            || qp.req.state == RxeQpState::QP_STATE_INIT
            || qp.req.state == RxeQpState::QP_STATE_ERROR
        {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    pub fn check_keys(&self, qpn: u32, qp: &RxeQueuePair) -> Result<(), Error> {
        let pkey = self.bth_pkey();

        if !pkey_match(pkey, IB_DEFAULT_PKEY_FULL) {
            warn!("bad pkey = {:x}", pkey);
            // TODO set_bad_pkey_cntr
            return Err(Errno::EINVAL);
        }
        if qp.qp_type() == ibv_qp_type::IBV_QPT_UD {
            // IB_QPT_GSI ignored
            let qkey = if qpn == 1 { GSI_QKEY } else { qp.qkey() };
            if self.deth_qkey() != qkey {
                warn!(
                    "bad qkey, got {:x}, expected {:x} for qpn {:x}",
                    self.deth_qkey(),
                    qkey,
                    qpn
                );
                // TODO set_qkey_viol_cntr
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    }
    /// check qp source/destination ip address are matched with packet destination/source address
    pub fn check_addr(&self, skb: &RxeSkb, qp: &RxeQueuePair) -> Result<(), Error> {
        if qp.qp_type() != ibv_qp_type::IBV_QPT_RC && qp.qp_type() != ibv_qp_type::IBV_QPT_UC {
            return Ok(());
        }
        if self.port_num != qp.port_num() {
            warn!("port {} != qp port {}", self.port_num, qp.port_num());
            return Err(Errno::EINVAL);
        }
        if skb.protocol == rxe_verbs::RXE_NETWORK_TYPE_IPV4 {
            let qp_saddr = unsafe { qp.pri_av.sgid_addr._sockaddr_in.sin_addr.s_addr };
            let qp_daddr = unsafe { qp.pri_av.dgid_addr._sockaddr_in.sin_addr.s_addr };
            let pkt_saddr = u32::from_be_bytes(skb.ipv4_hdr.source);
            let pkt_daddr = u32::from_be_bytes(skb.ipv4_hdr.destination);
            if pkt_daddr != qp_saddr {
                warn!("dst addr {:x} != qp source addr {:x}", pkt_daddr, qp_saddr);
                return Err(Errno::EINVAL);
            }
            if pkt_saddr != qp_daddr {
                warn!("source addr {:x} != qp dst addr {:x}", pkt_saddr, qp_daddr);
                return Err(Errno::EINVAL);
            }
        } else if skb.protocol == rxe_verbs::RXE_NETWORK_TYPE_IPV6 {
            let qp_saddr = unsafe { &qp.pri_av.sgid_addr._sockaddr_in6.sin6_addr.s6_addr };
            let qp_daddr = unsafe { &qp.pri_av.dgid_addr._sockaddr_in6.sin6_addr.s6_addr };
            let pkt_saddr = &skb.ipv6_hdr.source;
            let pkt_daddr = &skb.ipv6_hdr.destination;
            if rxe_net::compare(pkt_daddr, qp_saddr) != std::cmp::Ordering::Equal {
                warn!("dst addr {:?} != qp source addr {:?}", pkt_daddr, qp_saddr);
                return Err(Errno::EINVAL);
            }
            if rxe_net::compare(pkt_saddr, qp_daddr) != std::cmp::Ordering::Equal {
                warn!("source addr {:?} != qp dst addr {:?}", pkt_saddr, qp_daddr);
                return Err(Errno::EINVAL);
            }
        }

        Ok(())
    }

    pub fn hdr_check(&mut self, ctx: &RxeContext, skb: &RxeSkb) -> Result<(), Error> {
        let qpn = self.bth_qpn();
        if self.bth_tver() as u32 != rxe_hdr::BTH_TVER {
            warn!("bad tver");
            return Err(Errno::EINVAL);
        }
        if qpn == 0 {
            warn!("QP 0 not supported");
        }
        if qpn != rxe_verbs::IB_MULTICAST_QPN {
            let qp = ctx.rxe_pool_get_qp(qpn);
            if qp.is_none() {
                error!("no qp matches qpn {:x}", qpn);
                return Err(Errno::EINVAL);
            }
            let qp = qp.unwrap().as_ref().borrow();
            self.check_type_state(&qp)?;
            self.check_addr(skb, &qp)?;
            self.pkey_index = 0;
            self.check_keys(qpn, &qp)?;
            self.qp = Some(Rc::new(RefCell::new(qp.clone())));
        } else {
            if self.mask & rxe_opcode::rxe_hdr_mask::RXE_GRH_MASK != 0 {
                warn!("no grh for mcast qpn");
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    }
}

impl RxeSkb {
    pub fn rxe_rcv_pkt(&mut self) -> Result<(), Error> {
        let pkt_info = unsafe { &mut *self.pkt_info.as_ptr() };

        let mask = pkt_info.mask;
        if mask & rxe_hdr_mask::RXE_REQ_MASK != 0 {
            // pkt_info.qp.as_mut().unwrap().as_ref().borrow_mut().rxe_responder(&mut pkt_info);
            pkt_info
                .qp
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow_mut()
                .rxe_responder(self.pkt_info.as_ptr())
        } else {
            todo!()
            // pkt_info
            //     .borrow_mut()
            //     .qp
            //     .as_ref()
            //     .unwrap()
            //     .borrow_mut()
            //     .rxec()
        }
    }
    pub fn rxe_rcv(&mut self, ctx: &RxeContext) -> Result<(), Error> {
        let pkt = unsafe { &mut *self.pkt_info.as_ptr() };
        if pkt.get_iba_pkt_len() < rxe_hdr::rxe_hdr_length::RXE_BTH_BYTES as usize {
            return Err(Errno::EINVAL);
        }
        // TODO rxe_chk_dgid
        pkt.opcode = pkt.bth_opcode();
        pkt.psn = pkt.bth_psn();
        pkt.qp = None;
        pkt.mask |= rxe_opcode::RXE_OPCODE_INFO[pkt.opcode as usize].mask;
        if let Err(_) = pkt.hdr_check(ctx, self) {
            warn!("header check failed");
            return Err(Errno::EINVAL);
        }
        // TODO rxe_icrc_check
        if pkt.bth_qpn() == rxe_verbs::IB_MULTICAST_QPN {
            // TODO rxe_rcv_mcastpkt
        } else {
            self.rxe_rcv_pkt()?;
        }
        Ok(())
    }
}
