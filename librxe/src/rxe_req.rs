use crate::rxe_hdr::*;
use crate::rxe_opcode::{rxe_hdr_mask, rxe_wr_mask, wr_opcode_mask, RXE_OPCODE_INFO};
use crate::rxe_verbs::{self, psn_compare, RxeMrCopyDir, WqeState};
use librxe_sys::{qp_type, rxe_device_param, rxe_qp, rxe_qp_state, rxe_send_wqe};
use likely_stable::unlikely;
use nix::errno::Errno;
use nix::Error;
use rdma_sys::ibv_opcode::IBV_OPCODE_RC_COMPARE_SWAP;
use rdma_sys::{ibv_opcode, ibv_qp_type, ibv_send_flags, ibv_wc_status, ibv_wr_opcode};

fn next_opcode(
    qp: &librxe_sys::rxe_qp,
    wqe: &librxe_sys::rxe_send_wqe,
    opcode: rdma_sys::ibv_wr_opcode::Type,
) -> Result<ibv_opcode::Type, Error> {
    // FIXME: Using the MTU properties in QP struct
    let fits = wqe.dma.resid <= qp.mtu;
    match qp_type(qp) {
        ibv_qp_type::IBV_QPT_RC => next_opcode_rc(qp, opcode, fits),
        ibv_qp_type::IBV_QPT_UC => next_opcode_uc(qp, opcode, fits),
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
    qp: &librxe_sys::rxe_qp,
    opcode: rdma_sys::ibv_wr_opcode::Type,
    fits: bool,
) -> Result<ibv_opcode::Type, Error> {
    let req_op = qp.req.opcode as ibv_opcode::Type;
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
    qp: &librxe_sys::rxe_qp,
    opcode: rdma_sys::ibv_wr_opcode::Type,
    fits: bool,
) -> Result<ibv_opcode::Type, Error> {
    let req_op = qp.req.opcode as ibv_opcode::Type;
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
fn get_mtu(qp: &librxe_sys::rxe_qp) -> u32 {
    let qp_type = qp_type(qp);
    match qp_type {
        rdma_sys::ibv_qp_type::IBV_QPT_RC | rdma_sys::ibv_qp_type::IBV_QPT_UC => qp.mtu,
        // FIXME: it should return rxe->port.mtu_cap, which was assigned in the initialization of rxe device
        _ => rdma_sys::ibv_mtu::IBV_MTU_1024 as u32,
    }
}

fn req_next_wqe(qp: &mut librxe_sys::rxe_qp) -> Option<*mut librxe_sys::rxe_send_wqe> {
    let wqe = librxe_sys::queue_head::<librxe_sys::rxe_send_wqe>(qp.sq.queue);
    let sq_buf = qp.sq.queue;
    let index = qp.req.wqe_index as u32;
    let prod = librxe_sys::load_producer_index(sq_buf);
    let cons = librxe_sys::load_consumer_index(sq_buf);

    if unlikely(qp.req.state == rxe_qp_state::QP_STATE_DRAIN) {
        unsafe {
            libc::pthread_spin_lock(&mut qp.state_lock);
        }
        loop {
            if qp.req.state != rxe_qp_state::QP_STATE_DRAIN {
                /* comp just finished */
                unsafe {
                    libc::pthread_spin_unlock(&mut qp.state_lock);
                }
                break;
            }
            if let Some(wqe) = wqe {
                unsafe {
                    if (index != cons) || (*wqe).state != WqeState::WqeStatePosted as _ {
                        libc::pthread_spin_unlock(&mut qp.state_lock);
                    }
                }
                break;
            }
            qp.req.state = rxe_qp_state::QP_STATE_DRAINED;
            unsafe {
                libc::pthread_spin_unlock(&mut qp.state_lock);
            }
            break;
        }
    }
    if index == prod {
        return None;
    }
    let wqe =
        unsafe { &mut *(librxe_sys::addr_from_index::<librxe_sys::rxe_send_wqe>(sq_buf, index)) };
    if unlikely(
        (qp.req.state == rxe_qp_state::QP_STATE_DRAIN
            || qp.req.state == rxe_qp_state::QP_STATE_DRAINED)
            && wqe.state != WqeState::WqeStateProcessing as _,
    ) {
        return None;
    }
    if unlikely((wqe.wr.send_flags & ibv_send_flags::IBV_SEND_FENCE.0 != 0) && (index != cons)) {
        qp.req.wait_fence = 1;
        return None;
    }
    wqe.mask = wr_opcode_mask(qp, wqe.wr.opcode);

    Some(wqe)
}

fn init_req_packet(
    qp: &mut librxe_sys::rxe_qp,
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

    let dest_qp_num: u32 = if pkt_info.mask & RXE_DETH_MASK != 0 {
        unsafe { ibwr.wr.ud.as_ref().remote_qpn }
    } else {
        qp.attr.dest_qp_num
    };
    qp.req.noack_pkts = qp.req.noack_pkts + 1;
    let ack_req = ((pkt_info.mask & RXE_END_MASK) != 0)
        || ((qp.req.noack_pkts + 1) > rxe_device_param::RXE_MAX_PKT_PER_ACK as _);
    if ack_req {
        qp.req.noack_pkts = 0;
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
        pkt_info.reth_set_rkey(unsafe { ibwr.wr.rdma.as_ref().rkey });
        pkt_info.reth_set_va(wqe.iova);
        pkt_info.reth_set_len(wqe.dma.resid);
    }
    if (pkt_info.mask & RXE_IMMDT_MASK) != 0 {
        pkt_info.immdt_set_imm(unsafe { ibwr.ex.imm_data });
    }
    if (pkt_info.mask & RXE_ATMETH_MASK) != 0 {
        pkt_info.atmeth_set_va(wqe.iova);
        if opcode == IBV_OPCODE_RC_COMPARE_SWAP {
            pkt_info.atmeth_set_swap_add(unsafe { ibwr.wr.atomic.as_ref().swap });
            pkt_info.atmeth_set_comp(unsafe { ibwr.wr.atomic.as_ref().compare_add });
        } else {
            pkt_info.atmeth_set_swap_add(unsafe { ibwr.wr.atomic.as_ref().compare_add });
        }
        pkt_info.atmeth_set_rkey(unsafe { ibwr.wr.atomic.as_ref().rkey });
    }
    let src_qp_num = unsafe { qp.vqp.qp_union.qp.qp_num };
    if (pkt_info.mask & RXE_DETH_MASK) != 0 {
        if src_qp_num == 1 {
            pkt_info.deth_set_qkey(GSI_QKEY);
        } else {
            pkt_info.deth_set_qkey(unsafe { ibwr.wr.ud.as_ref().remote_qkey });
        }
        pkt_info.deth_set_sqp(src_qp_num);
    }
}

// fill the IBA content only,
// the IP/UDP headers, these will be filled in the kernel
// the IBA headers has been populated
pub fn finish_packet(
    qp: &mut librxe_sys::rxe_qp,
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
            pkt_info.copy_data(
                0,
                &mut wqe.dma,
                pkt_info.get_iba_hdr_len(),
                payload as u32,
                RxeMrCopyDir::RxeFromMrObj,
            )?;
        }
    }
    Ok(())
}
#[inline]
fn save_state(
    wqe: &rxe_send_wqe,
    qp: &librxe_sys::rxe_qp,
    rollback_wqe: &mut rxe_send_wqe,
    rollback_psn: &mut u32,
) {
    rollback_wqe.state = wqe.state;
    rollback_wqe.first_psn = wqe.first_psn;
    rollback_wqe.last_psn = wqe.last_psn;
    *rollback_psn = qp.req.psn;
}
#[inline]
fn rollback_state(
    wqe: &mut rxe_send_wqe,
    qp: &mut librxe_sys::rxe_qp,
    rollback_wqe: &rxe_send_wqe,
    rollback_psn: u32,
) {
    wqe.state = rollback_wqe.state;
    wqe.first_psn = rollback_wqe.first_psn;
    wqe.last_psn = rollback_wqe.last_psn;
    qp.req.psn = rollback_psn;
}

#[inline]
fn update_wqe_state(qp: &librxe_sys::rxe_qp, pkt: &RxePktInfo, wqe: &mut librxe_sys::rxe_send_wqe) {
    if pkt.mask & rxe_hdr_mask::RXE_END_MASK != 0 {
        if qp_type(qp) == ibv_qp_type::IBV_QPT_RC {
            wqe.state = WqeState::WqeStatePending as _;
        } else {
            wqe.state = WqeState::WqeStateProcessing as _;
        }
    }
}

#[inline]
fn update_state(qp: &mut rxe_qp, pkt: &RxePktInfo) {
    qp.req.opcode = pkt.opcode as _;
    if (pkt.mask & rxe_hdr_mask::RXE_END_MASK) != 0 {
        qp.req.wqe_index = librxe_sys::queue_next_index(qp.sq.queue, qp.req.wqe_index);
    }
    // TODO check timers
}
#[inline]
fn update_wqe_psn(
    qp: &mut librxe_sys::rxe_qp,
    wqe: &mut librxe_sys::rxe_send_wqe,
    pkt: &RxePktInfo,
    payload: u32,
) {
    // number of packets left to send including current one
    let _num_pkt = (wqe.dma.resid + payload + qp.mtu - 1) / qp.mtu;
    let num_pkt = if _num_pkt == 0 { 1 } else { _num_pkt };
    if (pkt.mask & rxe_hdr_mask::RXE_START_MASK) != 0 {
        wqe.first_psn = qp.req.psn;
        wqe.last_psn = (qp.req.psn + num_pkt - 1) & bth_mask::BTH_PSN_MASK;
    }
    if (pkt.mask & rxe_hdr_mask::RXE_READ_MASK) != 0 {
        qp.req.psn = (wqe.first_psn + num_pkt) & bth_mask::BTH_PSN_MASK;
    } else {
        qp.req.psn = (qp.req.psn + 1) & bth_mask::BTH_PSN_MASK;
    }
}

pub fn rxe_requster(qp: &mut librxe_sys::rxe_qp) -> Result<(), Error> {
    // break the loop only if the current work request is not legal
    loop {
        if unlikely(qp.valid != 1 || qp.req.state == rxe_qp_state::QP_STATE_ERROR) {
            break;
        }
        if unlikely(qp.req.state == rxe_qp_state::QP_STATE_RESET) {
            // FIXME: set wqe_index to sq.queue.index
            // qp.req.wqe_index
            qp.req.opcode = -1;
            qp.req.need_rd_atomic = 0;
            qp.req.wait_psn = 0;
            qp.req.need_retry = 0;
            break;
        }
        if unlikely(qp.req.need_retry == 1) {
            // TODO: impl req_retry(qp);
            qp.req.need_retry = 0;
        }

        let mut wqe = match req_next_wqe(qp) {
            Some(wqe) => unsafe { &mut (*wqe) },
            // TODO: should be unlikely
            None => break,
        };

        if (wqe.mask & rxe_wr_mask::WR_LOCAL_OP_MASK as u32) != 0 {
            // TODO: impl rxe_do_local_ops()
            // skip this wqe
            break;
        }

        if unlikely(
            qp_type(qp) == ibv_qp_type::IBV_QPT_RC
                && psn_compare(
                    qp.req.psn,
                    qp.comp.psn + rxe_device_param::RXE_MAX_UNACKED_PSNS as u32,
                ) > 0,
        ) {
            qp.req.wait_psn = 1;
            break;
        }

        let opcode = match next_opcode(qp, &wqe, wqe.wr.opcode) {
            Ok(opcode) => opcode,
            // TODO: unlikely
            Err(_) => {
                wqe.state = WqeState::WqeStateError as _;
                break;
            }
        };
        let mask = RXE_OPCODE_INFO[opcode as usize].mask;
        if unlikely((mask & rxe_hdr_mask::RXE_READ_OR_ATOMIC_MASK) != 0) {
            // TODO: check_init_depth(qp, wqe)
            break;
        }
        let mtu = get_mtu(qp);
        let mut payload = if (mask & rxe_hdr_mask::RXE_WRITE_OR_SEND_MASK) != 0 {
            wqe.dma.resid
        } else {
            0
        };
        if payload > mtu {
            if qp_type(qp) == ibv_qp_type::IBV_QPT_UD {
                /* C10-93.1.1: If the total sum of all the buffer lengths specified for a
                 * UD message exceeds the MTU of the port as returned by QueryHCA, the CI
                 * shall not emit any packets for this message. Further, the CI shall not
                 * generate an error due to this condition.
                 */
                // fake a successful UD send and return
                wqe.first_psn = qp.req.psn;
                wqe.last_psn = qp.req.psn;
                qp.req.psn = (qp.req.psn + 1) & bth_mask::BTH_PSN_MASK;
                qp.req.opcode = ibv_opcode::IBV_OPCODE_UD_SEND_ONLY as _;
                // TODO: qp.req.wqe_index = queue_next_index
                wqe.state = WqeState::WqeStateDone as _;
                wqe.status = ibv_wc_status::IBV_WC_SUCCESS;
                // TODO: 	__rxe_do_task(&qp->comp.task);
                return Ok(());
            }
            payload = mtu;
        }
        let mut pkt_info = RxePktInfo::new(
            RXE_OPCODE_INFO[opcode as usize].mask as _,
            qp.req.psn,
            0,
            0,
            1, // always 1 in RXE
            opcode as u8,
            mtu,
        );
        // ignore RDMA AV calcultion

        // init iba packet buffer and header
        init_req_packet(qp, &mut wqe, opcode, payload, &mut pkt_info);
        // fill the iba packet content
        if let Err(ret) = finish_packet(qp, wqe, &mut pkt_info, payload as _) {
            if ret == Errno::EFAULT {
                wqe.status = ibv_wc_status::IBV_WC_LOC_PROT_ERR;
            } else {
                wqe.status = ibv_wc_status::IBV_WC_LOC_QP_OP_ERR;
            }
            wqe.state = WqeState::WqeStateError as _;
            break;
        }
        // save state
        let mut rollback_wqe = librxe_sys::rxe_send_wqe::default();
        let mut rollback_psn = 0;
        save_state(wqe, qp, &mut rollback_wqe, &mut rollback_psn);
        update_wqe_state(qp, &pkt_info, wqe);
        update_wqe_psn(qp, wqe, &pkt_info, payload);
        // transmit this packet

        update_state(qp, &pkt_info);
        return Ok(());
    }

    Err(Error::EAGAIN)
}
