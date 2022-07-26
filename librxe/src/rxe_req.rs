use librxe_sys::rxe_qp_state;
use likely_stable::unlikely;
use nix::Error;
use rdma_sys::{ibv_opcode, ibv_qp_type, ibv_wr_opcode};

fn next_opcode(
    qp: &librxe_sys::rxe_qp,
    wqe: &librxe_sys::rxe_send_wqe,
    opcode: rdma_sys::ibv_wr_opcode::Type,
) -> Result<ibv_opcode::Type, Error> {
    // FIXME: Using the MTU properties in QP struct
    let fits = wqe.dma.resid <= rdma_sys::ibv_mtu::IBV_MTU_1024;
    match librxe_sys::qp_type(qp) {
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

fn req_next_wqe(qp: &mut librxe_sys::rxe_qp) -> Option<librxe_sys::rxe_send_wqe> {
    None
}

pub fn rxe_requster(qp: &mut librxe_sys::rxe_qp) -> Result<(), Error> {
    if unlikely(qp.valid != 1 || qp.req.state == rxe_qp_state::QP_STATE_ERROR) {
        return Err(Error::EINVAL);
    }
    if unlikely(qp.req.state == rxe_qp_state::QP_STATE_RESET) {
        // FIXME: set wqe_index to sq.queue.index
        // qp.req.wqe_index
        qp.req.opcode = -1;
        qp.req.need_rd_atomic = 0;
        qp.req.wait_psn = 0;
        qp.req.need_retry = 0;
        return Err(Error::EINVAL);
    }
    if unlikely(qp.req.need_retry == 1) {
        // TODO: impl req_retry(qp);
        qp.req.need_retry = 0;
    }
    if let Some(wqe) = req_next_wqe(qp) {
    } else {
        return Err(Error::EINVAL);
    }

    Ok(())
}
