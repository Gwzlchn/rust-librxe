/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

// Keep the same constant definition as in the upstream-kernel 
// drivers/infiniband/sw/rxe/rxe_param.h
#ifndef RXE_PARAM_H
#define RXE_PARAM_H

#include "rxe_bindings.h"

#define DEFAULT_MAX_VALUE (1 << 20)

/* default/initial rxe device parameter settings */
enum rxe_device_param {
  RXE_MAX_MR_SIZE = -1ull,
  RXE_PAGE_SIZE_CAP = 0xfffff000,
  RXE_MAX_QP_WR = DEFAULT_MAX_VALUE,

  RXE_MAX_SGE = 32,
  RXE_MAX_WQE_SIZE =
      sizeof(struct rxe_send_wqe) + sizeof(struct ibv_sge) * RXE_MAX_SGE,
  RXE_MAX_INLINE_DATA = RXE_MAX_WQE_SIZE - sizeof(struct rxe_send_wqe),
  RXE_MAX_SGE_RD = 32,
  RXE_MAX_CQ = DEFAULT_MAX_VALUE,
  RXE_MAX_LOG_CQE = 15,
  RXE_MAX_PD = DEFAULT_MAX_VALUE,
  RXE_MAX_QP_RD_ATOM = 128,
  RXE_MAX_RES_RD_ATOM = 0x3f000,
  RXE_MAX_QP_INIT_RD_ATOM = 128,
  RXE_MAX_MCAST_GRP = 8192,
  RXE_MAX_MCAST_QP_ATTACH = 56,
  RXE_MAX_TOT_MCAST_QP_ATTACH = 0x70000,
  RXE_MAX_AH = (1 << 15) - 1, /* 32Ki - 1 */
  RXE_MIN_AH_INDEX = 1,
  RXE_MAX_AH_INDEX = RXE_MAX_AH,
  RXE_MAX_SRQ_WR = DEFAULT_MAX_VALUE,
  RXE_MIN_SRQ_WR = 1,
  RXE_MAX_SRQ_SGE = 27,
  RXE_MIN_SRQ_SGE = 1,
  RXE_MAX_FMR_PAGE_LIST_LEN = 512,
  RXE_MAX_PKEYS = 64,
  RXE_LOCAL_CA_ACK_DELAY = 15,

  RXE_MAX_UCONTEXT = DEFAULT_MAX_VALUE,

  RXE_NUM_PORT = 1,

  RXE_MIN_QP_INDEX = 16,
  RXE_MAX_QP_INDEX = DEFAULT_MAX_VALUE,
  RXE_MAX_QP = DEFAULT_MAX_VALUE - RXE_MIN_QP_INDEX,

  RXE_MIN_SRQ_INDEX = 0x00020001,
  RXE_MAX_SRQ_INDEX = DEFAULT_MAX_VALUE,
  RXE_MAX_SRQ = DEFAULT_MAX_VALUE - RXE_MIN_SRQ_INDEX,

  RXE_MIN_MR_INDEX = 0x00000001,
  RXE_MAX_MR_INDEX = DEFAULT_MAX_VALUE,
  RXE_MAX_MR = DEFAULT_MAX_VALUE - RXE_MIN_MR_INDEX,
  RXE_MIN_MW_INDEX = 0x00010001,
  RXE_MAX_MW_INDEX = 0x00020000,
  RXE_MAX_MW = 0x00001000,

  RXE_MAX_PKT_PER_ACK = 64,

  RXE_MAX_UNACKED_PSNS = 128,

  /* Max inflight SKBs per queue pair */
  RXE_INFLIGHT_SKBS_PER_QP_HIGH = 64,
  RXE_INFLIGHT_SKBS_PER_QP_LOW = 16,

  /* Delay before calling arbiter timer */
  RXE_NSEC_ARB_TIMER_DELAY = 200,

  /* IBTA v1.4 A3.3.1 VENDOR INFORMATION section */
  RXE_VENDOR_ID = 0XFFFFFF,
};

/* default/initial rxe port parameters */
enum rxe_port_param {
  RXE_PORT_GID_TBL_LEN = 1024,
  // RXE_PORT_PORT_CAP_FLAGS		= IB_PORT_CM_SUP,
  RXE_PORT_MAX_MSG_SZ = 0x800000,
  RXE_PORT_BAD_PKEY_CNTR = 0,
  RXE_PORT_QKEY_VIOL_CNTR = 0,
  RXE_PORT_LID = 0,
  RXE_PORT_SM_LID = 0,
  RXE_PORT_SM_SL = 0,
  RXE_PORT_LMC = 0,
  RXE_PORT_MAX_VL_NUM = 1,
  RXE_PORT_SUBNET_TIMEOUT = 0,
  RXE_PORT_INIT_TYPE_REPLY = 0,
  RXE_PORT_ACTIVE_SPEED = 1,
  RXE_PORT_PKEY_TBL_LEN = 1,
  RXE_PORT_SUBNET_PREFIX = 0xfe80000000000000ULL,
};

/* default/initial port info parameters */
enum rxe_port_info_param {
  RXE_PORT_INFO_VL_CAP = 4,  /* 1-8 */
  RXE_PORT_INFO_MTU_CAP = 5, /* 4096 */
  RXE_PORT_INFO_OPER_VL = 1, /* 1 */
};

#endif /* RXE_PARAM_H */
