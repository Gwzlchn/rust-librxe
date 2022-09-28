/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2017 Mellanox Technologies Ltd. All rights reserved.
 */

#ifndef URXE_HW_COUNTERS_H
#define URXE_HW_COUNTERS_H

/*
 * when adding counters to enum also add
 * them to rxe_counter_name[] vector.
 */
enum urxe_counters {
	URXE_CNT_SENT_PKTS,
	URXE_CNT_RCVD_PKTS,
	URXE_CNT_DUP_REQ,
	URXE_CNT_OUT_OF_SEQ_REQ,
	URXE_CNT_RCV_RNR,
	URXE_CNT_SND_RNR,
	URXE_CNT_RCV_SEQ_ERR,
	URXE_CNT_COMPLETER_SCHED,
	URXE_CNT_RETRY_EXCEEDED,
	URXE_CNT_RNR_RETRY_EXCEEDED,
	URXE_CNT_COMP_RETRY,
	URXE_CNT_SEND_ERR,
	URXE_CNT_LINK_DOWNED,
	URXE_CNT_RDMA_SEND,
	URXE_CNT_RDMA_RECV,
	URXE_NUM_OF_COUNTERS
};

struct rdma_hw_stats *urxe_ib_alloc_hw_port_stats(struct ib_device *ibdev,
						 u32 port_num);
int urxe_ib_get_hw_stats(struct ib_device *ibdev,
			struct rdma_hw_stats *stats,
			u32 port, int index);
#endif /* RXE_HW_COUNTERS_H */
