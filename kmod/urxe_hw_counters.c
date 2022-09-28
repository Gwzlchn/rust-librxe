// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2017 Mellanox Technologies Ltd. All rights reserved.
 */

#include "urxe.h"
#include "urxe_hw_counters.h"

static const struct rdma_stat_desc urxe_counter_descs[] = {
	[URXE_CNT_SENT_PKTS].name           =  "sent_pkts",
	[URXE_CNT_RCVD_PKTS].name           =  "rcvd_pkts",
	[URXE_CNT_DUP_REQ].name             =  "duplicate_request",
	[URXE_CNT_OUT_OF_SEQ_REQ].name      =  "out_of_seq_request",
	[URXE_CNT_RCV_RNR].name             =  "rcvd_rnr_err",
	[URXE_CNT_SND_RNR].name             =  "send_rnr_err",
	[URXE_CNT_RCV_SEQ_ERR].name         =  "rcvd_seq_err",
	[URXE_CNT_COMPLETER_SCHED].name     =  "ack_deferred",
	[URXE_CNT_RETRY_EXCEEDED].name      =  "retry_exceeded_err",
	[URXE_CNT_RNR_RETRY_EXCEEDED].name  =  "retry_rnr_exceeded_err",
	[URXE_CNT_COMP_RETRY].name          =  "completer_retry_err",
	[URXE_CNT_SEND_ERR].name            =  "send_err",
	[URXE_CNT_LINK_DOWNED].name         =  "link_downed",
	[URXE_CNT_RDMA_SEND].name           =  "rdma_sends",
	[URXE_CNT_RDMA_RECV].name           =  "rdma_recvs",
};

int urxe_ib_get_hw_stats(struct ib_device *ibdev,
			struct rdma_hw_stats *stats,
			u32 port, int index)
{
	struct urxe_dev *dev = to_urdev(ibdev);
	unsigned int cnt;

	if (!port || !stats)
		return -EINVAL;

	for (cnt = 0; cnt < ARRAY_SIZE(urxe_counter_descs); cnt++)
		stats->value[cnt] = atomic64_read(&dev->stats_counters[cnt]);

	return ARRAY_SIZE(urxe_counter_descs);
}

struct rdma_hw_stats *urxe_ib_alloc_hw_port_stats(struct ib_device *ibdev,
						 u32 port_num)
{
	BUILD_BUG_ON(ARRAY_SIZE(urxe_counter_descs) != URXE_NUM_OF_COUNTERS);

	return rdma_alloc_hw_stats_struct(urxe_counter_descs,
					  ARRAY_SIZE(urxe_counter_descs),
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}
