#ifndef URXE_H
#define URXE_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>

#include "urxe_net.h"
#include "urxe_param.h"
#include "urxe_verbs.h"
#include "urxe_loc.h"


#define URXE_UVERBS_ABI_VERSION 2

/* The caller must do a matching ib_device_put(&dev->ib_dev) */
static inline struct urxe_dev *urxe_get_dev_from_net(struct net_device *ndev)
{
	struct ib_device *ibdev =
		ib_device_get_by_netdev(ndev, RDMA_DRIVER_URXE);

	if (!ibdev)
		return NULL;
	return container_of(ibdev, struct urxe_dev, ib_dev);
}

void urxe_set_mtu(struct urxe_dev *rxe, unsigned int dev_mtu);

int urxe_add(struct urxe_dev *urxe, unsigned int mtu, const char *ibdev_name);

void urxe_port_up(struct urxe_dev *urxe);
void urxe_port_down(struct urxe_dev *urxe);
void urxe_set_port_state(struct urxe_dev *urxe);

#endif // URXE_H