#ifndef URXE_VERBS_H
#define URXE_VERBS_H
#include "urxe_hw_counters.h"


struct urxe_ucontext {
	struct ib_ucontext ibuc;
};


struct urxe_port
{
	struct ib_port_attr attr;
	__be64 port_guid;
	__be64 subnet_prefix;
	spinlock_t port_lock; /* guard port */
	unsigned int mtu_cap;
	/* special QPs */
	u32			qp_gsi_index;
};

struct urxe_dev
{
	struct ib_device ib_dev;
	struct ib_device_attr attr;
	int max_ucontext;
	int max_inline_data;
	struct mutex usdev_lock;

	atomic64_t		stats_counters[URXE_NUM_OF_COUNTERS];

	struct net_device *ndev;
	struct urxe_port port;
};

static inline struct urxe_dev *to_urdev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct urxe_dev, ib_dev) : NULL;
}

static inline struct urxe_ucontext *to_uruc(struct ib_ucontext *uc)
{
	return uc ? container_of(uc, struct urxe_ucontext, ibuc) : NULL;
}

int urxe_register_device(struct urxe_dev *urxe, const char *ibdev_name);

#endif // URXE_VERBS_H