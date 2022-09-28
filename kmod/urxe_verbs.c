#include "urxe.h"
#include <net/addrconf.h>


// query urxe functions
// called by setup_device() in ib-core
static int urxe_query_device(struct ib_device *dev,
							 struct ib_device_attr *attr,
							 struct ib_udata *uhw)
{
	struct urxe_dev *urxe = to_urdev(dev);

	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	*attr = urxe->attr;
	return 0;
}

// called by __ib_query_port
static int urxe_query_port(struct ib_device *dev,
						   u32 port_num, struct ib_port_attr *attr)
{
	struct urxe_dev *urxe = to_urdev(dev);
	int rc;

	/* *attr being zeroed by the caller, avoid zeroing it here */
	*attr = urxe->port.attr;

	mutex_lock(&urxe->usdev_lock);
	rc = ib_get_eth_speed(dev, port_num, &attr->active_speed,
						  &attr->active_width);

	if (attr->state == IB_PORT_ACTIVE)
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	else if (dev_get_flags(urxe->ndev) & IFF_UP)
		attr->phys_state = IB_PORT_PHYS_STATE_POLLING;
	else
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;

	mutex_unlock(&urxe->usdev_lock);

	return rc;
}

// called by ib_query_pkey
static int urxe_query_pkey(struct ib_device *device,
						   u32 port_num, u16 index, u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = IB_DEFAULT_PKEY_FULL;
	return 0;
}

// modify urxe functions

// called by ib_modify_device
static int urxe_modify_device(struct ib_device *dev,
							  int mask, struct ib_device_modify *attr)
{
	struct urxe_dev *urxe = to_urdev(dev);

	if (mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID |
				 IB_DEVICE_MODIFY_NODE_DESC))
		return -EOPNOTSUPP;

	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		urxe->attr.sys_image_guid = cpu_to_be64(attr->sys_image_guid);

	if (mask & IB_DEVICE_MODIFY_NODE_DESC)
	{
		memcpy(urxe->ib_dev.node_desc,
			   attr->node_desc, sizeof(urxe->ib_dev.node_desc));
	}

	return 0;
}

// called by enable_device_and_get
static int urxe_enable_driver(struct ib_device *ib_dev)
{
	struct urxe_dev *urxe = container_of(ib_dev, struct urxe_dev, ib_dev);

	urxe_set_port_state(urxe);
	dev_info(&urxe->ib_dev.dev, "added %s\n", netdev_name(urxe->ndev));
	return 0;
}

/* free resources for a urxe device all objects created for this device must
 * have been destroyed
 */
void urxe_dealloc(struct ib_device *ib_dev)
{
	// NOTHING
}

static int urxe_port_immutable(struct ib_device *dev, u32 port_num,
							   struct ib_port_immutable *immutable)
{
	int err;
	struct ib_port_attr attr;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;

	err = ib_query_port(dev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

// called by rdma_port_get_link_layer
static enum rdma_link_layer urxe_get_link_layer(struct ib_device *dev,
					       u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

// called by ib_uverbs_add_one to add /sys/devices/virtual/infiniband_verbs/uverbs<>/ node
static int urxe_alloc_ucontext(struct ib_ucontext *ibuc, struct ib_udata *udata)
{
	// TODO
	return 0;
}

static void urxe_dealloc_ucontext(struct ib_ucontext *ibuc)
{
	// TODO
	return;
}

// exposed to sysfs node: /sys/class/infiniband/<name>/parent
static ssize_t parent_show(struct device *device,
			   struct device_attribute *attr, char *buf)
{
	struct urxe_dev *urxe =
		rdma_device_to_drv_device(device, struct urxe_dev, ib_dev);

	return sysfs_emit(buf, "%s\n", urxe_parent_name(urxe, 1));
}

static DEVICE_ATTR_RO(parent);

static struct attribute *urxe_dev_attributes[] = {
	&dev_attr_parent.attr,
	NULL
};

static const struct attribute_group urxe_attr_group = {
	.attrs = urxe_dev_attributes,
};

static const struct ib_device_ops urxe_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_URXE,
	.uverbs_abi_ver = URXE_UVERBS_ABI_VERSION,

	.alloc_hw_port_stats = urxe_ib_alloc_hw_port_stats,
	.alloc_ucontext = urxe_alloc_ucontext,
	.dealloc_driver = urxe_dealloc,
	.device_group = &urxe_attr_group,
	.dealloc_ucontext = urxe_dealloc_ucontext,
	.enable_driver = urxe_enable_driver,
	.get_port_immutable = urxe_port_immutable,
	.get_link_layer = urxe_get_link_layer,
	.get_hw_stats = urxe_ib_get_hw_stats,
	.modify_device = urxe_modify_device,
	.query_device = urxe_query_device,
	.query_pkey = urxe_query_pkey,
	.query_port = urxe_query_port,

	INIT_RDMA_OBJ_SIZE(ib_ucontext, urxe_ucontext, ibuc),
};

int urxe_register_device(struct urxe_dev *urxe, const char *ibdev_name)
{
	int err;
	struct ib_device *dev = &urxe->ib_dev;

	strscpy(dev->node_desc, "urxe", sizeof(dev->node_desc));

	dev->node_type = RDMA_NODE_IB_CA;
	dev->phys_port_cnt = 1;
	dev->num_comp_vectors = num_possible_cpus();
	dev->local_dma_lkey = 0;
	addrconf_addr_eui48((unsigned char *)&dev->node_guid,
						urxe->ndev->dev_addr);

	dev->uverbs_cmd_mask |= BIT_ULL(IB_USER_VERBS_CMD_POST_SEND) |
							BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ);

	ib_set_device_ops(dev, &urxe_dev_ops);
	err = ib_device_set_netdev(&urxe->ib_dev, urxe->ndev, 1);
	if (err)
		return err;

	err = ib_register_device(dev, ibdev_name, NULL);
	if (err)
		pr_warn("%s failed with error %d\n", __func__, err);

	/*
	 * Note that urxe may be invalid at this point if another thread
	 * unregistered it.
	 */
	return err;
}
