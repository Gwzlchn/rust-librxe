#include <rdma/rdma_netlink.h>
#include <net/addrconf.h>
#include "urxe.h"
MODULE_DESCRIPTION("Userspace RDMA-RXE device managment");
MODULE_LICENSE("Dual BSD/GPL");

/* initialize urxe device parameters */
static void urxe_init_device_param(struct urxe_dev *urxe)
{
	pr_info("urxe init device params \n");
	urxe->max_inline_data = RXE_MAX_INLINE_DATA;

	urxe->attr.vendor_id = RXE_VENDOR_ID;
	urxe->attr.max_mr_size = RXE_MAX_MR_SIZE;
	urxe->attr.page_size_cap = RXE_PAGE_SIZE_CAP;
	urxe->attr.max_qp = RXE_MAX_QP;
	urxe->attr.max_qp_wr = RXE_MAX_QP_WR;
	urxe->attr.device_cap_flags = RXE_DEVICE_CAP_FLAGS;
	urxe->attr.kernel_cap_flags = IBK_ALLOW_USER_UNREG;
	urxe->attr.max_send_sge = RXE_MAX_SGE;
	urxe->attr.max_recv_sge = RXE_MAX_SGE;
	urxe->attr.max_sge_rd = RXE_MAX_SGE_RD;
	urxe->attr.max_cq = RXE_MAX_CQ;
	urxe->attr.max_cqe = (1 << RXE_MAX_LOG_CQE) - 1;
	urxe->attr.max_mr = RXE_MAX_MR;
	urxe->attr.max_mw = RXE_MAX_MW;
	urxe->attr.max_pd = RXE_MAX_PD;
	urxe->attr.max_qp_rd_atom = RXE_MAX_QP_RD_ATOM;
	urxe->attr.max_res_rd_atom = RXE_MAX_RES_RD_ATOM;
	urxe->attr.max_qp_init_rd_atom = RXE_MAX_QP_INIT_RD_ATOM;
	urxe->attr.atomic_cap = IB_ATOMIC_HCA;
	urxe->attr.max_mcast_grp = RXE_MAX_MCAST_GRP;
	urxe->attr.max_mcast_qp_attach = RXE_MAX_MCAST_QP_ATTACH;
	urxe->attr.max_total_mcast_qp_attach = RXE_MAX_TOT_MCAST_QP_ATTACH;
	urxe->attr.max_ah = RXE_MAX_AH;
	urxe->attr.max_srq = RXE_MAX_SRQ;
	urxe->attr.max_srq_wr = RXE_MAX_SRQ_WR;
	urxe->attr.max_srq_sge = RXE_MAX_SRQ_SGE;
	urxe->attr.max_fast_reg_page_list_len = RXE_MAX_FMR_PAGE_LIST_LEN;
	urxe->attr.max_pkeys = RXE_MAX_PKEYS;
	urxe->attr.local_ca_ack_delay = RXE_LOCAL_CA_ACK_DELAY;
	addrconf_addr_eui48((unsigned char *)&urxe->attr.sys_image_guid,
						urxe->ndev->dev_addr);

	urxe->max_ucontext = RXE_MAX_UCONTEXT;
}

/* initialize port attributes */
static void urxe_init_port_param(struct urxe_port *port)
{
	pr_info("urxe init port params \n");
	port->attr.state = IB_PORT_DOWN;
	port->attr.max_mtu = IB_MTU_4096;
	port->attr.active_mtu = IB_MTU_256;
	port->attr.gid_tbl_len = RXE_PORT_GID_TBL_LEN;
	port->attr.port_cap_flags = RXE_PORT_PORT_CAP_FLAGS;
	port->attr.max_msg_sz = RXE_PORT_MAX_MSG_SZ;
	port->attr.bad_pkey_cntr = RXE_PORT_BAD_PKEY_CNTR;
	port->attr.qkey_viol_cntr = RXE_PORT_QKEY_VIOL_CNTR;
	port->attr.pkey_tbl_len = RXE_PORT_PKEY_TBL_LEN;
	port->attr.lid = RXE_PORT_LID;
	port->attr.sm_lid = RXE_PORT_SM_LID;
	port->attr.lmc = RXE_PORT_LMC;
	port->attr.max_vl_num = RXE_PORT_MAX_VL_NUM;
	port->attr.sm_sl = RXE_PORT_SM_SL;
	port->attr.subnet_timeout = RXE_PORT_SUBNET_TIMEOUT;
	port->attr.init_type_reply = RXE_PORT_INIT_TYPE_REPLY;
	port->attr.active_width = RXE_PORT_ACTIVE_WIDTH;
	port->attr.active_speed = RXE_PORT_ACTIVE_SPEED;
	port->attr.phys_state = RXE_PORT_PHYS_STATE;
	port->mtu_cap = ib_mtu_enum_to_int(IB_MTU_256);
	port->subnet_prefix = cpu_to_be64(RXE_PORT_SUBNET_PREFIX);
}

/* initialize port state, note IB convention that HCA ports are always
 * numbered from 1
 */
static void urxe_init_ports(struct urxe_dev *urxe)
{
	struct urxe_port *port = &urxe->port;

	urxe_init_port_param(port);
	addrconf_addr_eui48((unsigned char *)&port->port_guid,
						urxe->ndev->dev_addr);
	spin_lock_init(&port->port_lock);
}

/* initialize urxe device state */
static void urxe_init(struct urxe_dev *urxe)
{
	/* init default device parameters */
	urxe_init_device_param(urxe);

	urxe_init_ports(urxe);

	mutex_init(&urxe->usdev_lock);
}

void urxe_set_mtu(struct urxe_dev *urxe, unsigned int ndev_mtu)
{
	struct urxe_port *port = &urxe->port;
	enum ib_mtu mtu;

	mtu = eth_mtu_int_to_enum(ndev_mtu);

	/* Make sure that new MTU in range */
	mtu = mtu ? min_t(enum ib_mtu, mtu, IB_MTU_4096) : IB_MTU_256;

	port->attr.active_mtu = mtu;
	port->mtu_cap = ib_mtu_enum_to_int(mtu);
}

/* called by ifc layer to create new urxe device.
 * The caller should allocate memory for urxe by calling ib_alloc_device.
 */
int urxe_add(struct urxe_dev *urxe, unsigned int mtu, const char *ibdev_name)
{
	urxe_init(urxe);
	urxe_set_mtu(urxe, mtu);

	return urxe_register_device(urxe, ibdev_name);
}

static int urxe_newlink(const char *ibdev_name, struct net_device *ndev)
{
	struct urxe_dev *exists;
	int err = 0;
	pr_info("new urxe device %s\t", ibdev_name);
	pr_info("based on net device %s\n", ndev->name);
	if (is_vlan_dev(ndev))
	{
		pr_err("urxe creation allowed on top of a real device only\n");
		err = -EPERM;
		goto err;
	}
	pr_info("check vlan success\n");

	exists = urxe_get_dev_from_net(ndev);
	if (exists)
	{
		ib_device_put(&exists->ib_dev);
		pr_err("already configured on %s\n", ndev->name);
		err = -EEXIST;
		goto err;
	}
	pr_info("current net device is free :%s\n", ndev->name);

	err = urxe_net_add(ibdev_name, ndev);
	if (err)
	{
		pr_err("failed to add %s\n", ndev->name);
		goto err;
	}
err:
	return err;
}

static struct rdma_link_ops urxe_link_ops = {
	.type = "urxe",
	.newlink = urxe_newlink,
};

static int __init urxe_module_init(void)
{
	int err;

	err = urxe_net_init();
	if (err)
		return err;

	rdma_link_register(&urxe_link_ops);
	pr_info("loaded\n");
	return 0;
}

static void __exit urxe_module_exit(void)
{
	rdma_link_unregister(&urxe_link_ops);
	ib_unregister_driver(RDMA_DRIVER_URXE);
	urxe_net_exit();

	pr_info("unloaded\n");
}

late_initcall(urxe_module_init);
module_exit(urxe_module_exit);

MODULE_ALIAS_RDMA_LINK("urxe");
