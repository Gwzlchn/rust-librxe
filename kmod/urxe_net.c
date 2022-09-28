#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/sch_generic.h>
#include <linux/netfilter.h>
#include <rdma/ib_addr.h>

#include "urxe.h"
#include "urxe_net.h"


int urxe_net_add(const char *ibdev_name, struct net_device *ndev)
{
	int err;
	struct urxe_dev *urxe = NULL;

	urxe = ib_alloc_device(urxe_dev, ib_dev);
	pr_info("alloc urxe at addr: %p", urxe);
	if (!urxe)
		return -ENOMEM;

	urxe->ndev = ndev;

	err = urxe_add(urxe, ndev->mtu, ibdev_name);
	if (err) {
		ib_dealloc_device(&urxe->ib_dev);
		return err;
	}

	return 0;
}


static void urxe_port_event(struct urxe_dev *urxe,
			   enum ib_event_type event)
{
	struct ib_event ev;

	ev.device = &urxe->ib_dev;
	ev.element.port_num = 1;
	ev.event = event;

	ib_dispatch_event(&ev);
}

/* Caller must hold net_info_lock */
void urxe_port_up(struct urxe_dev *urxe)
{
	struct urxe_port *port;

	port = &urxe->port;
	port->attr.state = IB_PORT_ACTIVE;

	urxe_port_event(urxe, IB_EVENT_PORT_ACTIVE);
	dev_info(&urxe->ib_dev.dev, "set active\n");
}

/* Caller must hold net_info_lock */
void urxe_port_down(struct urxe_dev *urxe)
{
	struct urxe_port *port;

	port = &urxe->port;
	port->attr.state = IB_PORT_DOWN;

	urxe_port_event(urxe, IB_EVENT_PORT_ERR);
	dev_info(&urxe->ib_dev.dev, "set down\n");
}

void urxe_set_port_state(struct urxe_dev *urxe)
{
	if (netif_running(urxe->ndev) && netif_carrier_ok(urxe->ndev))
		urxe_port_up(urxe);
	else
		urxe_port_down(urxe);
}


/*
 * this is required by rxe_cfg to match rxe devices in
 * /sys/class/infiniband up with their underlying ethernet devices
 */
const char *urxe_parent_name(struct urxe_dev *urxe, unsigned int port_num)
{
	return urxe->ndev->name;
}


static int urxe_notify(struct notifier_block *not_blk,
		      unsigned long event,
		      void *arg)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(arg);
	struct urxe_dev *urxe = urxe_get_dev_from_net(ndev);

	if (!urxe)
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_UNREGISTER:
		ib_unregister_device_queued(&urxe->ib_dev);
		break;
	case NETDEV_UP:
		urxe_port_up(urxe);
		break;
	case NETDEV_DOWN:
		urxe_port_down(urxe);
		break;
	case NETDEV_CHANGEMTU:
		pr_info("%s changed mtu to %d\n", ndev->name, ndev->mtu);
		urxe_set_mtu(urxe, ndev->mtu);
		break;
	case NETDEV_CHANGE:
		urxe_set_port_state(urxe);
		break;
	case NETDEV_REBOOT:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGENAME:
	case NETDEV_FEAT_CHANGE:
	default:
		pr_info("ignoring netdev event = %ld for %s\n",
			event, ndev->name);
		break;
	}

	ib_device_put(&urxe->ib_dev);
	return NOTIFY_OK;
}

static struct notifier_block urxe_net_notifier = {
	.notifier_call = urxe_notify,
};

void urxe_net_exit(void)
{
	unregister_netdevice_notifier(&urxe_net_notifier);
}

int urxe_net_init(void)
{
	int err = 0;
	err = register_netdevice_notifier(&urxe_net_notifier);
	if (err) {
		pr_err("Failed to register netdev notifier\n");
		goto err_out;
	}
	return 0;
err_out:
	urxe_net_exit();
	return err;
}

