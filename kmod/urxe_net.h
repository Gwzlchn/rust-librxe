#ifndef URXE_NET_H
#define URXE_NET_H

#include <net/sock.h>
#include <net/if_inet6.h>
#include <linux/module.h>

int urxe_net_add(const char *ibdev_name, struct net_device *ndev);


int urxe_net_init(void);
void urxe_net_exit(void);

#endif /* URXE_NET_H */
