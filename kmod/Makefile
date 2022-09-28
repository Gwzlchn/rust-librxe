# SPDX-License-Identifier: GPL-2.0
obj-m += rdma_urxe.o

rdma_urxe-y := \
	urxe.o \
	urxe_verbs.o \
	urxe_net.o \
	urxe_hw_counters.o


PWD := $(CURDIR) 
KDIR ?= /lib/modules/`uname -r`/build
INSTALL_MOD_PATH ?= /

all: 
	$(MAKE) -C $(KDIR) M=$$PWD modules 

modules_install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
 
clean: 
	$(MAKE) -C $(KDIR) M=$$PWD clean  