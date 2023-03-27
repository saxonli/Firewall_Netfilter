obj-m += WJ_firewall.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
MOD_NAME := "WJ_firewall.ko"

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	cp $(MOD_NAME) "../bin/"