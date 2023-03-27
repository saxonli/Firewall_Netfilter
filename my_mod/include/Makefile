obj-m += sha256.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
FILE_NAME_1 := "sha256.o"
FILE_NAME_2 := "sha256.o.cmd"

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	cp $(FILE_NAME_1) ../
	cp $(FILE_NAME_2) ../