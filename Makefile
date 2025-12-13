KVER := $(shell uname -r)

M := $(shell pwd)

KDIR := /lib/modules/$(KVER)/build

obj-m += syscall_hooking.o

all:
	make -C $(KDIR) M=$(M) modules

clean:
	$(MAKE) -C $(KDIR) M=$(M) clean
