obj-m += namestack.o
namestack-objs := main.o af_name.o dns.o namecache.o address.o

EXTRA_CFLAGS := -DCONFIG_NAMESTACK_MODULE

# ordinary compiles:
#KERN_BUILD := /lib/modules/$(shell uname -r)/build
KERN_BUILD := ~/src/linux-2.6.27

all:
	make -C $(KERN_BUILD) M=$(PWD) modules

clean:
	make -C $(KERN_BUILD) M=$(PWD) clean
