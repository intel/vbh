KERNEL_MODULE_NAME := vmx-switch
KERNEL_MODULE_OBJECT_FILE_LIST := kernelhardening.o ptable.o vmexit.o hypervisor_introspection.o guest_info.o vbh_events.o cpu_switch_debug.o hvi_kernel_protection.o vbh_rt.o vbh_setup.o
KERNELDIR:=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

INCLUDES = -I.

ccflags-y += $(INCLUDES) -ggdb -O0 -Wall

obj-m += vmx-switch.o

$(KERNEL_MODULE_NAME)-y += $(KERNEL_MODULE_OBJECT_FILE_LIST)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
