VBH_SRC_DIR := ../../sources
TEST_SHARED_DIR := ../shared

KERNELDIR := /lib/modules/$(shell uname -r)/build

KERNEL_MODULE_NAME := vbh_test
KERNEL_MODULE_OBJECT_FILE_LIST := vcpu_management_tests_module.o
TEST_MODULE_SHARED_FILE_LIST := vmcall.o

obj-m := $(KERNEL_MODULE_NAME).o
$(KERNEL_MODULE_NAME)-y += $(KERNEL_MODULE_OBJECT_FILE_LIST) $(TEST_SHARED_DIR)/$(TEST_MODULE_SHARED_FILE_LIST)

 EXTRA_CFLAGS += -I$(PWD)/$(VBH_SRC_DIR) -I$(PWD)/$(TEST_SHARED_DIR)

ccflags-y := -ggdb -O0

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f $(PWD)/$(TEST_SHARED_DIR)/*.o $(PWD)/$(TEST_SHARED_DIR)/.*.cmd
