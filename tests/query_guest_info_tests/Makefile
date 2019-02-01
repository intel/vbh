VBH_SRC_DIR := $(PWD)/../../sources
TEST_SHARED_DIR := ../shared

KERNELDIR := /lib/modules/$(shell uname -r)/build

TEST_MODULE_NAME := vbh_test
TEST_MODULE_OBJECT_FILE_LIST := query_guest_info_tests_module.o
TEST_MODULE_SHARED_FILE_LIST := vmcall.o

obj-m := $(TEST_MODULE_NAME).o
$(TEST_MODULE_NAME)-y := $(TEST_MODULE_OBJECT_FILE_LIST) $(TEST_SHARED_DIR)/$(TEST_MODULE_SHARED_FILE_LIST)

EXTRA_CFLAGS += -I$(VBH_SRC_DIR) -I$(PWD)/$(TEST_SHARED_DIR)

ccflags-y := -ggdb -O0

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f $(PWD)/$(TEST_SHARED_DIR)/*.o $(PWD)/$(TEST_SHARED_DIR)/.*.cmd
