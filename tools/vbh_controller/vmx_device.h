#pragma once
#ifndef __VMX_DEVICE_H
#define __VMX_DEVICE_H

#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/wait.h>

enum vmx_control_e
{
	CONTROL_CR_WRITE,
	CONTROL_CR_READ,
	CONTROL_MSR_WRITE,
	CONTROL_MSR_READ,
	CONTROL_EPT_PROT
};

struct vmx_control_cr {
	__u8 enable;
	__u8 allow;
	__u32 mask;
	__u32 cr;
};

struct vmx_control_msr {
	__u8 enable;
	__u8 allow;
	__u32 msr;
};

struct vmx_control_ept_prot
{
	__u64 start_mem;
	__u64 end_mem;
	__u32 prot;
	__u16 mem_type;
	__u16 allow;
};

struct vmx_control
{
	unsigned long control_type;
	union
	{
		struct vmx_control_cr control_cr;
		struct vmx_control_msr control_msr;
		struct vmx_control_ept_prot control_ept_prot;
	};
};

struct k_vmx_control
{
	unsigned long control_type;
	union
	{
		struct vmx_control_cr control_cr;
		struct vmx_control_msr control_msr;
		struct vmx_control_ept_prot control_ept_prot;
	};
	struct list_head list;
};

long vmx_device_ioctl(struct file * f, unsigned int cmd, unsigned long arg);
int vmx_open_device(struct inode * node, struct file * f);
int vmx_release_device(struct inode * node, struct file * f);
ssize_t vmx_read_device(struct file * f, char __user * buffer, size_t length, loff_t * offset);
int vmx_init_device(void);
void vmx_device_unload(void);
	
#define VMX_SWITCH_MAGIC_NUM			'k'

#define VMX_SWITCH_DEVICE_NAME "vmx_switch"

#define READALL_BUF_LEN					16*1024 // Maximum supported by ioctl

#define VMX_SWITCH_IOCTL_CONTROL_CR_READ _IOW(VMX_SWITCH_MAGIC_NUM, 16, struct vmx_control )

#define VMX_SWITCH_IOCTL_CONTROL_CR_WRITE _IOW(VMX_SWITCH_MAGIC_NUM, 17, struct vmx_control )

#define VMX_SWITCH_IOCTL_CONTROL_MSR_READ _IOW(VMX_SWITCH_MAGIC_NUM, 18, struct vmx_control)

#define VMX_SWITCH_IOCTL_CONTROL_MSR_WRITE _IOW(VMX_SWITCH_MAGIC_NUM, 19, struct vmx_control)

#define VMX_SWITCH_IOCTL_CONTROL_START_LOG	_IO(VMX_SWITCH_MAGIC_NUM, 20)

#define VMX_SWITCH_IOCTL_CONTROL_STOP_LOG	_IO(VMX_SWITCH_MAGIC_NUM, 21)

#define VMX_SWITCH_IOCTL_CONTROL_EPT_PROT		_IOW(VMX_SWITCH_MAGIC_NUM, 22, struct vmx_control)

#define VMX_SWITCH_IOCTL_CONTROL_BLOCK_READ	_IO(VMX_SWITCH_MAGIC_NUM, 23)

#endif // !__VMX_DEVICE_H
