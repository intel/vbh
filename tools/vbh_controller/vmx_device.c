#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/poll.h>

#include "vbh_controller_ds.h"
#include "vmx_device.h"
#include "vbh_controller.h"
#include "ring_buffer.h"

#define VMX_SWITCH_DEVICE_MINOR_NUM    MISC_DYNAMIC_MINOR

typedef enum
{
	LOG_UNINIT,
	LOG_ON,
	LOG_STOPPED
}log_state;

DECLARE_WAIT_QUEUE_HEAD(vmx_poll_wait);

static wait_queue_head_t read_ready_wait_queue;

static int vmx_switch_device_open;
static spinlock_t vmx_switch_device_lock;

static log_state _log_state;

extern int blocked_read;

static unsigned int vmx_poll_device(struct file *file, struct poll_table_struct *wait);

void signal_ready_to_read(void);

extern rbuf_handle_t vmx_ring_buffer;

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = vmx_open_device, 
	.read = vmx_read_device,
	.release = vmx_release_device,
	.unlocked_ioctl = vmx_device_ioctl,
	.poll = vmx_poll_device
};

static struct miscdevice vmx_switch_device = { 
	.minor = VMX_SWITCH_DEVICE_MINOR_NUM,
	.name = VMX_SWITCH_DEVICE_NAME,
	.fops = &fops
};

static void process_control_request(unsigned long arg, unsigned int cmd, int control_type)
{
	struct k_vmx_control *ctrl;
	
	ctrl = kmalloc(sizeof(struct k_vmx_control), GFP_KERNEL);
	
	if (!ctrl)
	{
		printk(KERN_ERR "<vbh_controller>: process_control_request: Failed to allocate memory.\n");
		return;
	}
		
	copy_from_user(ctrl, (void *)arg, _IOC_SIZE(cmd));
	
	ctrl->control_type = control_type;
	
	switch (control_type)
	{
	case CONTROL_CR_READ:
	case CONTROL_CR_WRITE:
		printk(KERN_ERR "<vmx_device> receive policy: %lu, cr = %d, mask = 0x%x, enable = %s, allow = %s\n",
			ctrl->control_type,
			ctrl->control_cr.cr,
			ctrl->control_cr.mask,
			ctrl->control_cr.enable == 1 ? "true" : "false",
			ctrl->control_cr.allow == 1 ? "true" : "false");
		append_to_pending_policy_list(&(ctrl->list));
	
		raise_request(PENDING_REQUEST_SET_POLICY);
		break;
		
	case CONTROL_MSR_READ:
	case CONTROL_MSR_WRITE:
		printk(KERN_ERR "<vmx_device> receive policy: %lu, msr = %d, enable = %s, allow = %s\n",
			ctrl->control_type,
			ctrl->control_msr.msr,
			ctrl->control_msr.enable == 1 ? "true" : "false",
			ctrl->control_msr.allow == 1 ? "true" : "false");
		
		append_to_pending_policy_list(&(ctrl->list));
	
		raise_request(PENDING_REQUEST_SET_POLICY);
		break;
	case CONTROL_EPT_PROT:
		printk(KERN_ERR "<vmx_device> receive policy: %lu.\n", ctrl->control_type);
		
		append_to_pending_policy_list(&(ctrl->list));
		
		raise_request(PENDING_REQUEST_SET_POLICY);
		
		break;
	default:
		printk(KERN_ERR "<vmx_device> Unknown policy: %lu.\n", ctrl->control_type);
		break;
	}
}

static void process_start_log_request(void)
{
	register_vbh_event_handlers();
	_log_state = LOG_ON;
}

static void process_stop_log_request(void)
{
	// unregister vbh event handling
	unregister_vbh_event_handlers();
	
	if (blocked_read)
		process_readall_request();
	
	_log_state = LOG_STOPPED;

	raise_request(PENDING_REQUEST_LOG_OFF);
}

long vmx_device_ioctl(struct file * f, unsigned int cmd, unsigned long arg)
{
	if (_IOC_TYPE(cmd) != VMX_SWITCH_MAGIC_NUM) return -EINVAL;
	
	if (!vmx_switch_device_open) return -ENODEV;	
	
	spin_lock(&vmx_switch_device_lock);	
	printk(KERN_ERR "<vbh_controller> ioctl: Accquire device lock.\n");
	
	switch (cmd)
	{
	case VMX_SWITCH_IOCTL_CONTROL_CR_WRITE:
		process_control_request(arg, cmd, CONTROL_CR_WRITE);	
		break;
		
	case VMX_SWITCH_IOCTL_CONTROL_CR_READ:
		process_control_request(arg, cmd, CONTROL_CR_WRITE);	
		break;
		
	case VMX_SWITCH_IOCTL_CONTROL_MSR_WRITE:
		process_control_request(arg, cmd, CONTROL_MSR_WRITE);
		break;
	
	case VMX_SWITCH_IOCTL_CONTROL_EPT_PROT:
		printk(KERN_ERR "<vbh_control>:  Receive EPT_NAMED_MEM ioctl.\n");
		process_control_request(arg, cmd, CONTROL_EPT_PROT);
		break;
		
	case VMX_SWITCH_IOCTL_CONTROL_STOP_LOG:
		printk(KERN_ERR "<vbh_control>:  Receive STOP_LOG ioctl.\n");
		process_stop_log_request();
		break;
	
	case VMX_SWITCH_IOCTL_CONTROL_START_LOG:
		printk(KERN_ERR "<vbh_control>: Receive START_LOG ioctl.\n");
		process_start_log_request();
		break;
		
	default:
		printk(KERN_ERR "<vbh_control>: Unknown IOCTL: %d.\n", cmd);
		break;
	}
	
	spin_unlock(&vmx_switch_device_lock);
	printk(KERN_ERR "<vbh_controller> ioctl: Release device lock.\n");
	
	return 0;
}

ssize_t vmx_blocked_read(struct file *f, char __user *buffer, size_t length, loff_t *offset)
{
	int bytes_read = 0;
	int ret;
	struct vbh_msg *pmsg;
	
	if (!vmx_switch_device_open) return -ENODEV;
	
	if (_log_state == LOG_STOPPED && list_empty(ready_list))
	{
		printk(KERN_ERR "<vbh_controller> read: logging is stopped and all logs are flushed.\n");
		return 0;
	}
	
	//ret = wait_event_interruptible(read_ready_wait_queue, !list_empty(ready_list) || (_log_state == LOG_STOPPED));
	ret = wait_event_interruptible(read_ready_wait_queue, !list_empty(ready_list));
	
	printk(KERN_ERR "<vbh_controller> read: wakes up on cpu-%d.\n", smp_processor_id());
	
	if (!vmx_switch_device_open) return -ENODEV;
	
//	if (_log_state == LOG_STOPPED && list_empty(ready_list))
//	{
//		printk(KERN_ERR "<vbh_controller> read: logging is stopped and all logs are flushed.\n");
//		return 0;
//	}
	
	spin_lock(&vmx_switch_device_lock);

	printk(KERN_ERR "<vbh_controller> read: Accquire device lock.\n");
	
	pmsg = list_first_entry_or_null(ready_list, struct vbh_msg, list);
	
	if (pmsg)
	{
		printk(KERN_ERR "<vbh_controller>: log buffer # = %d, vcpu = %d, receiving buffer len = %lu.\n", pmsg->number, pmsg->vcpu, length);	
	
		bytes_read = LOG_BUFFER_SIZE - pmsg->size;
		
		if (length >= bytes_read)
		{						
			copy_to_user(buffer, pmsg->msg, bytes_read);			
		}
		else
		{
			bytes_read = 0;
		}
		
		move_msg_logs(pmsg);
	}

	spin_unlock(&vmx_switch_device_lock);
	printk(KERN_ERR "<vbh_controller> read: Release device lock.\n");
	
	return bytes_read;
}

ssize_t vmx_non_blocked_read(struct file *f, char __user *buffer, size_t length, loff_t *offset)
{
	int bytes_read = 0;
	int remaing_space = 0;
	
	struct vmx_event *pcurrent;
	
	if (ring_buf_empty(vmx_ring_buffer))
		return 0;
	
	if (length <= 0)
		return 0;
	
	spin_lock(&vmx_switch_device_lock);
	
	// block copy if there is enough space
	bytes_read = ring_buf_copy_to_user(vmx_ring_buffer, buffer, length);
	
	if (bytes_read == 0)
	{
		remaing_space = length;
		
		while (!ring_buf_empty(vmx_ring_buffer))
		{
			if (remaing_space > sizeof(struct vmx_event))
			{				
				pcurrent = ring_buf_remove(vmx_ring_buffer);
				if (copy_to_user(&buffer[bytes_read], (char *)pcurrent, sizeof(struct vmx_event)) == 0)
				{
					bytes_read += sizeof(struct vmx_event);
					remaing_space -= sizeof(struct vmx_event);
				}
				else
					break;
			}
			else
			{
				break;
			}
		}
	}

	printk(KERN_ERR "<vbh_controller>: non blocked read = %d bytes.\n", bytes_read);
	
	spin_unlock(&vmx_switch_device_lock);
	
	return bytes_read;
}

ssize_t vmx_read_device(struct file *f, char __user *buffer, size_t length, loff_t *offset)
{	
	int bytes_read = 0;
	
	if (blocked_read == true)	
		bytes_read = vmx_blocked_read(f, buffer, length, offset);
	else
	{
		bytes_read = vmx_non_blocked_read(f, buffer, length, offset);
	}

	return bytes_read;
}

static unsigned int vmx_poll_device(struct file *file, struct poll_table_struct *wait)
{
	poll_wait(file, &vmx_poll_wait, wait);
	
	if (!ring_buf_empty(vmx_ring_buffer) || _log_state == LOG_STOPPED)
	{
		printk(KERN_ERR "<vbh_controller> %s data is ready to read.\n", __func__);
		return POLLIN | POLLRDNORM;
	}		
	
	return 0;
}

void signal_ready_to_read(void)
{
	if (blocked_read)
		wake_up_interruptible(&read_ready_wait_queue);
	else
		wake_up_interruptible(&vmx_poll_wait);
}

int vmx_open_device(struct inode * node, struct file * f)
{
	printk(KERN_ERR "<vmx_device> vmx_switch_open_device (%p, %p)\n", node, f);
	
	spin_lock(&vmx_switch_device_lock);
	
	if (vmx_switch_device_open)
	{
		spin_unlock(&vmx_switch_device_lock);
		return -EBUSY;
	}
	
	register_vbh_event_handlers();
	
	vmx_switch_device_open++;
	
	_log_state = LOG_UNINIT;
	
	spin_unlock(&vmx_switch_device_lock);
	
	return 0;
}

int vmx_init_device()
{
	int ret;
	
	ret = misc_register(&vmx_switch_device);
	
	if (ret)
	{
		printk(KERN_ERR "<vmx_device> Failed to create device: %s", vmx_switch_device.name);
		return ret;
	}
	
	init_waitqueue_head(&read_ready_wait_queue);
	
	spin_lock_init(&vmx_switch_device_lock);
	
	printk(KERN_ERR "<vmx_device> Register misc device: minor number = %d, device name = %s", vmx_switch_device.minor, vmx_switch_device.name);
	
	return ret;
}

int vmx_release_device(struct inode * node, struct file * f)
{
	spin_lock(&vmx_switch_device_lock);
	vmx_switch_device_open--;
	
	if (blocked_read)
		reset_msg_logs();
	else
		ring_buf_reset(vmx_ring_buffer);
	
	printk(KERN_ERR "<vmx_device> vmx_switch_release_device (%p, %p)\n", node, f);	
	spin_unlock(&vmx_switch_device_lock);
	return 0;
}

void vmx_device_unload()
{
	printk(KERN_ERR "<vmx_device> vmx_device_unload.\n");	
	misc_deregister(&vmx_switch_device);
}
