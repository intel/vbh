#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>

#include "hypervisor_introspection.h"
#include "vbh_controller.h"
#include "vmx_device.h"
#include "vbh_controller_ds.h"
#include "ring_buffer.h"

#define SUCCESS(x)		(x==0)

#define NUM_EVENT_HANDLERS		4

enum EPT_PROT_MEM_TYPE_e
{
	MEM_RANGE = 0,
	KERNEL_CODE = 1,
};

extern void signal_ready_to_read(void);
extern int configure_kernel_code_protection(__u64 prot);

int blocked_read = 0;

static DEFINE_SPINLOCK(pending_policy_lock);

static struct task_struct *controller_handler_thread;

static DECLARE_BITMAP(controller_pending_requests, 64);

//static wait_queue_head_t controller_event_wq;

static struct hvi_event_callback logger_event_handlers[NUM_EVENT_HANDLERS];

// list of log buffers which are available for logging
static __percpu struct list_head *available_list;
static __percpu rwlock_t *available_list_lock;   			// lock for available list, only used when manipulate list

// list of policies to be processed
LIST_HEAD(pending_policy_list);

// list of log buffers which are ready to be transferred to user space
struct list_head *ready_list;
rwlock_t ready_list_lock;  			// lock for ready list, only used when manipulate list

rbuf_handle_t vmx_ring_buffer;

void reset_msg_logs(void)
{
	int cpu;
	struct list_head *p_available;
	struct vbh_msg *msg_entry, *msg_temp;
	
	list_for_each_entry_safe(msg_entry, msg_temp, ready_list, list)
	{
		// delete it from ready_list
		list_del(&msg_entry->list);
		
		// Add it back to available_list
		p_available = per_cpu_ptr(available_list, msg_entry->vcpu);
	}
	
	// reset every msg buffer
	for_each_online_cpu(cpu)
	{
		p_available = per_cpu_ptr(available_list, cpu);
		list_for_each_entry(msg_entry, p_available, list)
		{
			msg_entry->size = LOG_BUFFER_SIZE;
		}
	}
}

// delete pmsg from ready_list and add it to available_list
void move_msg_logs(struct vbh_msg *pmsg)
{
	int cpu;
	struct list_head *p_available;
	
	cpu = pmsg->vcpu;
	p_available = per_cpu_ptr(available_list, cpu);

	if (p_available)
	{
		printk(KERN_ERR "<vbh_controller> move_list: number=%d, vcpu=%d\n", pmsg->number, pmsg->vcpu);
		pmsg->size = LOG_BUFFER_SIZE;
		list_del(&pmsg->list);
		list_add_tail(&pmsg->list, p_available);
	}		
}

void append_to_pending_policy_list(struct list_head *policy)
{
	spin_lock(&pending_policy_lock);
	
	list_add_tail(policy, &pending_policy_list);
	
	spin_unlock(&pending_policy_lock);
}

void raise_request(int request)
{
	set_bit(request, controller_pending_requests);
}

void process_readall_request(void)
{
	struct list_head *p_available;
	struct vbh_msg *pbuf;
	int cpu;
	
	for_each_online_cpu(cpu)
	{
		p_available = per_cpu_ptr(available_list, cpu);
		
		pbuf = list_first_entry_or_null(p_available, struct vbh_msg, list);
	
		// append all buffers that have logging data
		// to ready_list
		if (pbuf && pbuf->size < LOG_BUFFER_SIZE)
		{
			list_del(&pbuf->list);
	
			// add it to the end of ready_list
			list_add_tail(&pbuf->list, ready_list);
		}
	}
}

static int logger_vmcall_event_callback(hv_event_e type, unsigned char *data, int size, int *allow)
{
	struct k_vmx_control *ctrl;
	struct list_head *p_list;
	
	hvi_request_vcpu_pause(0);
	
	list_for_each(p_list, &pending_policy_list)
	{
		ctrl = list_entry(p_list, struct k_vmx_control, list);
		
		switch (ctrl->control_type)
		{
			case CONTROL_CR_WRITE:
				printk(KERN_ERR "<vbh_controller>: vmcall_event_callback:  Receive CONTROL_CR_WRITE policy: cr=%d, enable=%s.\n",
							ctrl->control_cr.cr, ctrl->control_cr.enable?"true":"false");
				hvi_modify_cr_write_exit(ctrl->control_cr.cr, ctrl->control_cr.mask, ctrl->control_cr.enable);
				break;
			case CONTROL_MSR_WRITE:
				printk(KERN_ERR "<vbh_controller>: vmcall_event_callback:  Receive CONTROL_MSR_WRITE policy: msr=%d, enable=%s.\n",
							ctrl->control_msr.msr,
							ctrl->control_msr.enable?"true":"false");
				hvi_modify_msr_write_exit(ctrl->control_msr.msr, ctrl->control_msr.enable);
				break;
			case CONTROL_EPT_PROT:
				printk(KERN_ERR "<vbh_controller>: vmcall_event_callback: \
						Receive CONTROL_EPT_PROT policy: mem_type=%d, prot=0x%x, start_mem=0x%llu, end_mem=0x%llu.\n",
							ctrl->control_ept_prot.mem_type,
							ctrl->control_ept_prot.prot,
							ctrl->control_ept_prot.start_mem,
							ctrl->control_ept_prot.end_mem);

				switch (ctrl->control_ept_prot.mem_type)
				{
				case KERNEL_CODE:
					configure_kernel_code_protection(ctrl->control_ept_prot.prot);
					break;
				default:
					printk(KERN_ERR "<vbh_controller>: Named Mem <%d> not implemented.\n", ctrl->control_ept_prot.mem_type);
					break;
				}

			default:
				printk(KERN_ERR "<vbh_controller>: vmcall_event_callback:  Unknown ploicy.\n");
				break;
		}		
	}
	
	hvi_request_vcpu_resume();
	
	return 0;
}

static struct vbh_msg* get_available_buffer(int required_size, int *pos)
{
	struct vbh_msg *pbuf;
	struct list_head *p_list;
	
	// Get the buffer for logging, start from the first	
	p_list = this_cpu_ptr(available_list);
	
	pbuf = list_first_entry_or_null(p_list, struct vbh_msg, list);
	
	// if there is a buffer and enough space available
	if(pbuf != NULL)
	{
		if (required_size < pbuf->size)
		{
			*pos = LOG_BUFFER_SIZE - pbuf->size;
			return pbuf;
		}

		// get next available buffer
		// remove from the available_list
		list_del(&pbuf->list);

		// add it to the end of ready_list
		list_add_tail(&pbuf->list, ready_list);

		// get next available buffer
		pbuf = list_first_entry_or_null(p_list, struct vbh_msg, list);

		*pos = 0;

		raise_request(PENDING_REQUEST_BUFFER_READY);
	}
	else
	{
		*pos = 0;

		printk(KERN_ERR "<vbh_controller> get_available_buffer:  No buffer is available on cpu-[%d]", smp_processor_id());
	}

	return pbuf;
}

static int logger_cr_write_event_callback(hv_event_e type, unsigned char *data, int size, int *allow)
{
	int pos, data_size;

	struct vbh_msg *pbuf = NULL;

	struct vmx_event* cr_event;

	struct hvi_event_cr *p;

	data_size = sizeof(struct vmx_event);

	p = (struct hvi_event_cr*)data;

	if (blocked_read)
	{
		pbuf = get_available_buffer(data_size, &pos);

		if (pbuf == NULL)
			return 0;

		cr_event = (struct vmx_event *)(pbuf + pos);

		pbuf->size -= data_size;
	}
	else
		cr_event = ring_buf_insert(vmx_ring_buffer);

	cr_event->metadata.event_type = cr_write;
	cr_event->metadata.payload_size = sizeof(cr_event->cr_event);
	cr_event->metadata.vcpu = smp_processor_id();

	cr_event->cr_event.cr = p->cr;
	cr_event->cr_event.new_value = p->new_value;
	cr_event->cr_event.old_value = p->old_value;

	if (!blocked_read)
		signal_ready_to_read();

	*allow = 0;

	return 0;
}

static int logger_msr_write_event_callback(hv_event_e type, unsigned char* data, int size, int *allow)
{
	int pos, data_size;

	struct vbh_msg *pbuf = NULL;

	struct vmx_event* msr_event;

	struct hvi_event_msr *p;

	data_size = sizeof(struct vmx_event);

	p = (struct hvi_event_msr*)data;

	if (blocked_read)
	{
		pbuf = get_available_buffer(data_size, &pos);

		if (pbuf == NULL)
			return 0;

		msr_event = (struct vmx_event*)(pbuf->msg + pos);

		pbuf->size -= data_size;
	}
	else
	{
		msr_event = ring_buf_insert(vmx_ring_buffer);
	}

	msr_event->metadata.event_type = msr_write;
	msr_event->metadata.payload_size = sizeof(msr_event->msr_event);
	msr_event->metadata.vcpu = smp_processor_id();

	msr_event->msr_event.msr = p->msr;
	msr_event->msr_event.new_value = p->new_value;
	msr_event->msr_event.old_value = p->old_value;

	if (blocked_read)
		printk(KERN_ERR "<vbh_controller> %s on cpu-[%d]: put data on buff number = %d, buff vcpu = %d, size = %d, remaining buffer size = %d.\n",
			__func__,
			smp_processor_id(),
			pbuf->number,
			pbuf->vcpu,
			data_size,
			pbuf->size);
	else
	{
		signal_ready_to_read();

		printk(KERN_ERR "<vbh_controller> %s on cpu-[%d]: put data on ring buffer: size = %lu.\n",
			__func__,
			smp_processor_id(),
			ring_buf_size(vmx_ring_buffer));
	}

	return 0;
}

static int logger_ept_violation_event_callback(hv_event_e type, unsigned char* data, int size, int *allow)
{
	int pos, data_size;

	struct vbh_msg *pbuf = NULL;

	struct vmx_event* event;

	struct hvi_event_ept_violation *p;

	data_size = sizeof(struct vmx_event);

	p = (struct hvi_event_ept_violation*)data;

	if (blocked_read)
	{
		pbuf = get_available_buffer(data_size, &pos);

		if (pbuf == NULL)
			return 0;

		event = (struct vmx_event*)(pbuf->msg + pos);

		pbuf->size -= data_size;
	}
	else
	{
		event = ring_buf_insert(vmx_ring_buffer);
	}

	event->metadata.event_type = ept_violation;
	event->metadata.payload_size = sizeof(event->ept_violation);
	event->metadata.vcpu = smp_processor_id();

	event->ept_violation.g_rip = p->g_rip;
	event->ept_violation.g_rsp = p->g_rsp;
	event->ept_violation.gla = p->gla;
	event->ept_violation.gpa = p->gpa;
	event->ept_violation.mode = p->mode;

	if (blocked_read)
		printk(KERN_ERR "<vbh_controller> %s on cpu-[%d]: put data on buff number = %d, buff vcpu = %d, size = %d, remaining buffer size = %d.\n",
			__func__,
			smp_processor_id(),
			pbuf->number,
			pbuf->vcpu,
			data_size,
			pbuf->size);
	else
	{
		signal_ready_to_read();

		printk(KERN_ERR "<vbh_controller> %s on cpu-[%d]: put data on ring buffer: size = %lu.\n",
			__func__,
			smp_processor_id(),
			ring_buf_size(vmx_ring_buffer));
	}

	return 0;		
}

void unregister_vbh_event_handlers(void)
{
	int i;

	for (i = 0; i < sizeof(logger_event_handlers) / sizeof(struct hvi_event_callback); i++)
	{
		if (logger_event_handlers[i].callback != NULL)
			hvi_unregister_event_callback(logger_event_handlers[i].event);
	}
}

int register_vbh_event_handlers(void)
{
	int result;

	logger_event_handlers[0].event = vmcall;
	logger_event_handlers[0].callback = logger_vmcall_event_callback;

	logger_event_handlers[1].event = cr_write;
	logger_event_handlers[1].callback = logger_cr_write_event_callback;

	logger_event_handlers[2].event = msr_write;
	logger_event_handlers[2].callback = logger_msr_write_event_callback;
	
	logger_event_handlers[3].event = ept_violation;
	logger_event_handlers[3].callback = logger_ept_violation_event_callback;

	result = hvi_register_event_callback(logger_event_handlers, sizeof(logger_event_handlers) / sizeof(struct hvi_event_callback));

	return result;
}

static int vbh_controller_handler(void *data)
{
	int cpu;
	int quit = 0;
	struct k_vmx_control *entry, *temp;

	do
	{
		//wait_event_interruptible(controller_event_wq, !bitmap_empty(controller_pending_requests, 64));

		cpu = get_cpu();

		if (test_and_clear_bit(PENDING_REQUEST_UNLOAD, controller_pending_requests))
		{
			printk(KERN_ERR "<vbh_controller>: handles request: UNLOAD.\n");
			quit = 1;
		}

		if (test_and_clear_bit(PENDING_REQUEST_SET_POLICY, controller_pending_requests))
		{
			printk(KERN_ERR "<vbh_controller>: handles request: SET_POLICY.\n");

			spin_lock(&pending_policy_lock);
			asm_make_vmcall(0, NULL);

			list_for_each_entry_safe(entry, temp, &pending_policy_list, list)
			{
				list_del(&entry->list);

				kfree(entry);
			}
			spin_unlock(&pending_policy_lock);
		}

		if (test_and_clear_bit(PENDING_REQUEST_BUFFER_READY, controller_pending_requests))
		{
			printk(KERN_ERR "<vbh_controller>: handles request: BUFFER_READY.\n");

			signal_ready_to_read();
		}

		if (test_bit(PENDING_REQUEST_LOG_OFF, controller_pending_requests))
		{
			if (!blocked_read)
			{
				signal_ready_to_read();
				clear_bit(PENDING_REQUEST_LOG_OFF, controller_pending_requests);
				printk(KERN_ERR "<vbh_controller>: handles request: LOG_OFF. Kicks non-blocked read.\n");
			}
			else
			{
				if (!list_empty(ready_list))
					signal_ready_to_read();
				else
					clear_bit(PENDING_REQUEST_LOG_OFF, controller_pending_requests);
			}
		}

		put_cpu();

		schedule();

	} while (!kthread_should_stop() && !quit);

	printk(KERN_ERR "<vbh_controller>: event_handler stopped.\n");
	
	return 0;
}

static int init_msg_buffers(void)
{
	int i, vcpu;
	struct vbh_msg *buf;
	
	struct list_head *phead;
	
	available_list = alloc_percpu(struct list_head);
	
	if (!available_list)
		return -ENOMEM;
	
	available_list_lock = alloc_percpu(rwlock_t);
	
	if (!available_list_lock)
		return -ENOMEM;
	
	ready_list = kmalloc(sizeof(struct list_head), GFP_KERNEL);
	if (!ready_list)
		return -ENOMEM;
	
	INIT_LIST_HEAD(ready_list);
	
	for_each_online_cpu(vcpu)
	{
		phead = per_cpu_ptr(available_list, vcpu);
		
		INIT_LIST_HEAD(phead);
		
		for (i = 0; i < NUM_LOG_BUFFERS; i++)
		{
			buf = kmalloc(sizeof(struct vbh_msg), GFP_KERNEL);
		
			if (!buf)
				return -ENOMEM;
		
			buf->msg = kmalloc(LOG_BUFFER_SIZE, GFP_KERNEL);
		
			if (!buf->msg)
				return -ENOMEM;
		
			buf->number = i;
			buf->size = LOG_BUFFER_SIZE;
			buf->vcpu = vcpu;
		
			list_add_tail(&buf->list, phead);
		}
	}
	
	return 0;
}

static void clean_msg_buffers_internal(struct list_head *pcpu_list, rwlock_t* lock)
{
	struct vbh_msg *entry, *temp;
	
	write_lock(lock);
	
	if (pcpu_list)
	{		
		list_for_each_entry_safe(entry, temp, pcpu_list, list)
		{	
			list_del(&entry->list);
			kfree(entry->msg);
			kfree(entry);
		}
	}
	
	write_unlock(lock);
}

static void clean_log_buffers(void)
{
	int vcpu;
			
	struct list_head *_list_pcpu;
	
	rwlock_t *lock_pcpu;
	
	if (available_list && available_list_lock)
	{
		for_each_online_cpu(vcpu)
		{
			// clean available_list
			_list_pcpu = per_cpu_ptr(available_list, vcpu);
			lock_pcpu = per_cpu_ptr(available_list_lock, vcpu);
	
			clean_msg_buffers_internal(_list_pcpu, lock_pcpu);
		}
	
		free_percpu(available_list);
		free_percpu(available_list_lock);		
	}

	if (ready_list)
		kfree(ready_list);
}

static void clean_policies(void)
{
	struct k_vmx_control *entry, *temp;
	
	if (!list_empty(&pending_policy_list))
	{
		list_for_each_entry_safe(entry, temp, &pending_policy_list, list)
		{		
			list_del(&entry->list);
			kfree(entry);
		}
	}
}

static int __init vbh_controller_init(void)
{
	int ret = 0;
	
	int cpu;
	
	cpu = get_cpu();
	
	printk(KERN_ERR "%s size of vmx_control=%lu.\n", __func__, sizeof(struct vmx_control));
	
	printk(KERN_ERR "VMX_SWITCH_IOCTL_CONTROL_CR_READ size = 0x%lx.\n", VMX_SWITCH_IOCTL_CONTROL_CR_READ);
	printk(KERN_ERR "VMX_SWITCH_IOCTL_CONTROL_CR_WRITE size = 0x%lx.\n", VMX_SWITCH_IOCTL_CONTROL_CR_WRITE);
	printk(KERN_ERR "VMX_SWITCH_IOCTL_CONTROL_MSR_READ size = 0x%lx.\n", VMX_SWITCH_IOCTL_CONTROL_MSR_READ);
	printk(KERN_ERR "VMX_SWITCH_IOCTL_CONTROL_MSR_WRITE size = 0x%lx.\n", VMX_SWITCH_IOCTL_CONTROL_MSR_WRITE);
	printk(KERN_ERR "VMX_SWITCH_IOCTL_CONTROL_STOP_LOG size = 0x%x.\n", VMX_SWITCH_IOCTL_CONTROL_STOP_LOG);
	printk(KERN_ERR "VMX_SWITCH_IOCTL_CONTROL_START_LOG size = 0x%x.\n", VMX_SWITCH_IOCTL_CONTROL_START_LOG);
	printk(KERN_ERR "VMX_SWITCH_IOCTL_CONTROL_EPT_PROT size = 0x%lx.\n", VMX_SWITCH_IOCTL_CONTROL_EPT_PROT);
	
	if (!hvi_is_vbh_loaded())
	{
		ret = hvi_switch_to_nonroot();
	
		if (!SUCCESS(ret))
		{
			printk(KERN_ERR "<vbh_controller>: ERROR!  Failed to load vbh.\n");
			return 1;
		}
	}

	if (blocked_read)
		init_msg_buffers();
	else
	{
		vmx_ring_buffer = ring_buf_init(100);
	}
	
	//register_vbh_event_handlers();
//	logger_event_handlers[0].event = vmcall;
//	logger_event_handlers[0].callback = logger_vmcall_event_callback;
	
	controller_handler_thread = kthread_create(vbh_controller_handler, NULL, "vhb_controller_handler");
	
	wake_up_process(controller_handler_thread);
	
	ret = vmx_init_device();
	
	printk(KERN_ERR "<vbh_controller>: Hello World!\n");
	
	put_cpu();
	
	return 0;
}

static void __exit vbh_controller_exit(void)
{
	// remove vmx_device
	vmx_device_unload();
	
	// stop event handling thread
	set_bit(PENDING_REQUEST_UNLOAD, controller_pending_requests);
	kthread_stop(controller_handler_thread);
	
	// unregister callbacks
	unregister_vbh_event_handlers();
	
	// free msg buffers
	if (blocked_read)
		clean_log_buffers();
	else
		ring_buf_free(vmx_ring_buffer);
	
	// free policy list
	clean_policies();
		
	printk("<vbh_controller>: Goodbye, world!\n");
}

module_init(vbh_controller_init);
module_exit(vbh_controller_exit);
MODULE_LICENSE("GPL");
