#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>

#include <asm/msr-index.h>

#include "hypervisor_introspection.h"
#include "vmx_common.h"
#include "vbh_test_shared.h"

MODULE_LICENSE("Proprietary");

#define		SUCCESS						0

#define		CR0							0
#define		CR4							4
#define		MSR_						MSR_EFER		// MSR_PLATFORM_INFO

#define		NUM_EVENT_HANDLERS			3

#define		NUM_CR0_WRITE				2
#define		NUM_CR4_WRITE				2
#define		NUM_MSR_WRITE				1

static int recv_cr0_write_event, recv_cr4_write_event, recv_msr_write_event;

static long volatile old_cr0_val; 
static long volatile new_cr0_val;
static long volatile old_cr4_val;
static long volatile new_cr4_val;
static long volatile old_msr_val;
static long volatile new_msr_val;

static int should_allow_cr_write;
static int should_allow_msr_write;

static struct semaphore kh_test_sema;

struct task_struct* thread_ptr;

static struct hvi_event_callback dummy_event_handlers[NUM_EVENT_HANDLERS];

static inline unsigned long read_cr4(void)
{
	 unsigned long val;

	 asm volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));

	 return val;
}

static int worker_thread(void* data)
{
	u32 hi, lo;
	
	unsigned long val;
	
	down(&kh_test_sema);
		
	printk(KERN_ERR "kernel_hardening_test_module: worker_thread thread unlocked!\n");
	
	// TEST CASE #1: write to cr0 and disallow operation
	old_cr0_val = read_cr0();
	new_cr0_val = old_cr0_val & ~PG;
	should_allow_cr_write = 0;	
	printk(KERN_ERR "kernel_hardening_test_module: old_cr0_value = 0x%lx, new_cr0_value=0x%lx, allow=%d", old_cr0_val, new_cr0_val, should_allow_cr_write);
	
	write_cr0(new_cr0_val);
	
	// make sure new value is NOT written to the shadow register
	val = read_cr0();		
	assert(val == old_cr0_val);
	
	// TEST CASE #2: write to cr0 and allow operation
	old_cr0_val = read_cr0();
	new_cr0_val = old_cr0_val & ~PG;
	should_allow_cr_write = 1;	
	printk(KERN_ERR "kernel_hardening_test_module: old_cr0_value = 0x%lx, new_cr0_value=0x%lx, allow=%d", old_cr0_val, new_cr0_val, should_allow_cr_write);	
	
	write_cr0(new_cr0_val);
	
	// make sure new value is written to the shadow register
	val = read_cr0();		
	assert(val == new_cr0_val);
	
	// TEST CASE #3: write to cr4 and disallow operation
	old_cr4_val = read_cr4();
	new_cr4_val = old_cr4_val & ~SMEP;
	should_allow_cr_write = 0;
	printk(KERN_ERR "kernel_hardening_test_module: old_cr4_value = 0x%lx, new_cr4_value=0x%lx, allow=%d", old_cr4_val, new_cr4_val, should_allow_cr_write);
	
	__write_cr4(new_cr4_val);
	
	// make sure new value is NOT written to the shadow register
	val = read_cr4();
	assert(val == old_cr4_val);
	
	// TEST CASE #4: write to cr4 and allow operation
	old_cr4_val = read_cr4();
	new_cr4_val = old_cr4_val & ~SMEP;		
	should_allow_cr_write = 1;
	printk(KERN_ERR "kernel_hardening_test_module: old_cr4_value = 0x%lx, new_cr4_value=0x%lx, allow=%d", old_cr4_val, new_cr4_val, should_allow_cr_write);
	
	__write_cr4(new_cr4_val);
	
	// make sure new value is written to the shadow register
	val = read_cr4();
	assert(val == new_cr4_val);
	
	// TEST CASE #5: write to msr and disallow the operation
	rdmsr(MSR_, lo, hi);
		
	old_msr_val = (u64)hi << 32 | lo;
		
	// try to flip the NXE bit - bit 11
	new_msr_val = old_msr_val & ~(1 << 11);
	should_allow_msr_write = 0;
	printk(KERN_ERR "kernel_hardening_test_module: old_msr_value = 0x%lx, new_msr_value=0x%lx, allow=%d", old_msr_val, new_msr_val, should_allow_msr_write);
	
	//wrmsr(MSR_, (u32)(new_msr_val >> 32), (u32)new_msr_val);
	wrmsrl(MSR_, new_msr_val);

	// Assert new msr value is ignored
	rdmsr(MSR_, lo, hi);
	
	val = (u64)hi << 32 | lo;
	
	assert(val == old_msr_val);
	
	printk(KERN_ERR "kernel_hardening_test_module: worker_thread thread stopping...\n");
	
	return 0;
}

static int kh_test_cr_write_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	struct hvi_event_cr *cr_event = (struct hvi_event_cr*)data;
	
	assert(size == sizeof(struct hvi_event_cr));
	
	assert(cr_event->cr == CR0 || cr_event->cr == CR4);
	
	if (cr_event->cr == CR0)
	{
		assert(cr_event->old_value == old_cr0_val);
		assert(cr_event->new_value == new_cr0_val);	
		
		recv_cr0_write_event++;
	}
	else if (cr_event->cr == CR4)
	{
		assert(cr_event->old_value == old_cr4_val);
		assert(cr_event->new_value == new_cr4_val);		
		
		recv_cr4_write_event++;
	}

	*allow = should_allow_cr_write;
	
	return 0;
}

static int kh_test_msr_write_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	struct hvi_event_msr *msr_event = (struct hvi_event_msr*)data;
	
	assert(size == sizeof(struct hvi_event_msr));
	
	assert(msr_event->msr == MSR_);
	
	assert(msr_event->old_value == old_msr_val);
	
	assert(msr_event->new_value == new_msr_val);	
	
	recv_msr_write_event++;
	
	*allow = should_allow_msr_write;
	
	return 0;
}

static int kh_test_set_policy(void)
{
	int result = -1;
	
	// enable cr_write_exit policy on cr0
	result = hvi_modify_cr_write_exit(CR0, PG, 1);
	assert(result == SUCCESS);

	// enable cr_write_exit policy on cr4
	result = hvi_modify_cr_write_exit(CR4, SMEP, 1);
	assert(result == SUCCESS);
	
	// enable msr_write_exit policy on msr
	result = hvi_modify_msr_write_exit(MSR_, 1);
	assert(result == SUCCESS);
	
	return 0;
}

static int kh_test_vmcall_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	kh_test_set_policy();
	
	return 0;
}

static int __init kernel_hardening_test_module_init(void)
{	
	
	recv_cr0_write_event = 0;
	recv_cr4_write_event = 0;
	recv_msr_write_event = 0;
	
	// register a callback function
	dummy_event_handlers[0].event = vmcall;
	dummy_event_handlers[0].callback = kh_test_vmcall_event_handler;
	
	dummy_event_handlers[1].event = cr_write;
	dummy_event_handlers[1].callback = kh_test_cr_write_event_handler;
	
	dummy_event_handlers[2].event = msr_write;
	dummy_event_handlers[2].callback = kh_test_msr_write_event_handler;
	
	hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback));
	
	sema_init(&kh_test_sema, 1);
	
	thread_ptr = kthread_create(worker_thread, NULL, "kh-test-worker-thread");
	wake_up_process(thread_ptr);
	
	// vmcall to enter vmm so we can set policies
	asm_make_vmcall(0, NULL);
	
	// signal worker kthread to continue
	up(&kh_test_sema);

	return 0;
}

static void __exit kernel_hardening_test_module_exit(void)
{
	int i;
	assert(recv_cr0_write_event == NUM_CR0_WRITE);
	assert(recv_cr4_write_event == NUM_CR4_WRITE);
	assert(recv_msr_write_event == NUM_MSR_WRITE);
	
//	if (thread_ptr)
//		kthread_stop(thread_ptr);
	
	printk(KERN_ERR "kernel_hardening_test_module: worker thread stopped.\n");
	
	for (i = 0; i < sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback); i++)
	{
		if (dummy_event_handlers[i].callback != NULL)
			hvi_unregister_event_callback(dummy_event_handlers[i].event);
	}
	
	printk(KERN_ERR "kernel_hardening_test_module: Goodbye, world!\n");
}

module_init(kernel_hardening_test_module_init);
module_exit(kernel_hardening_test_module_exit);
