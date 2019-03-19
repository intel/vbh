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

struct kh_test_data
{
	int recv_cr0_write_event;
	int recv_cr4_write_event;
	int recv_msr_write_event;
	long old_cr0_val;
	long new_cr0_val;
	long restore_cr0_val;
	long old_cr4_val;
	long new_cr4_val;
	long restore_cr4_val;
	long old_msr_val;
	long new_msr_val;
	struct semaphore kh_test_sema;
	
	int should_allow_cr_write;
	int should_allow_msr_write;
};

static int done;

static DEFINE_PER_CPU(struct kh_test_data, test_data);

static struct task_struct **test_threads;

static struct hvi_event_callback dummy_event_handlers[NUM_EVENT_HANDLERS];

static void setup_test(void);
static void cleanup_test(void);

static inline unsigned long read_cr4(void)
{
	 unsigned long val;

	 asm volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));

	 return val;
}

static int do_test(void* data)
{
	u32 hi, lo;	
	unsigned long val;	
	int me;
	struct kh_test_data *this;
	
	me = smp_processor_id();	
	
	this = &per_cpu(test_data, me);
	
	down(&this->kh_test_sema);
		
	printk(KERN_ERR "[!TEST!]: CPU-[%d] test thread unlocked!\n", me);
	
	// TEST CASE #1: write to cr0 and disallow operation
	this->old_cr0_val = read_cr0();
	this->new_cr0_val = this->old_cr0_val & ~PG;
	this->should_allow_cr_write = 0;	
	printk(KERN_ERR "[!TEST!]-1 on cpu-%d: old_cr0_value = 0x%lx, new_cr0_value=0x%lx, allow=%d", me, this->old_cr0_val, this->new_cr0_val, this->should_allow_cr_write);
	
	write_cr0(this->new_cr0_val);
	
	// make sure new value is NOT written to the shadow register
	val = read_cr0();		
	assert(val == this->old_cr0_val);
	
	// TEST CASE #2: write to cr0 and allow operation
	this->old_cr0_val = read_cr0();
	this->new_cr0_val = this->old_cr0_val & ~PG;
	this->should_allow_cr_write = 1;	
	printk(KERN_ERR "[!TEST!]-2 on cpu-%d: old_cr0_value = 0x%lx, new_cr0_value=0x%lx, allow=%d", me, this->old_cr0_val, this->new_cr0_val, this->should_allow_cr_write);	
	
	write_cr0(this->new_cr0_val);
	
	// make sure new value is written to the shadow register
	val = read_cr0();		
	assert(val == this->new_cr0_val);
	
	// restore
	this->restore_cr0_val = this->old_cr0_val;
	
	// TEST CASE #3: write to cr4 and disallow operation
	this->old_cr4_val = read_cr4();
	this->new_cr4_val = this->old_cr4_val & ~SMEP;
	this->should_allow_cr_write = 0;
	printk(KERN_ERR "[!TEST!]-3 on cpu-%d: old_cr4_value = 0x%lx, new_cr4_value=0x%lx, allow=%d", me, this->old_cr4_val, this->new_cr4_val, this->should_allow_cr_write);
	
	__write_cr4(this->new_cr4_val);
	
	// make sure new value is NOT written to the shadow register
	val = read_cr4();
	assert(val == this->old_cr4_val);
	
	// TEST CASE #4: write to cr4 and allow operation
	this->old_cr4_val = read_cr4();
	this->new_cr4_val = this->old_cr4_val & ~SMEP;		
	this->should_allow_cr_write = 1;
	printk(KERN_ERR "[!TEST!]-4 on cpu-%d: old_cr4_value = 0x%lx, new_cr4_value=0x%lx, allow=%d", me, this->old_cr4_val, this->new_cr4_val, this->should_allow_cr_write);
	
	__write_cr4(this->new_cr4_val);
	
	// make sure new value is written to the shadow register
	val = read_cr4();
	assert(val == this->new_cr4_val);
	
	// restor
	this->restore_cr4_val = this->old_cr4_val;
	
	// TEST CASE #5: write to msr and disallow the operation
	rdmsr(MSR_, lo, hi);
		
	this->old_msr_val = (u64)hi << 32 | lo;
		
	// try to flip the NXE bit - bit 11
	this->new_msr_val = this->old_msr_val & ~(1 << 11);
	this->should_allow_msr_write = 0;
	printk(KERN_ERR "[!TEST!]-5 on cpu-%d: old_msr_value = 0x%lx, new_msr_value=0x%lx, allow=%d", me, this->old_msr_val, this->new_msr_val, this->should_allow_msr_write);
	
	//wrmsr(MSR_, (u32)(new_msr_val >> 32), (u32)new_msr_val);
	wrmsrl(MSR_, this->new_msr_val);

	// Assert new msr value is ignored
	rdmsr(MSR_, lo, hi);
	
	val = (u64)hi << 32 | lo;
	
	assert(val == this->old_msr_val);
	
	printk(KERN_ERR "[!TEST!]: test_thread on cpu-%d stopped.\n", me);
	
	return 0;
}

static int kh_test_cr_write_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	struct kh_test_data *this;
	int cpu;
	
	struct hvi_event_cr *cr_event = (struct hvi_event_cr*)data;
	
	cpu = smp_processor_id();
	
	this = &per_cpu(test_data, cpu);
	
	assert(size == sizeof(struct hvi_event_cr));
	
	assert(cr_event->cr == CR0 || cr_event->cr == CR4);
	
	if (cr_event->cr == CR0)
	{
		assert(cr_event->old_value == this->old_cr0_val);
		assert(cr_event->new_value == this->new_cr0_val);	
		
		this->recv_cr0_write_event++;
	}
	else if (cr_event->cr == CR4)
	{
		assert(cr_event->old_value == this->old_cr4_val);
		assert(cr_event->new_value == this->new_cr4_val);		
		
		this->recv_cr4_write_event++;
	}

	*allow = this->should_allow_cr_write;
	
	return 0;
}

static int kh_test_msr_write_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	struct kh_test_data *this = &per_cpu(test_data, smp_processor_id());
	
	struct hvi_event_msr *msr_event = (struct hvi_event_msr*)data;
	
	assert(size == sizeof(struct hvi_event_msr));
	
	assert(msr_event->msr == MSR_);
	
	assert(msr_event->old_value == this->old_msr_val);
	
	assert(msr_event->new_value == this->new_msr_val);	
	
	this->recv_msr_write_event++;
	
	*allow = this->should_allow_msr_write;
	
	return 0;
}

static int kh_test_set_policy(int is_enable)
{
	int result = -1;
	
	// enable cr_write_exit policy on cr0
	result = hvi_modify_cr_write_exit(CR0, PG, is_enable);
	assert(result == SUCCESS);

	// enable cr_write_exit policy on cr4
	result = hvi_modify_cr_write_exit(CR4, SMEP, is_enable);
	assert(result == SUCCESS);
	
	// enable msr_write_exit policy on msr
	result = hvi_modify_msr_write_exit(MSR_, is_enable);
	assert(result == SUCCESS);
	
	return 0;
}

static int kh_test_vmcall_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	int ret;

	printk(KERN_ERR "[!TEST!]kh_test_vmcall_event_handler: set_policy.\n");
	ret = hvi_request_vcpu_pause();
	
	assert(ret == SUCCESS);
	
	if (!done)
		kh_test_set_policy(1);
	else
		kh_test_set_policy(0);

	ret = hvi_request_vcpu_resume();
		
	assert(ret == SUCCESS);

	return 0;
}

static void cleanup_test(void)
{
	int cpu;
	struct kh_test_data *data_ptr;
	
	get_cpu();
	
	// unregister cr event handler so restoring cr value won't call into the event handler
	hvi_unregister_event_callback(cr_write);
	
	for_each_online_cpu(cpu)
	{
		data_ptr = per_cpu_ptr(&test_data, cpu);
		
		write_cr0(data_ptr->restore_cr0_val);
		
		__write_cr4(data_ptr->restore_cr4_val);
	}
	
	// unregister msr event handler
	hvi_unregister_event_callback(msr_write);
	
	// reset policy
	asm_make_vmcall(0, NULL);
	
	// unregister vmcall handler
	hvi_unregister_event_callback(vmcall);
	
	put_cpu();
}

static void setup_test(void)
{
	int online_cpus, cpu;
	struct task_struct *test_thread;
	
	struct kh_test_data *data_ptr;
		
	online_cpus = num_online_cpus();
	
	test_threads = kmalloc(sizeof(struct task_struct*) * online_cpus, GFP_KERNEL);
	
	for_each_online_cpu(cpu)
	{
		data_ptr = per_cpu_ptr(&test_data, cpu);
		
		sema_init(&data_ptr->kh_test_sema, 0);
		
		data_ptr->recv_cr0_write_event = 0;
		data_ptr->recv_cr4_write_event = 0;
		data_ptr->recv_msr_write_event = 0;
		
		test_thread = kthread_create(do_test, NULL, "kh-test-thread");
		
		test_threads[cpu] = test_thread;
		
		kthread_bind(test_thread, cpu);
		
		wake_up_process(test_thread);
	}
}

static int __init kernel_hardening_test_module_init(void)
{
	int cpu;
	
	struct kh_test_data *data_ptr;
	
	done = 0;
	
	// setup tests: create all test threads
	setup_test();
	
	// register a callback function
	dummy_event_handlers[0].event = vmcall;
	dummy_event_handlers[0].callback = kh_test_vmcall_event_handler;
	
	dummy_event_handlers[1].event = cr_write;
	dummy_event_handlers[1].callback = kh_test_cr_write_event_handler;
	
	dummy_event_handlers[2].event = msr_write;
	dummy_event_handlers[2].callback = kh_test_msr_write_event_handler;
	
	hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback));
	
	// vmcall to enter vmm so we can set policies
	asm_make_vmcall(0, NULL);
	
	// signal test kthread to run test
	for_each_online_cpu(cpu)
	{
		data_ptr = per_cpu_ptr(&test_data, cpu);
		up(&data_ptr->kh_test_sema);
	}


	return 0;
}

static void __exit kernel_hardening_test_module_exit(void)
{
	int cpu;
	
	struct kh_test_data *data_ptr;
	
	done = 1;
	
	printk(KERN_ERR "[!TEST!]: kernel_hardening_test_module stopping...\n");
	
	for_each_online_cpu(cpu)
	{
		data_ptr = per_cpu_ptr(&test_data, cpu);
		
		assert(data_ptr->recv_cr0_write_event == NUM_CR0_WRITE);
		assert(data_ptr->recv_cr4_write_event == NUM_CR4_WRITE);
		assert(data_ptr->recv_msr_write_event == NUM_MSR_WRITE);
	}
	
	cleanup_test();
	
	printk(KERN_ERR "[!TEST!]: Goodbye, world!\n");
}

module_init(kernel_hardening_test_module_init);
module_exit(kernel_hardening_test_module_exit);
