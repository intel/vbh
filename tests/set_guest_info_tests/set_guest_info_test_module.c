#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <asm/paravirt.h>
#include <asm/vmx.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/spinlock.h>

#include "vbh_test_shared.h"
#include "hypervisor_introspection.h"
#include "vmx_common.h"

MODULE_LICENSE("Proprietary");

#define CHECK_BIT_IS_SET(var,pos) (((var) & (1<<(pos))) >> pos)

#define FLAG_IF_MASK	0x0200
#define FLAG_IF			9

static DEFINE_SPINLOCK(rflag_test_spin_lock);

static struct hvi_event_callback dummy_event_handlers[1];

static struct task_struct *vmcall_thread;

static struct semaphore rflags_test_sema_block_vmcall;
static struct semaphore rflags_test_sema_block_main;

static unsigned long rip;
static int cpu_under_test;

static int test_rflags_on_remote_cpu;

static int set_rflags_test_make_vmcall(void* data);

static long get_rflag(void)
{
	volatile long flag;
	
	__asm__ __volatile__("pushf \n\t"
						"popq %%rax\n\t"
						"movq %%rax, %0\n\t"
						: "=m"(flag)
						:
						: "%rax"
		);
	
	return flag;
}

static int set_rip_test_event_handler(hv_event_e type, unsigned char *data, int size, int* allow)
{	
	int ret;
	
	rip -= 4;	
	
	// pause all vcpus
	ret = hvi_request_vcpu_pause();
	
	assert(ret == 0);
		
	// set guest rip
	ret = hvi_set_register_rip(cpu_under_test, rip);
	assert(ret == 0);
	
	ret = hvi_request_vcpu_resume();
	assert(ret == 0);
	
	return 0;
}

static void run_set_rip_test(void)
{
	int expected = 101;
	int actual = 100;

    cpu_under_test = get_cpu();
	
	// Register a callback function
	dummy_event_handlers[0].callback = set_rip_test_event_handler;
	dummy_event_handlers[0].event = vmcall;
		
	hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback));
	
	asm("lea Done, %0\n\t"
		:"=r"(rip));

	printk(KERN_ERR "set_guest_rip_test: label Done is at addr: 0x%lx", rip);
	
	// issue vmcall to enter vmm for testing
	asm_make_vmcall(0, NULL);
	
	// The following codes are executed in guest
	asm("jmp Done\n");
		
	actual++;

	asm("Done:\n");

	assert(expected == actual);
	
	hvi_unregister_event_callback(vmcall);
    put_cpu();
}

static int set_rflags_test_event_handler(hv_event_e type, unsigned char *data, int size, int* allow)
{
	unsigned char* buffer;
	int bsz;
	int result;

	unsigned long rflags, new_rflags;
	
	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	bsz = PAGE_SIZE;
	
	// pause all vcpus
	hvi_request_vcpu_pause();
	
	// first read under_test_guest's rflags	
	result = hvi_query_guest_info(cpu_under_test, registers_state, NULL, buffer, &bsz);
	
	assert(result == 0);
		
	rflags = ((hvi_x86_registers_t*)buffer)->rflags;
	
	new_rflags = rflags & ~FLAG_IF_MASK;
	
	printk(KERN_ERR "<!TEST!> On cpu_under_test-[%d]: old rflags value = 0x%lx, new rflags value = 0x%lx.\n", cpu_under_test, rflags, new_rflags);
	
	hvi_set_register_rflags(cpu_under_test, new_rflags);
	
	// resume all vcpus
	hvi_request_vcpu_resume();
	
	return 0;
}

static void setup_rflags_test(int remote)
{	
	int cpu;
	
	test_rflags_on_remote_cpu = 0;
	
	// Register a callback function
	dummy_event_handlers[0].callback = set_rflags_test_event_handler;
	dummy_event_handlers[0].event = vmcall;
	
	hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers) / sizeof(struct hvi_event_callback));
	
	sema_init(&rflags_test_sema_block_vmcall, 0);
	sema_init(&rflags_test_sema_block_main, 0);
		
	if (remote == true)
	{		
		test_rflags_on_remote_cpu = 1;
		
		for_each_online_cpu(cpu)
		{
			if (cpu != cpu_under_test)
			{
				vmcall_thread = kthread_create(set_rflags_test_make_vmcall, NULL, "kh-test-thread");
				kthread_bind(vmcall_thread, cpu);
				wake_up_process(vmcall_thread);
				break;
			}
		}
	}
}

static int set_rflags_test_make_vmcall(void* data)
{
	unsigned long rflags, rflags_new;
	
	if (test_rflags_on_remote_cpu)
	{
		spin_lock(&rflag_test_spin_lock);
	
		down(&rflags_test_sema_block_vmcall);
	
		up(&rflags_test_sema_block_main);		
	}	
	
	rflags = get_rflag();
	
	printk(KERN_ERR "<!TEST!>rflags_test_make_vmcall: local_cpu=%d, cpu_under_test=%d, rflags on local cpu=0x%lx.\n", smp_processor_id(), cpu_under_test, rflags);
	
	// issue vmcall to enter vmm for testing
	asm_make_vmcall(0, NULL);	
	
	if (test_rflags_on_remote_cpu)
		spin_unlock(&rflag_test_spin_lock);
	
	rflags_new = get_rflag();
	
	printk(KERN_ERR "<!TEST!>rflags_test_make_vmcall: after vmcall, rflags on local cpu-[%d]=0x%lx.\n", smp_processor_id(), rflags_new);
	
	return 0;
}

static unsigned long verify_rflags_tests(void)
{
	unsigned long rflags;
	
	rflags = get_rflag();
	
	printk(KERN_ERR "<!TEST!>rflags_test on CPU-[%d] AFTER, rflags=0x%lx, guest interrupt is %s.\n", smp_processor_id(), rflags, (CHECK_BIT_IS_SET(rflags, FLAG_IF) == 1) ? "enabled" : "disabled");	
	
	if (!test_rflags_on_remote_cpu)
		assert(CHECK_BIT_IS_SET(rflags, FLAG_IF) == 0);
	
	printk("set_rflags_test: Success.\n");
	
	return rflags;
}

static void clean_up_rflags_tests(unsigned long rflags)
{	
	if (CHECK_BIT_IS_SET(rflags, FLAG_IF) == 0)	
	{
		//re-enable interrupt
		local_irq_enable();
	}
	
	cpu_under_test = -1;
	
	test_rflags_on_remote_cpu = 0;

	hvi_unregister_event_callback(vmcall);
}

static void run_set_rflags_test_on_different_cpu(void)
{
	unsigned long rflags;

	int cpu;
	
	cpu = get_cpu();
	
	cpu_under_test = cpu;
	
	setup_rflags_test(true);
	
	rflags = get_rflag();	
	
	printk(KERN_ERR "<!TEST!rflags_test on CPU-[%d], BEFORE, rflags=0x%lx, guest interrupt is %s.\n", smp_processor_id(), rflags, (CHECK_BIT_IS_SET(rflags, FLAG_IF) == 1) ? "enabled" : "disabled");
	
	// vmcall_thread makes vmcall	
	up(&rflags_test_sema_block_vmcall);
	
	down(&rflags_test_sema_block_main);
	
	spin_lock(&rflag_test_spin_lock);
	
	// verify
	verify_rflags_tests();
	
	// clean up
	clean_up_rflags_tests(0);
	
	spin_unlock(&rflag_test_spin_lock);
	
	put_cpu();
}

static void run_set_rflags_test(void)
{
	unsigned long rflags;

	int cpu;
	
	cpu = get_cpu();
	
	cpu_under_test = cpu;
	
	setup_rflags_test(false);
	
	rflags = get_rflag();
	
	printk(KERN_ERR "<!TEST!>run_set_rflags_test BEFORE, guest interrupt is %s.\n", (CHECK_BIT_IS_SET(rflags, 9) == 1) ? "enabled" : "disabled");
	
	// issue vmcall to enter vmm
	set_rflags_test_make_vmcall(NULL);
	
	rflags = verify_rflags_tests();
	
	clean_up_rflags_tests(rflags);	
	
	put_cpu();
}

static int __init set_guest_info_test_module_init(void)
{
	printk(KERN_ERR "<!TEST!>------------------- set_rflags_test on local cpu: ----------");
	run_set_rflags_test();
	
	msleep(1000);
	
	printk(KERN_ERR "<!TEST!>------------------- set_rip_test on local cpu: ----------");
	run_set_rip_test();	
	
	msleep(1000);
	
	if (num_online_cpus() > 1)
	{
		// This test can only verify that code path is correct.  The test result (rflags value)
		// doesn't make sense because remote cpus are paused by using ipi->vmcall, so the "app" that 
		// runs on the cpu_under_test is always ipi interrupt handler when pause happens.
		//printk(KERN_ERR "<!TEST!>--------------- set_rflags_test on remote cpu: ----------");
		//run_set_rflags_test_on_different_cpu();
		
		//msleep(1000);		
		//printk(KERN_ERR "<!TEST!>--------------- set_rip_test on remote cpu: ----------");
		//run_set_rip_test_on_different_cpu();
	}

	return 0;
}

static void __exit set_guest_info_test_module_exit(void)
{
	printk("set_guest_info_test_module: Goodbye, world!\n");
}

module_init(set_guest_info_test_module_init);
module_exit(set_guest_info_test_module_exit);
