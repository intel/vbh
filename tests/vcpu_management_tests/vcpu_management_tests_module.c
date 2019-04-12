#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kernel.h>

#include "hypervisor_introspection.h"
#include "vmx_common.h"
#include "vbh_test_shared.h"

MODULE_LICENSE("Proprietary");

static bool pause_from_guest = 0;

module_param_named(request_pause_from_guest, pause_from_guest, bool, 0444);

MODULE_PARM_DESC(request_pause_from_guest, "Request pause vcpu from guest");

static struct hvi_event_callback dummy_event_handlers[1];

static struct task_struct **worker_threads;

struct task_struct *culprit_thread;

static int done;

static int tick_per_cpu(void* data)
{
	int cpu = smp_processor_id();
	
	do
	{
		if (!done)
			printk(KERN_ERR "<!TEST!>CPU: %d ticks.\n", cpu);
		
		msleep(500);
	} while (!kthread_should_stop());
	
	//do_exit(0);
	
	printk(KERN_ERR "<!TEST!>tick_per_cpu on cpu [%d] stopped.\n", cpu);
	
	return 0;
}

static int do_bad(void *data)
{
	int cpu;
	
	cpu = smp_processor_id();
	
	printk(KERN_ERR "<!TEST!>Do_bad on cpu [%d].\n", cpu);
	
	asm_make_vmcall(0, NULL);
	
	cpu = smp_processor_id();
	
	printk(KERN_ERR "<!TEST!>Do_bad resumes on cpu [%d].\n", cpu);
	
	msleep(2000);
	
	// stop printing tick message
	done = 1;
	
	return 0;
}

static void setup_test(void)
{
	struct task_struct *worker_thread;
	
	int cpu, cpus;
	
	done = 0;
	
	cpus = num_online_cpus();
	
	worker_threads = kmalloc(sizeof(struct task_struct*) * cpus, GFP_KERNEL);
	
	for_each_online_cpu(cpu)
	{
		worker_thread = kthread_create(tick_per_cpu, NULL, "tick_thread-%d", cpu);
		
		worker_threads[cpu] = worker_thread;
		
		kthread_bind(worker_thread, cpu);
		
		wake_up_process(worker_thread);
	}
	
	culprit_thread = kthread_create(do_bad, NULL, "culprit-thread");
		
}

static int vcpu_mgr_test_vmcall_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	int ret;
	int cpu;
	int total_cpus = num_online_cpus();
	
	cpu = get_cpu();
	
	printk(KERN_ERR "<!TEST!>: Ready request pause on cpu [%d], processor [%d], interrupt is %s.\n", cpu, smp_processor_id(), irqs_disabled() ? "disabled" : "enabled");
	
	ret = hvi_request_vcpu_pause(false);
	
	printk(KERN_ERR "<!TEST!>: hvi_request_vcpu_pause %s.\n", ret==0?"Succeeds":"Fails");
	
	if(total_cpus == 1)
	{
		// Cannot pause the only cpu.  This assumes that hvi_request_vcpu_pause is only called when in root mode.
		assert(ret == -1);
	}
	else
	{
		assert(ret == 0);
	}
	
	mdelay(2000);
	
	printk(KERN_ERR "<!TEST!>Ready to request resume on cpu [%d]...\n", smp_processor_id());
	
	ret = hvi_request_vcpu_resume();
	
	put_cpu();
		
	return ret;
}

static int __init vcpu_management_tests_init(void)
{
	int ret;
	
	setup_test();
	
	// Give each tick thread some time to run so we can see guest ticks.
	msleep(500);
	
	printk(KERN_ERR "<!TEST!>Run....\n");
//	if (pause_from_guest)
//		ret = hvi_request_vcpu_pause();
//	else
	{
		// register a callback function
		dummy_event_handlers[0].event = vmcall;
		dummy_event_handlers[0].callback = vcpu_mgr_test_vmcall_event_handler;
	
		hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers) / sizeof(struct hvi_event_callback));
	
		wake_up_process(culprit_thread);
	}

	return 0;
}

static void __exit vcpu_management_tests_exit(void)
{
	int cpu;
	
	for_each_online_cpu(cpu)
	{
		kthread_stop(worker_threads[cpu]);
	}
	
	printk("vcpu_management_tests: Goodbye, world!\n");
}

module_init(vcpu_management_tests_init);
module_exit(vcpu_management_tests_exit);

