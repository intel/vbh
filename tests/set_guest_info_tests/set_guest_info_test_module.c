#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <asm/paravirt.h>
#include <asm/vmx.h>

#include "vbh_test_shared.h"
#include "hypervisor_introspection.h"
#include "vmx_common.h"

MODULE_LICENSE("Proprietary");

#define CHECK_BIT_IS_SET(var,pos) (((var) & (1<<(pos))) >> pos)

static struct hvi_event_callback dummy_event_handlers[1];

static unsigned long rip;

static long get_rflag(void)
{
	long flag;
	
	__asm__ __volatile__("pushf \n\t"
						"popq %%rax\n\t"
						"movq %%rax, %0\n\t"
						: "=m"(flag)
						:
						: "%rax"
		);
	
	return flag;
}

static int set_register_rflags_test_event_handler(hv_event_e type, unsigned char *data, int size, int* allow)
{
#if 0
	unsigned long rflags, new_rflags;
	
	// first read guest's rflags
	
	rflags = vmcs_readl(GUEST_RFLAGS);
	
	if (!CHECK_BIT_IS_SET(rflags, 6))
	{
		new_rflags = rflags ^ 0x0040;
		
		printk(KERN_ERR "set_rflags_test: old_rflags = 0x%lx, new_rflags=0x%lx.\n", rflags, new_rflags);
		
		hvi_set_register_rflags(0, new_rflags);
	}		
	else
	{
		assert(0);
	}
#endif
	return 0;
}

static int set_register_rip_test_event_handler(hv_event_e type, unsigned char *data, int size, int* allow)
{	
	 rip -= 4;
	
	// set guest rip
	hvi_set_register_rip(0, rip);
	
	return 0;
}

static void run_set_rip_test(void)
{
	int expected = 101;
	int actual = 100;

	// Register a callback function
	dummy_event_handlers[0].callback = set_register_rip_test_event_handler;
	dummy_event_handlers[0].event = vmcall;
		
	hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback));
	
	asm("lea Done, %0\n\t"
		:"=r"(rip));

	printk(KERN_ERR "set_guest_rip_test: label Done is at rip: 0x%lx", rip);
	
	// issue vmcall to enter vmm for testing
	asm_make_vmcall(0, NULL);
	
	// The following codes are executed in guest
	asm("jmp Done\n");
		
	actual++;

	asm("Done:\n");

	assert(expected == actual);
	
	hvi_unregister_event_callback(vmcall);
}

static void run_set_rflags_test(void)
{
	unsigned long rflags;

	// Register a callback function
	dummy_event_handlers[0].callback = set_register_rflags_test_event_handler;
	dummy_event_handlers[0].event = vmcall ;
	
	hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback));
	
	// issue vmcall to enter vmm for testing
	asm_make_vmcall(0, NULL);	
	
	rflags = get_rflag();
	
	assert(CHECK_BIT_IS_SET(rflags, 6)==1);

	printk("set_rflags_test: Success.\n");
	
	hvi_unregister_event_callback(vmcall);
}

static int __init set_guest_info_test_module_init(void)
{
	run_set_rflags_test();
	
	run_set_rip_test();	
	
	return 0;
}

static void __exit set_guest_info_test_module_exit(void)
{
	printk("set_guest_info_test_module: Goodbye, world!\n");
}

module_init(set_guest_info_test_module_init);
module_exit(set_guest_info_test_module_exit);
