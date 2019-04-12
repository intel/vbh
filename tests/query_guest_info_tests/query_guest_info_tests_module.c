#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <asm/paravirt.h>
#include <asm/vmx.h>
#include <asm/desc.h>

#include "vbh_test_shared.h"
#include "hypervisor_introspection.h"
#include "vmx_common.h"


MODULE_LICENSE("Proprietary");

static struct hvi_event_callback dummy_event_handlers[1];

struct x86_dtable expected_idt;

struct x86_dtable expected_gdt;

int expected_cpu_count;

int expected_tid;

u64 expected_rsp;

u64 expected_msr_value;

int expected_cs_type;

int expected_cs_ring;

struct x86_sregs expected_sregs;

struct x86_regs expected_regs;

static void get_msr_test(int cpu);

static void get_cpu_count_test(int cpu);

static void get_idt_test(int cpu);

static void get_gdt_test(int cpu);

static void get_gpr_registers_test(int cpu);
static void set_sregs_expected_values(void);

static void check_sreg(struct x86_segment *expected, struct x86_segment *actual)
{
	assert(expected->ar == actual->ar);
	
	assert(expected->base == actual->base);
	
	assert(expected->limit == actual->limit);
	
	assert(expected->selector == actual->selector);
}

static void check_sreg_result(char* name, struct x86_segment *expected, struct x86_segment *actual)
{
	printk(KERN_ERR "Segment %s: Expected base=0x%llx, limit=0x%x, selector=0x%x, ar=0x%x", name, expected->base, expected->limit, expected->selector, expected->ar);
	printk(KERN_ERR "Segment %s: Actual base=0x%llx, limit=0x%x, selector=0x%x, ar=0x%x", name, actual->base, actual->limit, actual->selector, actual->ar);
	
	check_sreg(expected, actual);
}

static void get_gpr_registers_test(int cpu)
{
	int size = PAGE_SIZE;
	
	int result;
	
	u64 expected_rsp, actual_rsp;
	
	hvi_x86_gpr_t actual;
	
	// guest's rsp is also guest state area
	expected_rsp = vmcs_read64(GUEST_RSP);
	
	printk(KERN_ERR "<vbh_test>_%s: expected value = 0x%llx.\n", __func__, expected_rsp);
	
	result = hvi_query_guest_info(cpu, general_purpose_registers, NULL, (unsigned char*)&actual, &size);
	
	actual_rsp = actual.rsp;
	
	printk(KERN_ERR "<vbh_test>_%s: actual value = 0x%llx.\n", __func__, actual_rsp);
	
	assert(result == 0);
	
	assert(size == 16 * 8);
	
	assert(expected_rsp == actual_rsp);
}

static void get_gdt_test(int cpu)
{
	struct x86_dtable actual;
	
	int size = sizeof(actual);
	
	int result;
	
	printk(KERN_ERR "<vbh_test>_%s: expected base = 0x%llx, limit = 0x%x.\n", __func__, expected_gdt.base, expected_gdt.limit);
	
	result = hvi_query_guest_info(cpu, gdtr, NULL, (unsigned char*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: actual base = 0x%llx, limit = 0x%x.\n", __func__, actual.base, actual.limit);
	
	assert(result == 0);
	
	assert(expected_gdt.base == actual.base);
	
	assert(expected_gdt.limit == actual.limit);
}

static void get_idt_test(int cpu)
{
	struct x86_dtable actual;
	
	int result;
	
	int size = sizeof(actual);

	printk(KERN_ERR "<vbh_test>_%s: expected base = 0x%llx, limit=0x%x.\n", __func__, expected_idt.base, expected_idt.limit);
	
	result = hvi_query_guest_info(cpu, idtr, NULL, (void*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: actual base = 0x%llx, limit=0x%x.\n", __func__, actual.base, actual.limit);
	
	assert(result == 0);
	
	assert(expected_idt.base == actual.base);
	
	assert(expected_idt.limit == actual.limit);
}

static void get_cpu_count_test(int cpu)
{
	int actual;
	int size = sizeof(int);
	
	int result;
	
	printk(KERN_ERR "<vbh_test>_%s: expected value = %d.\n", __func__, expected_cpu_count);
	
	result = hvi_query_guest_info(cpu, cpu_count, NULL, (unsigned char*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: actual value = %d.\n", __func__, actual);
	
	assert(result == 0);
	
	assert(expected_cpu_count == actual);	
}

static void get_msr_test(int cpu)
{
	u64 actual;
	
	int size = sizeof(u64);
	
	int result;

	hvi_query_info_e query_type = msr;
	
	u32 param = MSR_IA32_FEATURE_CONTROL;	

    printk(KERN_ERR "<vbh_test>_%s: expected value = 0x%llx.\n", __func__ , expected_msr_value);
	
	result = hvi_query_guest_info(cpu, query_type, (unsigned char*)&param, (unsigned char*)&actual, &size);

    printk(KERN_ERR "<vbh_test>_%s: actual value = 0x%llx.\n", __func__ , actual);
	
	assert(result == 0);
	
	assert(expected_msr_value == actual);
}

static void get_cs_type_test(int cpu)
{
	int actual;
	
	int size = sizeof(int);
	
	int result;
	
	hvi_query_info_e query_type = cs_type;
	
	printk(KERN_ERR "<vbh_test>_%s: expected value = %d.\n", __func__, expected_cs_type);
	
	result = hvi_query_guest_info(cpu, query_type, NULL, (unsigned char*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: actual value = %d.\n", __func__, actual);
	
	assert(result == 0);
	
	assert(expected_cs_type == actual);	
}

static void get_cs_ring_test(int cpu)
{
	int actual;
	
	int size = sizeof(int);
	
	int result;
	
	hvi_query_info_e query_type = cs_ring;
	
	printk(KERN_ERR "<vbh_test>_%s: expected value = %d.\n", __func__, expected_cs_ring);
	
	result = hvi_query_guest_info(cpu, query_type, NULL, (unsigned char*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: actual value = %d.\n", __func__, actual);
	
	assert(result == 0);
	
	assert(expected_cs_ring == actual);	
	
}

static void get_seg_registers_state_test(int cpu)
{
	struct x86_sregs actual;
	
	int size = sizeof(actual);
	
	int result;
	
	hvi_query_info_e query_type = segment_registers;

	// sregs
	set_sregs_expected_values();
	
	result = hvi_query_guest_info(cpu, query_type, NULL, (unsigned char*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: \n", __func__);	
		
	assert(result == 0);
	
	check_sreg_result("CS", &expected_sregs.cs, &actual.cs);
	check_sreg_result("DS", &expected_sregs.ds, &actual.ds);
	check_sreg_result("ES", &expected_sregs.es, &actual.es);
	check_sreg_result("FS", &expected_sregs.fs, &actual.fs);
	check_sreg_result("GS", &expected_sregs.gs, &actual.gs);
	check_sreg_result("SS", &expected_sregs.ss, &actual.ss);	
}

static void get_current_tid_test(int cpu)
{
	int size = sizeof(int);
	
	int actual;
	
	int result;
	
	hvi_query_info_e query_type = current_tid;
	
	result = hvi_query_guest_info(cpu, query_type, NULL, (unsigned char*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: expected value = %d, actual value = %d.\n", __func__, expected_tid, actual);
	
	assert(result == 0);
	
	assert(expected_tid == actual);	
}

static void get_guest_state_test(int cpu)
{
	hvi_x86_registers_t actual;
	int size = sizeof(actual);
	
	int result;
	
	hvi_query_info_e query_type = registers_state;
	
	expected_rsp = vmcs_read64(GUEST_RSP);
	
	result = hvi_query_guest_info(cpu, query_type, NULL, (unsigned char*)&actual, &size);
	
	printk(KERN_ERR "<vbh_test>_%s: Expected cr0 = 0x%llx, cr3 = 0x%llx, cr4 = 0x%llx, dr7 = 0x%llx, rsp = 0x%llx\n", 
			__func__, 
			expected_regs.cr0, 
			expected_regs.cr3,
			expected_regs.cr4,
			expected_regs.dr7,
		    expected_rsp);
	
	printk(KERN_ERR "<vbh_test>_%s: Actual cr0 = 0x%llx, cr3 = 0x%llx, cr4 = 0x%llx, dr7 = 0x%llx, rsp = 0x%llx.\n", 
		__func__, 
		actual.cr0, 
		actual.cr3,
		actual.cr4,
		actual.dr7,
		actual.gprs.rsp);
	assert(result == 0);
	
	assert(size == sizeof(actual));
	
	assert(expected_regs.cr0 == actual.cr0);
	
	assert(expected_regs.cr3 == actual.cr3);
	
	assert(expected_regs.cr4 == actual.cr4);
	
	assert(expected_regs.dr7 == actual.dr7);
	
	assert(expected_rsp == actual.gprs.rsp);
}

static int qgi_test_event_handler(hv_event_e type, unsigned char* data, int size, int* allow)
{
	int cpu = smp_processor_id();
	
	// pause all cpus first
	hvi_request_vcpu_pause(false);
	
	// test get_msr returns correct value
	get_msr_test(cpu);
	
	// test get_cpu_count returns correct value
	get_cpu_count_test(cpu);
	
	// test get_idt returns correct value
	get_idt_test(cpu);
	
	// test get_gdt returns correct value
	get_gdt_test(cpu);
	
	// test get_gpr_register_state returns correct value
	get_gpr_registers_test(cpu);
	
	// test get_cs_type returns correct value
	get_cs_type_test(cpu);
	
	// test get_cs_ring returns correct value
	get_cs_ring_test(cpu);
	
	// test get_seg_registers_state returns correct value
	get_seg_registers_state_test(cpu);
	
	// test get_current_tid
	get_current_tid_test(cpu);
	
	// test get_guest_state
	get_guest_state_test(cpu);
	
	hvi_request_vcpu_resume();
	
	return 0;
}

static void set_sregs_expected_values(void)
{
	expected_sregs.cs.padding = 0;
	expected_sregs.cs.base = vmcs_readl(GUEST_CS_BASE);
	expected_sregs.cs.limit = vmcs_read32(GUEST_CS_LIMIT);
	expected_sregs.cs.selector = vmcs_read16(GUEST_CS_SELECTOR);
	expected_sregs.cs.ar = vmcs_read32(GUEST_CS_AR_BYTES);
	
	// ds register
	expected_sregs.ds.padding = 0;
	expected_sregs.ds.base = vmcs_readl(GUEST_DS_BASE);
	expected_sregs.ds.limit = vmcs_read32(GUEST_DS_LIMIT);
	expected_sregs.ds.selector = vmcs_read16(GUEST_DS_SELECTOR);
	expected_sregs.ds.ar = vmcs_read32(GUEST_DS_AR_BYTES);
	
	// ss register
	expected_sregs.ss.padding = 0;
	expected_sregs.ss.base = vmcs_readl(GUEST_SS_BASE);
	expected_sregs.ss.limit = vmcs_read32(GUEST_SS_LIMIT);
	expected_sregs.ss.selector = vmcs_read16(GUEST_SS_SELECTOR);
	expected_sregs.ss.ar = vmcs_read32(GUEST_SS_AR_BYTES);
	
	// es register
	expected_sregs.es.padding = 0;
	expected_sregs.es.base = vmcs_readl(GUEST_ES_BASE);
	expected_sregs.es.limit = vmcs_read32(GUEST_ES_LIMIT);
	expected_sregs.es.selector = vmcs_read16(GUEST_ES_SELECTOR);
	expected_sregs.es.ar = vmcs_read32(GUEST_ES_AR_BYTES);
	
	// fs register
	expected_sregs.fs.padding = 0;
	expected_sregs.fs.base = vmcs_readl(GUEST_FS_BASE);
	expected_sregs.fs.limit = vmcs_read32(GUEST_FS_LIMIT);
	expected_sregs.fs.selector = vmcs_read16(GUEST_FS_SELECTOR);
	expected_sregs.fs.ar = vmcs_read32(GUEST_FS_AR_BYTES);
	
	// gs register
	expected_sregs.gs.padding = 0;
	expected_sregs.gs.base = vmcs_readl(GUEST_GS_BASE);
	expected_sregs.gs.limit = vmcs_read32(GUEST_GS_LIMIT);
	expected_sregs.gs.selector = vmcs_read16(GUEST_GS_SELECTOR);
	expected_sregs.gs.ar = vmcs_read32(GUEST_GS_AR_BYTES);
}

static void set_control_reg_expected_values(void)
{
	u64 cr0, cr3, cr4, dr7;
	
	__asm__ __volatile__ (
		"mov %%cr0, %%rax\n\t"
		"mov %%rax, %0\n\t"
		"mov %%cr3, %%rax\n\t"
		"mov %%rax, %1\n\t"
		"mov %%cr4, %%rax\n\t"
		"mov %%rax, %2\n\t"
		"mov %%dr7, %%rax\n\t"
		"mov %%rax, %3\n\t"
		: "=m"(cr0), "=m"(cr3), "=m"(cr4), "=m"(dr7)
		:
		: "%rax"
	);
	
	expected_regs.cr0 = cr0;
	expected_regs.cr3 = cr3;
	expected_regs.cr4 = cr4;
	expected_regs.dr7 = dr7;
}

static void set_expected_values(void)
{
	u32 hi, lo;
	struct desc_ptr dt;
		
	//idtr
	store_idt(&dt);	
	expected_idt.limit = dt.size;
	expected_idt.base = dt.address;
	
	//gdtr
	native_store_gdt(&dt);
	expected_gdt.limit = dt.size;
	expected_gdt.base = dt.address;
	
	// cpu_count
	expected_cpu_count = num_online_cpus();
	
	// msr
	rdmsr(MSR_IA32_FEATURE_CONTROL, hi, lo);

	expected_msr_value = (u64)lo << 32 | hi;
	
	// used by get_gpr_registers_test
	asm("movq %%rsp, %%rax\n"
	: "=a"(expected_rsp));
	
	// cs_type
	expected_cs_type = KVI_CS_TYPE_64_BIT;
	
	// cs ring
	expected_cs_ring = KVI_CPL_KERNEL;
	
	// tid (current cpu id)
	expected_tid = smp_processor_id();
	
	// control registers
	set_control_reg_expected_values();
}

static int __init query_shared_info_tests_init(void)
{
	int cpu = get_cpu();
	
	printk(KERN_ERR "<vbh_test>_%s: cpu=%d.\n", __func__, cpu);
	
	set_expected_values();
	
	// Register a callback function
	dummy_event_handlers[0].callback = qgi_test_event_handler;
	dummy_event_handlers[0].event = vmcall;
	
	hvi_register_event_callback(dummy_event_handlers, sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback));
	
	// issue vmcall to enter vmm for testing
	asm_make_vmcall(0, NULL);
	
	put_cpu();
	
    return 0;
}


static void __exit query_shared_info_tests_exit(void)
{
	int i;
	for(i=0; i<sizeof(dummy_event_handlers)/sizeof(struct hvi_event_callback); i++)
		hvi_unregister_event_callback(dummy_event_handlers[i].event);
	
	printk("query_shared_info_tests: Goodbye, world!\n");
}

module_init(query_shared_info_tests_init);
module_exit(query_shared_info_tests_exit);
