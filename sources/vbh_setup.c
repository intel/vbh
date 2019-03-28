// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/sched.h>

#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <asm/kvm_host.h>
#include <asm/vmx.h>
#include <asm/msr-index.h>
#include <asm/special_insns.h>

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>

#include "vmx_common.h"

#define __ex(x) x

#define VMX_EPTP_MT_WB						0x6ull
#define VMX_EPTP_PWL_4						0x18ull

#define	NR_LOAD_MSRS						8
#define NR_STORE_MSRS						8

#define is_aligned(POINTER, BYTE_COUNT) \
		(((uintptr_t)(const void *)(POINTER)) % (BYTE_COUNT) == 0)

struct vmx_capability {
	u32 ept;
	u32 vpid;
};

DEFINE_SPINLOCK(vbh_load_lock);
static bool vbh_loaded = 0;

static struct vmx_capability vmx_cap;
static struct vmcs_config __percpu *vmcs_config;
struct vcpu_vmx __percpu *vcpu;
static int vmxon_success;
static struct desc_ptr __percpu *host_gdt;

DECLARE_BITMAP(switch_done, NR_CPUS);
DECLARE_BITMAP(all_cpus, NR_CPUS);

DEFINE_PER_CPU(unsigned long[NR_VCPU_REGS], reg_scratch);

static pgd_t *host_cr3;
static unsigned long rflags_value;
static unsigned long is_vmlaunch_fail;
static unsigned long *vmx_io_bitmap_a_switch;
static unsigned long *vmx_io_bitmap_b_switch;
unsigned long *vmx_msr_bitmap_switch;
unsigned long *vmx_eptp_pml4;
static bool __read_mostly switch_on_load = 1;
module_param_named(switch_vmx_on_load, switch_on_load, bool, 0444);
MODULE_PARM_DESC(switch_vmx_on_load, "Switch to non root when module is load");

extern void vmx_switch_and_exit_handle_vmexit(void);

void setup_ept_tables(void);
void unload_vbh_per_cpu(void *info);
int vmx_switch_to_nonroot(void);
bool check_vbh_status(void);

static void set_msr_state(void);
static noinline void load_guest_state_registers(void);
static int switch_to_nonroot_per_cpu(void *data);
static bool is_xsaves_supported(void);
static bool is_invpcid_supported(void);

void vmcs_clear(void)
{
	struct vcpu_vmx *vcpu_ptr;
	u64 phys_addr;
	u8 error;

	vcpu_ptr = this_cpu_ptr(vcpu);
	phys_addr = __pa(vcpu_ptr->pcpu_vmcs);

	asm volatile(__ex(ASM_VMX_VMCLEAR_RAX) "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr),
			"m"(phys_addr)
			: "cc",
			"memory");

	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
			vcpu_ptr->pcpu_vmcs,
			phys_addr);
}

static void vmxon_setup_revid(void *vmxon_region)
{
	u32 rev_id = 0;
	u32 msr_high_value = 0;

	rdmsr(MSR_IA32_VMX_BASIC, rev_id, msr_high_value);

	memcpy(vmxon_region, &rev_id, 4);
}

static int cpu_vmxon(u64 addr, int cpu)
{
	vmxon_success = 1;

	// Do vmxon
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");

	// Check whether vmxon succeeds or not
	asm volatile("jbe vmxon_fail\n");
	asm volatile("jmp vmxon_finish\n"
			"vmxon_fail:\n"
			"pushfq\n");

	asm volatile("popq %0\n"
		: "=m"(rflags_value)
		:
		: "memory");

	vmxon_success = 0;
	printk(KERN_ERR "<1>CPU-%d: vmxon has failed. rflags_value=%lx\n",
				cpu, rflags_value);

	asm volatile("vmxon_finish:\n");
	if (vmxon_success)
		printk(KERN_ERR "<1>CPU-%d: vmxon has succeeded.\n", cpu);

	return rflags_value == 0 ? 0 : -EIO;
}

static u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp = 0;

	rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, vmx_cap.ept, vmx_cap.vpid);

	printk(KERN_ERR "<1> vmx_capability.ept=0x%x, vmx_capability.vpid=0x%x\n", vmx_cap.ept, vmx_cap.vpid);

	if (vmx_cap.ept & VMX_EPT_PAGE_WALK_4_BIT)
		eptp = VMX_EPTP_PWL_4;

	if (vmx_cap.ept & VMX_EPTP_WB_BIT)
		eptp |= VMX_EPTP_MT_WB;

	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static void vmcs_load(struct vmcs *vmcs, int cpu)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "<1> CPU-%d: vmptrld %p/%llx failed\n",
					cpu, vmcs, phys_addr);
	else
		printk(KERN_ERR "<1> CPU-%d: vmptrld %p/%llx succeeded.\n",
					cpu, vmcs, phys_addr);

}

static unsigned long segment_base(u16 selector)
{
	struct desc_ptr *gdt = this_cpu_ptr(host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;
		table_base = segment_base(ldt_selector);
	}

	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);

#ifdef CONFIG_X86_64
	if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
		v |= ((unsigned long)((tss_desc *)d)->base3) << 32;
#endif
	return v;
}

static unsigned int segment_limit(u16 selector)
{
	struct desc_ptr *gdt = this_cpu_ptr(host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned int l;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {
		/* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;
		table_base = segment_base(ldt_selector);
	}

	d = (struct desc_struct *)(table_base + (selector & ~7));
	l = get_desc_limit(d);
	return l;
}

//static inline unsigned long kvm_read_tr_base(void)
//{
//	u16 tr;
//
//	asm("str %0" : "=g"(tr));
//	return segment_base(tr);
//}

static struct vmcs *alloc_vmcs_cpu(int cpu, struct vmcs_config *vmcs_config_ptr)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = __alloc_pages_node(node, GFP_KERNEL, vmcs_config_ptr->order);
	if (!pages)
		return NULL;

	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config_ptr->size);
	vmcs->revision_id = vmcs_config_ptr->revision_id; /* vmcs revision id */
	return vmcs;
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, int *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	printk(KERN_ERR "<1> adjust_vmx_control: msr=0x%x, value=0x%llx.\n",
				msr, (u64)vmx_msr_high << 32 | vmx_msr_low);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init void setup_vmcs_config(void *data)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	int _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;
	u64 basic_msr_value;
	int cpu;
	struct vmcs_config *vmcs_config_p;

	vmcs_config_p = this_cpu_ptr(vmcs_config);

	cpu = smp_processor_id();

	// if INVPCID is disabled, return error
	if (!is_invpcid_supported()) {
		printk(KERN_ERR "<1> INVPCID is disabled.\n");
		return;
	}

	min = CPU_BASED_USE_MSR_BITMAPS |
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS, &_cpu_based_exec_control) < 0)
		return;

	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = SECONDARY_EXEC_ENABLE_EPT;

		if (is_invpcid_supported())
			min2 |= SECONDARY_EXEC_ENABLE_INVPCID;

		if (is_xsaves_supported())
			min2 |= SECONDARY_EXEC_XSAVES;

		opt2 = 0;
		if (adjust_vmx_controls(min2, opt2, MSR_IA32_VMX_PROCBASED_CTLS2, &_cpu_based_2nd_exec_control) < 0)
			return;
	}

	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
				CPU_BASED_CR3_STORE_EXITING);
	}

	min = 0;
	opt = 0;

#ifdef CONFIG_X86_64
	min = VM_EXIT_HOST_ADDR_SPACE_SIZE  | VM_EXIT_LOAD_IA32_EFER |
			VM_EXIT_SAVE_IA32_EFER;
#endif

	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
					&_vmexit_control) < 0)
		return;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	min = 0;
	opt = 0;

	basic_msr_value = (u64)vmx_msr_high << 32 | vmx_msr_low;
	if (basic_msr_value & VMX_BASIC_TRUE_CTLS) {
		printk(KERN_ERR "CPU-%d: basic_msr_value=0x%llx, bit 55 is set.\n"
					, cpu, basic_msr_value);
		if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_TRUE_PINBASED_CTLS,
						&_pin_based_exec_control) < 0) {
			printk(KERN_ERR "CPU-%d: Failed to set pinbased control.\n", cpu);
			return;
		}
	} else {
		printk(KERN_ERR "CPU-%d: basic_msr_value=0x%llx, bit 55 is NOT set.\n",
					cpu, basic_msr_value);
		if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
						&_pin_based_exec_control) < 0) {
			printk(KERN_ERR "CPU-%d: Failed to set pinbased control.\n",
						cpu);
			return;
		}
	}

	min = VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_IA32E_MODE;
	opt = VM_ENTRY_LOAD_IA32_EFER;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
					&_vmentry_control) < 0)
		return;

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return;

	vmcs_config_p->size = vmx_msr_high & 0x1fff;
	vmcs_config_p->order = get_order(vmcs_config_p->size);
	vmcs_config_p->basic_cap = vmx_msr_high & ~0x1fff;
	vmcs_config_p->revision_id = vmx_msr_low;

	vmcs_config_p->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_config_p->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_config_p->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_config_p->vmexit_ctrl         = _vmexit_control;
	vmcs_config_p->vmentry_ctrl        = _vmentry_control;
}

static noinline void load_guest_state_registers(void)
{
	vmcs_writel(GUEST_CR0, read_cr0() & ~X86_CR0_TS);
	vmcs_writel(GUEST_CR3, __read_cr3());
	vmcs_writel(GUEST_CR4, cr4_read_shadow());
}

static noinline void load_guest_state_segment_registers(int cpu)
{
	u16 selector;
	u64 base;
	u32 access_rights;
	u32 limit;

	base = 0;
	limit = 0xffffffff;

	asm ("mov %%cs, %%ax\n"
			: "=a"(selector));
	vmcs_write16(GUEST_CS_SELECTOR, selector);

	asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
	access_rights = access_rights >> 8;   //24.4.1 Guest Register State
	access_rights = access_rights & 0xf0ff;
	vmcs_write32(GUEST_CS_AR_BYTES, access_rights);
	vmcs_writel(GUEST_CS_BASE, base);
	vmcs_write32(GUEST_CS_LIMIT, limit);

	asm ("mov %%ss, %%ax;\n"
		: "=a"(selector));

	vmcs_write16(GUEST_SS_SELECTOR, selector);

	if (selector == 0) {
		access_rights = 0x10000;
	} else {
		asm("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		access_rights = access_rights >> 8;    //24.4.1 Guest Register State
		access_rights = access_rights & 0xf0ff;
	}

	vmcs_write32(GUEST_SS_AR_BYTES, access_rights);
	vmcs_writel(GUEST_SS_BASE, base);
	vmcs_write32(GUEST_SS_LIMIT, limit);
}

static noinline void load_guest_state_area(int cpu)
{
	u16 selector;
	u64 base;
	u32 limit;
	u32 access_rights;
	struct desc_ptr dt;
	u16 tr;

	load_guest_state_registers();

	load_guest_state_segment_registers(cpu);

	base = 0;
	limit = 0xffffffff;

	asm ("mov %%ds, %%ax\n"
		: "=a"(selector));
	vmcs_write16(GUEST_DS_SELECTOR, selector);
	if (selector == 0) {
		vmcs_write32(GUEST_DS_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		access_rights = access_rights >> 8;  //24.4.1 Guest Register State
		access_rights = access_rights & 0xf0ff;
		vmcs_write32(GUEST_DS_AR_BYTES, access_rights);
		vmcs_writel(GUEST_DS_BASE, base);
		vmcs_write32(GUEST_DS_LIMIT, limit);
	}

	asm ("mov %%es, %%ax\n"
			: "=a"(selector));
	vmcs_write16(GUEST_ES_SELECTOR, selector);
	if (selector == 0) {
		vmcs_write32(GUEST_ES_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		access_rights = access_rights >> 8;  //24.4.1 Guest Register State
		access_rights = access_rights & 0xf0ff;
		vmcs_write32(GUEST_ES_AR_BYTES, access_rights);
		vmcs_writel(GUEST_ES_BASE, base);
		vmcs_write32(GUEST_ES_LIMIT, limit);
	}

	// get base for fs and gs from the register
	asm ("mov %%fs, %%ax\n"
		: "=a"(selector));
	vmcs_write16(GUEST_FS_SELECTOR, selector);
	if (selector == 0) {
		vmcs_write32(GUEST_FS_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		access_rights = access_rights >> 8;  //24.4.1 Guest Register State
		access_rights = access_rights & 0xf0ff;
		vmcs_write32(GUEST_FS_AR_BYTES, access_rights);
	}

	vmcs_writel(GUEST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_write32(GUEST_FS_LIMIT, limit);

	asm ("mov %%gs, %%ax\n"
		: "=a"(selector));
	vmcs_write16(GUEST_GS_SELECTOR, selector);
	if (selector == 0) {
		vmcs_write32(GUEST_GS_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		access_rights = access_rights >> 8;  //24.4.1 Guest Register State
		access_rights = access_rights & 0xf0ff;
		vmcs_write32(GUEST_GS_AR_BYTES, access_rights);
	}
	vmcs_writel(GUEST_GS_BASE, read_msr(MSR_GS_BASE));
	vmcs_write32(GUEST_GS_LIMIT, limit);

	asm volatile ("str %0" : "=r" (tr));
	vmcs_write16(GUEST_TR_SELECTOR, tr);
	if (tr == 0) {
		vmcs_write32(GUEST_TR_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(tr));
		access_rights = access_rights >> 8;  //24.4.1 Guest Register State
		access_rights = access_rights & 0xf0ff;
		vmcs_writel(GUEST_TR_BASE, segment_base(tr));
		vmcs_write32(GUEST_TR_LIMIT, segment_limit(tr));
		vmcs_write32(GUEST_TR_AR_BYTES, access_rights);
	}

	vmcs_write16(GUEST_LDTR_SELECTOR, kvm_read_ldt());
	vmcs_writel(GUEST_LDTR_BASE, base);
	vmcs_write32(GUEST_LDTR_LIMIT, limit);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x10000);

	native_store_gdt(&dt);
	vmcs_writel(GUEST_GDTR_BASE, dt.address);
	vmcs_write32(GUEST_GDTR_LIMIT, dt.size);

	store_idt(&dt);
	vmcs_writel(GUEST_IDTR_BASE, dt.address);
	vmcs_write32(GUEST_IDTR_LIMIT, dt.size);

	//MSR state
	set_msr_state();
}

static noinline void set_msr_state(void)
{
	u32 high, low;
	unsigned long a;

	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	rdmsr(MSR_IA32_SYSENTER_CS, low, high);
	vmcs_write32(GUEST_SYSENTER_CS, low);

	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(GUEST_SYSENTER_ESP, a);

	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(GUEST_SYSENTER_EIP, a);

	rdmsrl(MSR_EFER, a);
	vmcs_write64(GUEST_IA32_EFER, a);

	rdmsrl(MSR_IA32_CR_PAT, a);
	vmcs_write64(GUEST_IA32_PAT, a);

	//Guest non register state
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmcs_write64(VMCS_LINK_POINTER, -1ull);

	//TODO:  why this one doesn't work on vmware?
	//vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, 0);
}

static noinline void load_host_state_area(void)
{
	struct desc_ptr dt;
	u16 selector;
	u32 high, low;
	unsigned long a;
	u16 tr;

	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);
	vmcs_writel(HOST_CR3, __pa(host_cr3));
	vmcs_writel(HOST_CR4, cr4_read_shadow());

	asm ("mov %%cs, %%ax\n"
		: "=a"(selector));
	vmcs_write16(HOST_CS_SELECTOR, selector);

	asm ("mov %%ss, %%ax\n"
		: "=a"(selector));
	vmcs_write16(HOST_SS_SELECTOR, selector);

	asm ("mov %%ds, %%ax\n"
		: "=a"(selector));
	vmcs_write16(HOST_DS_SELECTOR, selector);

	asm ("mov %%es, %%ax\n"
		: "=a"(selector));
	vmcs_write16(HOST_ES_SELECTOR, selector);

	asm ("mov %%fs, %%ax\n"
		: "=a"(selector));
	vmcs_write16(HOST_FS_SELECTOR, selector);
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));


	asm ("mov %%gs, %%ax\n"
		: "=a"(selector));
	vmcs_write16(HOST_GS_SELECTOR, selector);
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));


	asm volatile ("str %0" : "=r" (tr));
	vmcs_write16(HOST_TR_SELECTOR, tr);
	vmcs_writel(HOST_TR_BASE, segment_base(tr));

	native_store_gdt(&dt);
	vmcs_writel(HOST_GDTR_BASE, dt.address);

	store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);

	//MSR area
	rdmsr(MSR_IA32_SYSENTER_CS, low, high);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low);

	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);

	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);

	rdmsrl(MSR_EFER, a);
	vmcs_write64(HOST_IA32_EFER, a);

	rdmsrl(MSR_IA32_CR_PAT, a);
	vmcs_write64(HOST_IA32_PAT, a);
}

static void load_execution_control(struct vmcs_config *vmcs_config_ptr)
{
	u32 high, low;
	u64 eptp;
	u32 value;

	rdmsr(MSR_IA32_VMX_PINBASED_CTLS, low, high);
	value = 0x16;
	value = value | low;
	value = value & high;
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
				vmcs_config_ptr->pin_based_exec_ctrl);

	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS, low, high);
	value = 0x94006172;
	value = value | low;
	value = value & high;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
				vmcs_config_ptr->cpu_based_exec_ctrl);   //enable seconday controls

	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2, low, high);
	value = 0x0;
	value = value | low;
	value = value & high;
	vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
				vmcs_config_ptr->cpu_based_2nd_exec_ctrl);   //enable seconday controls

	vmcs_write32(EXCEPTION_BITMAP, 0);

	vmx_io_bitmap_a_switch = (unsigned long *)__get_free_page(GFP_KERNEL);
	memset(vmx_io_bitmap_a_switch, 0, PAGE_SIZE);
	vmcs_write64(IO_BITMAP_A, __pa(vmx_io_bitmap_a_switch));

	vmx_io_bitmap_b_switch = (unsigned long *)__get_free_page(GFP_KERNEL);
	memset(vmx_io_bitmap_b_switch, 0, PAGE_SIZE);
	vmcs_write64(IO_BITMAP_B, __pa(vmx_io_bitmap_b_switch));

	vmx_msr_bitmap_switch = (unsigned long *)__get_free_page(GFP_KERNEL);
	memset(vmx_msr_bitmap_switch, 0, PAGE_SIZE);
	vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_switch));

	eptp = construct_eptp(__pa(vmx_eptp_pml4));

	vmcs_write64(EPT_POINTER, eptp);

	vmcs_writel(CR0_GUEST_HOST_MASK, 0); //guest owns the bits

	vmcs_writel(CR4_GUEST_HOST_MASK, 0);

	vmcs_write32(CR3_TARGET_COUNT, 0);

	//TODO: MSR bitmap addresses - all bits shud be set to 0
}

void load_vmentry_control(struct vmcs_config *vmcs_config_ptr)
{
	u32 low, high;
	u32 value;

	rdmsr(MSR_IA32_VMX_ENTRY_CTLS, low, high);
	value = 0x93ff;
	value = value | low;
	value = value & high;

	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config_ptr->vmentry_ctrl);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
				vmcs_config_ptr->vmentry_intr_info_ctrl);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
}

void load_vmexit_control(struct vmcs_config *vmcs_config_ptr)
{
	u32 low, high;
	u32 value;

	rdmsr(MSR_IA32_VMX_EXIT_CTLS, low, high);
	value = 0x336fff;
	value = value | low;
	value = value & high;

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config_ptr->vmexit_ctrl);
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
}

static void enable_feature_control(void)
{
	u64 old, test_bits;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
}

static bool is_xsaves_supported(void)
{
	int eax = 0xD, ebx = 0, ecx = 1, edx = 0;

	__cpuid(&eax, &ebx, &ecx, &edx);

	if ((eax >> 3) & 1)
		return true;

	printk(KERN_ERR "<1> xsaves is not supported.\n");
	return false;
}

static bool is_invpcid_supported(void)
{
	int eax = 0x07, ebx = 0, ecx = 0, edx = 0;

	__cpuid(&eax, &ebx, &ecx, &edx);

	if ((ebx >> 10) & 1)
		return true;

	return false;
}

static bool is_vmx_supported(void)
{
	int recx = 0, redx = 0;
	int eax = 1, ebx = 0;
	int feature_value = 0;

	// First check whether cpu supports vmx
	__cpuid(&eax, &ebx, &recx, &redx);

	if (!((recx >> 5) & 1)) {
		printk(KERN_ERR "<1>CPU doesn't support vmx.\n");
		return false;
	}

	printk(KERN_ERR "<1>CPU supports vmx.\n");

	rdmsrl(MSR_IA32_FEATURE_CONTROL, feature_value);

	if (feature_value & 1) {
		if ((feature_value >> 2) & 1) {
			printk("<1>MSR 0x3A:Lock bit is on. VMXON bit is on. OK\n");
		} else {
			printk("<1>MSR 0x3A:Lock bit is on. VMXON bit is off. Cannot turn on vmxon\n");
			return false;
		}
	} else {
		printk("<1>MSR 0x3A:Lock bit is off. Cannot turn on vmxon\n");
		return false;
	}

	return true;
}

 /*turn on vmxe*/
static void enable_vmxe(void)
{
	unsigned long cr4_value;

	cr4_value = native_read_cr4();

	if (cr4_value & X86_CR4_VMXE) {
		printk("<1> enable_vmxe:  vmxe is already on.\n");
		return;
	}

	asm volatile("movq %cr4, %rax\n"
			"bts $13, %rax\n"
			"movq %rax, %cr4\n");

	printk("<1> turned on cr4.vmxe\n");
}

static void disable_vmxe(void)
{
	asm volatile("movq %cr4, %rax\n");
	asm volatile("btr $13, %rax\n");
	asm volatile("movq %rax, %cr4\n");
}

static void setup_vmcs_memory(void)
{
	int cpu;
	struct vcpu_vmx *vcpu_ptr;
	struct vmcs_config *vmcs_config_ptr;
	u64 phys_addr;

	for_each_online_cpu(cpu) {
		vcpu_ptr = per_cpu_ptr(vcpu, cpu);
		vmcs_config_ptr = per_cpu_ptr(vmcs_config, cpu);

		vcpu_ptr->vcpu_stack = (u64) kmalloc(16384, GFP_KERNEL);
		memset((void *)vcpu_ptr->vcpu_stack, 0, 16384);

		vcpu_ptr->vmxarea = kmalloc(PAGE_SIZE, GFP_KERNEL);
		phys_addr = __pa(vcpu_ptr->vmxarea);

		if (!is_aligned(vcpu_ptr->vmxarea, 0x1000) ||
					!is_aligned(phys_addr, 0x1000)) {
			printk(KERN_ERR "<1>vmxon region address is not aligned.\n");
			return;
		}

		// setup revision id in vmxon region
		vmxon_setup_revid(vcpu_ptr->vmxarea);
		
		vcpu_ptr->pcpu_vmcs = alloc_vmcs_cpu(cpu, vmcs_config_ptr);

		//printk(KERN_ERR "<1> CPU-%d: vmxarea=0x%p, vmxarea-physical=0x%p, pcpu_vmcs=0x%p", cpu, vcpu_ptr->vmxarea, (void *)phys_addr, vcpu_ptr->pcpu_vmcs);
	}

	printk(KERN_ERR "<1> Finish setup vmcs memories.\n");
}

static int switch_to_nonroot_per_cpu(void *data)
{
	struct vcpu_vmx *vcpu_ptr;
	int cpu;
	u64 phys_addr, host_rsp, host_rflags;
	struct vmcs_config *vmcs_config_ptr;
	unsigned long flags;

	int32_t instruction_error_code = 0;

	cpu = get_cpu();
	local_irq_save(flags);

	printk(KERN_ERR "switch_to_nonroot_per_cpu: cpu <%d> Enter.\n", cpu);

	vcpu_ptr = this_cpu_ptr(vcpu);
	
	vmcs_config_ptr = this_cpu_ptr(vmcs_config);

	native_store_gdt(this_cpu_ptr(host_gdt));

	enable_feature_control();

	vcpu_ptr->regs = per_cpu_ptr(reg_scratch, cpu);

	if (!(cr4_read_shadow() & X86_CR4_VMXE))
		cr4_set_bits(cr4_read_shadow() | X86_CR4_VMXE);

	// enable vmx
	enable_vmxe();

	phys_addr = __pa(vcpu_ptr->vmxarea);

	if (cpu_vmxon(phys_addr, cpu) != 0)
		return -1;

	vmcs_load(vcpu_ptr->pcpu_vmcs, cpu);

	load_guest_state_area(cpu);

	load_host_state_area();

	load_execution_control(vmcs_config_ptr);

	load_vmexit_control(vmcs_config_ptr);

	load_vmentry_control(vmcs_config_ptr);

	asm("movq %%rsp, %%rax\n"
		: "=a"(host_rsp));
	vmcs_writel(HOST_RSP, (vcpu_ptr->vcpu_stack + 16384));
	vmcs_writel(GUEST_RSP, host_rsp);

	asm("pushfq\n");
	asm("popq %0\n"
		: "=m"(host_rflags) : : "memory");
	vmcs_writel(GUEST_RFLAGS, host_rflags);

	// host rip vmx_handle_vm_exit
	vmcs_writel(HOST_RIP,
			(unsigned long) vmx_switch_and_exit_handle_vmexit);

	// guest rip
	asm("movq $0x681e, %rdx");
	asm("movq $vmentry_point, %rax");
	asm("vmwrite %rax, %rdx");

	printk(KERN_ERR "<1>Ready to call VMLAUNCH.\n");

	asm volatile(__ex(ASM_VMX_VMLAUNCH) "\n\t");
	asm volatile("jbe vmlaunch_fail\n");
	asm volatile("jmp vmentry_point\n"
				 "vmlaunch_fail:\n");

	is_vmlaunch_fail = 1;

	// read RFlag
	asm volatile("popq %0\n"
			: "=m"(rflags_value)
			:
			: "memory");

	printk(KERN_ERR "<1> VMLaunch has failed, rflags_value=%lx\n",
					rflags_value);

	// Read error
	instruction_error_code = vmcs_readl(VM_INSTRUCTION_ERROR);
	printk(KERN_ERR "<1> VMLaunch has failed, instruction_error_code=%d\n",
					instruction_error_code);

	asm volatile("vmentry_point:\n");

	if (!is_vmlaunch_fail) {
		printk(KERN_ERR "<1> CPU-%d: VmLaunch Done. Enter guest mode.\n", cpu);
	}

	bitmap_set(switch_done, cpu, 1);
	put_cpu();

	local_irq_restore(flags);

	return 0;
}

bool check_vbh_status(void)
{
	return vbh_loaded;
}

//switch to non-root API
int vmx_switch_to_nonroot(void)
{
	int cpu;
	struct task_struct *thread_ptr;

	//on_each_cpu(switch_to_nonroot_per_cpu, NULL, true);

	int cpus = num_online_cpus();

	bitmap_zero(switch_done, cpus);

	spin_lock(&vbh_load_lock);
	
	if (vbh_loaded)
	{
		printk(KERN_ERR "Warning: vbh is loaded already!\n");
		spin_unlock(&vbh_load_lock);
		return -1;
	}
	
	for_each_online_cpu(cpu) {
		thread_ptr = kthread_create(switch_to_nonroot_per_cpu, NULL, "vmx-switch-%d", cpu);
		kthread_bind(thread_ptr, cpu);
		wake_up_process(thread_ptr);
	}

	while (!bitmap_equal((const long unsigned *)&all_cpus,
			(const long unsigned *)&switch_done, cpus)) {
		schedule();
	}

	vbh_loaded = 1;
	spin_unlock(&vbh_load_lock);
	
	printk(KERN_ERR "vmx_switch_to_nonroot: exit.\n");

	return 0;
}
//EXPORT_SYMBOL(vmx_switch_to_nonroot);

pgd_t *init_process_cr3(void)
{
	struct task_struct *task;

	for_each_process(task)
		if (task->pid == (pid_t) 1)
			return task->mm->pgd;

	return NULL;
}

static int __init cpu_switch_init(void)
{
	vbh_loaded = 0;
	
	if (!is_vmx_supported())
		goto err;

	bitmap_fill((long unsigned *)&all_cpus, num_online_cpus());

	vcpu = alloc_percpu(struct vcpu_vmx);
	if (vcpu == NULL) {
		printk(KERN_ERR "<1>Cannot allocate memory for vcpu\n");
		return -ENOMEM;
	}

	host_gdt = alloc_percpu(struct desc_ptr);
	if (host_gdt == NULL) {
		printk(KERN_ERR "Cannot allocate memory for host_gdt\n");
		return -ENOMEM;
	}

	vmcs_config = alloc_percpu(struct vmcs_config);
	if (vmcs_config == NULL) {
		printk(KERN_ERR "<1>Cannot allocate memory for vmcs_config\n");
		return -ENOMEM;
	}

	printk(KERN_ERR "<1> vcpu=0x%p, host_gdt=0x%p, vmcs_config=0x%p, reg_scratch=0x%p\n",
			vcpu, host_gdt, vmcs_config,
			reg_scratch);

	on_each_cpu(setup_vmcs_config, NULL, true);

	setup_vmcs_memory();

	host_cr3 = init_process_cr3();
	if (!host_cr3)
		goto err;

	vmx_eptp_pml4 =  (unsigned long *)__get_free_page(GFP_KERNEL);
	memset(vmx_eptp_pml4, 0, PAGE_SIZE);

	setup_ept_tables();
	
	if (switch_on_load)
		vmx_switch_to_nonroot();

err:
	return 0;
}

void unload_vbh_per_cpu(void *info)
{
	struct vcpu_vmx *vcpu_ptr;

	// Turn off vm
	if (vmxon_success) {
		printk(KERN_ERR "<1> kernel_hardening_unload: Ready to send VMXOFF.\n");
		asm volatile(ASM_VMX_VMXOFF);
	}

	disable_vmxe();

	vcpu_ptr = this_cpu_ptr(vcpu);
	if (vcpu_ptr && vcpu_ptr->vcpu_stack != 0)
		kfree((void *)(vcpu_ptr->vcpu_stack));

	if (vcpu_ptr && vcpu_ptr->vmxarea != NULL)
		kfree(vcpu_ptr->vmxarea);
}

static void cpu_switch_exit(void)
{
	int cpus;

	cpus = num_online_cpus();

	printk(KERN_ERR "<1> Trying to unload...");

	on_each_cpu(unload_vbh_per_cpu, NULL, true);

	if (vcpu != NULL) {
		free_percpu(vcpu);
	}

	if (host_gdt != NULL) {
		free_percpu(host_gdt);
	}

	if (vmcs_config != NULL)
		free_percpu(vmcs_config);
	
	vbh_loaded = 0;

	printk(KERN_ERR "module vmx-switch unloaded\n");
}

module_init(cpu_switch_init);
module_exit(cpu_switch_exit);
MODULE_LICENSE("GPL");
