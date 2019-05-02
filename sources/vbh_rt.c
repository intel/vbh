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
#include <linux/stop_machine.h>
#include <linux/delay.h>

#include <linux/cpufeature.h>
#include <asm/cpufeatures.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <linux/kvm_host.h>
#include <asm/vmx.h>
#include <asm/msr-index.h>
#include <asm/special_insns.h>

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>

#include "vmx_common.h"

#define __ex(x) x

#define CR0	0
#define CR3	3
#define CR4	4

#define VMX_EPTP_MT_WB		0x6ull
#define VMX_EPTP_PWL_4		0x18ull

#define	NR_LOAD_MSRS		8
#define NR_STORE_MSRS		8

#define MOV_TO_CR		0

#define EXIT_REASON_INIT        3

struct vmx_capability {
	u32 ept;
	u32 vpid;
};

static struct vmx_capability vmx_cap;

static inline void vbh_invept(int ext, u64 eptp, u64 gpa);

static void cpu_has_vmx_invept_capabilities(bool *context, bool *global);

unsigned long *get_scratch_register(void)
{
	unsigned long *reg_ptr;

	reg_ptr = this_cpu_ptr(reg_scratch);

	return reg_ptr;
}

void *get_vcpu(int cpu)
{
	int me = smp_processor_id();

	if (cpu == me)
		return this_cpu_ptr(vcpu);
	else
		return per_cpu_ptr(vcpu, cpu);
}

static void cpu_has_vmx_invept_capabilities(bool *context, bool *global)
{
	if (vmx_cap.ept == 0 && vmx_cap.vpid == 0)
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, vmx_cap.ept, vmx_cap.vpid);

	*context = vmx_cap.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
	*global = vmx_cap.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

static inline void vbh_invept(int ext, u64 eptp, u64 gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = { eptp, gpa };

	pr_err("<1> cpu_switch_invept: ext=%d, eptp=0x%llx, gpa=0x%llx",
		ext, eptp, gpa);

	asm volatile(__ex(ASM_VMX_INVEPT)
		:
		: "a" (&operand), "c" (ext)
		: "cc", "memory"
	);
}

void vbh_tlb_shootdown(void)
{
	bool global, context;

	cpu_has_vmx_invept_capabilities(&context, &global);

	if (global)
		vbh_invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
	else if (context)
		vbh_invept(VMX_EPT_EXTENT_CONTEXT, __pa(vmx_eptp_pml4), 0);
	else
		pr_err("<1> ERROR:  Unsupported EPT EXTENT!!!!\n");
}

static void skip_emulated_instruction(struct vcpu_vmx *vcpu)
{
	unsigned long rip;

	if (!vcpu->skip_instruction_not_used) {
		rip = vcpu->regs[VCPU_REGS_RIP];
		rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		vcpu->regs[VCPU_REGS_RIP] = rip;
		vcpu->instruction_skipped = true;
	}
}

void handle_cpuid(struct vcpu_vmx *vcpu)
{
	u32 eax, ebx, ecx, edx;

	eax = vcpu->regs[VCPU_REGS_RAX];
	ecx = vcpu->regs[VCPU_REGS_RCX];
	native_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->regs[VCPU_REGS_RAX] = eax;
	vcpu->regs[VCPU_REGS_RBX] = ebx;
	vcpu->regs[VCPU_REGS_RCX] = ecx;
	vcpu->regs[VCPU_REGS_RDX] = edx;
	skip_emulated_instruction(vcpu);
}

void handle_ept_violation(struct vcpu_vmx *vcpu)
{
	unsigned long exit_qual = vmcs_readl(EXIT_QUALIFICATION);
	unsigned long long gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	unsigned long long gla = vmcs_read64(GUEST_LINEAR_ADDRESS);
	unsigned long g_rsp, g_rip;

	int allow = 0;

	g_rsp = vmcs_readl(GUEST_RSP);
	g_rip = vmcs_readl(GUEST_RIP);

	pr_err("EPT_VIOLATION at GPA -> 0x%llx GVA -> 0x%llx, exit_qulification = 0x%lx, G_RSP = 0x%lx, G_RIP=0x%lx\n",
		gpa, gla, exit_qual, g_rsp, g_rip);

	if (hvi_handle_ept_violation(gpa, gla, &allow))
		pr_err("vmx-root: hvi_handle_ept_violation failed\n");

    // Skip the instruction regardless the value of allow.
    // TODO: skip only if allow is false.
	vmx_switch_skip_instruction();
}

void handle_vmcall(struct vcpu_vmx *vcpu)
{
	u64 hypercall_id;
	u64 params;

	hypercall_id = vcpu->regs[VCPU_REGS_RAX];
	params = vcpu->regs[VCPU_REGS_RBX];

	pr_err("<1> %s: hypercall_id = 0x%llx, params = %p",
		__func__, hypercall_id, (void *)params);
	switch (hypercall_id) {
	case KERNEL_HARDENING_HYPERCALL:
		handle_kernel_hardening_hypercall(params);
		break;
	case VCPU_REQUEST_HYPERCALL:
		handle_vcpu_request_hypercall(vcpu, params);
		break;
	case DFO_HYPERCALL:
		hvi_handle_event_dfo((int *)params);
		break;
	default:
		hvi_handle_event_vmcall();
		break;
	}
	skip_emulated_instruction(vcpu);
}

void handle_read_msr(struct vcpu_vmx *vcpu)
{
	u32 low, high;
	unsigned long msr;

	// msr should be in rcx
	msr = vcpu->regs[VCPU_REGS_RCX];

	rdmsr(msr, low, high);

	// Debug only
	pr_err("<1> %s: Value of msr 0x%lx: low=0x%x, high=0x%x\n",
		__func__, msr, low, high);

	// save msr value into rax and rdx
	vcpu->regs[VCPU_REGS_RAX] = low;
	vcpu->regs[VCPU_REGS_RDX] = high;

	vmx_switch_skip_instruction();
}

void handle_write_msr(struct vcpu_vmx *vcpu)
{
	u32 low, high, new_low, new_high;
	unsigned long old_value, new_value;
	unsigned long msr;
	int allow = 0;

	// msr should be in rcx
	msr = vcpu->regs[VCPU_REGS_RCX];

	new_low = vcpu->regs[VCPU_REGS_RAX];
	new_high = vcpu->regs[VCPU_REGS_RDX];

	new_value = (unsigned long)new_high << 32 | new_low;

	// Get old value
	rdmsr(msr, low, high);
	old_value = (unsigned long)high << 32 | low;

	hvi_handle_event_msr(msr, old_value, new_value, &allow);

	// hvi decides whether wrmsr is permitted or not.
	if (allow)
		wrmsr(msr, new_low, new_high);

	vmx_switch_skip_instruction();
}

void handle_mtf(struct vcpu_vmx *vcpu)
{
	// TODO: report event.  What format?
}

void handle_cr(struct vcpu_vmx *vcpu)
{
	unsigned long exit_qual, val;
	int cr;
	int type;
	int reg;
	unsigned long old_value;

	int allow = 0;

	int cpu = smp_processor_id();

	exit_qual = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qual & 15;
	type = (exit_qual >> 4)	& 3;
	reg = (exit_qual >> 8) & 15;

	switch (type) {
	case MOV_TO_CR:
		switch (cr) {
		case CR0:
			allow = 0;
			old_value = vmcs_readl(GUEST_CR0);
			val = vcpu->regs[reg];
			pr_err("<1> cpu-%d EXIT on cr0 access: old value %lx, new value %lx",
				cpu, old_value, val);

			// report event
			hvi_handle_event_cr(cr, old_value, val, &allow);

			// write the new value to shadow register
			// only if allowed
			if (allow)
				vmcs_writel(CR0_READ_SHADOW, val);

			// skip next instruction
			post_handle_vmexit_mov_to_cr();
			break; // CR0
		case CR4:
			allow = 0;
			old_value = vmcs_readl(GUEST_CR4);
			val = vcpu->regs[reg];
			pr_err("<1> cpu-%d EXIT on cr4 access: old value %lx, new value %lx",
				cpu, old_value, val);

			// report event
			hvi_handle_event_cr(cr, old_value, val, &allow);

			// write the new value to shadow register
			// only if allowed
			if (allow)
				vmcs_writel(CR4_READ_SHADOW, val);

			// skip next instruction
			post_handle_vmexit_mov_to_cr();
			break;	// CR4
		default:
			break;
		} //MOV_TO_CR
	default:
		break;
	}
}

void vcpu_exit_request_handler(unsigned int request)
{
	int cpu;

	cpu = smp_processor_id();

	// use vmcall to enter root mode
	asm_make_vmcall(request, NULL);

	pr_err("<1> CPU-[%d] %s is back to guest.\n",
		cpu, __func__);
}

void vmx_switch_and_exit_handler (void)
{
	unsigned long *reg_area;
	struct vcpu_vmx *vcpu_ptr;
	u32 vmexit_reason;
	u64 gpa;
	int id = -1;

	id = get_cpu();

	reg_area = per_cpu_ptr(reg_scratch, id);

	if (reg_area == NULL) {
		pr_err("%s: Failed to get reg_area!\n", __func__);
		return;
	}

	vcpu_ptr = this_cpu_ptr(vcpu);
	reg_area[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
	reg_area[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
	reg_area[VCPU_REGS_RFLAG] = vmcs_readl(GUEST_RFLAGS);

	vmexit_reason = vmcs_readl(VM_EXIT_REASON);
	vcpu_ptr->instruction_skipped = false;
	vcpu_ptr->skip_instruction_not_used = false;

	switch (vmexit_reason) {
	case EXIT_REASON_CPUID:
		handle_cpuid(vcpu_ptr);
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
		pr_err("<1> vmexit_reason: guest physical address 0x%llx resulted in EPT_MISCONFIG\n",
			gpa);
		dump_entries(gpa);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		pr_err("<1> vmexit_reason: EPT_VIOLATION\n");
		handle_ept_violation(vcpu_ptr);
		break;
	case EXIT_REASON_VMCALL:
		pr_err("<1> vmexit_reason: VMCALL\n");
		handle_vmcall(vcpu_ptr);
		break;
	case EXIT_REASON_CR_ACCESS:
		pr_err("<1> vmexit_reason: CR_ACCESS.\n");
		handle_cr(vcpu_ptr);
		break;
	case EXIT_REASON_MSR_READ:
		pr_err("<1> vmexit_reason: MSR_READ.\n");
		handle_read_msr(vcpu_ptr);
		break;
	case EXIT_REASON_MSR_WRITE:
		handle_write_msr(vcpu_ptr);
		break;
	case EXIT_REASON_INIT:
		pr_err("<1> vmexit reason: INIT on cpu-[%d].\n", id);
		handle_vcpu_request_hypercall(vcpu_ptr, 0);
		break;
	case EXIT_REASON_MONITOR_TRAP_FLAG:
		pr_err("<1> vmexit_reason: MONITOR_TRAP_FLAG.\n");
		handle_mtf(vcpu_ptr);
		break;
	case EXIT_REASON_VMOFF:
		// Should never reach here
		pr_err("<1> vmexit_reason: vmxoff.\n");
		break;
	default:
		pr_err("<1> CPU-%d: Unhandled vmexit reason 0x%x.\n",
			id, vmexit_reason);
		break;
	}

	if (vcpu_ptr->instruction_skipped == true)
		vmcs_writel(GUEST_RIP, reg_area[VCPU_REGS_RIP]);

	put_cpu();
}

void vmx_switch_skip_instruction(void)
{
	struct vcpu_vmx *vcpu_ptr;

	vcpu_ptr = this_cpu_ptr(vcpu);
	skip_emulated_instruction(vcpu_ptr);
}
