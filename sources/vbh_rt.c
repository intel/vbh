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
#include <asm/vmx.h>
#include <asm/msr-index.h>
#include <asm/special_insns.h>

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>

#include "vmx_common.h"
#include "vbh_status.h"

#define CR0	0
#define CR3	3
#define CR4	4

#define VMX_EPTP_MT_WB		0x6ull
#define VMX_EPTP_PWL_4		0x18ull

#define	NR_LOAD_MSRS		8
#define NR_STORE_MSRS		8

#define MOV_TO_CR		0

#define EXIT_REASON_INIT        3

#define EXIT_REASON_INIT        3
#define VMX_AR_DPL_SHIFT        5
#define VMX_AR_DPL(ar)          (((ar) >> VMX_AR_DPL_SHIFT) & 3)

static struct vmx_capability vmx_cap;

static int inject_pending_vcpu_exceptions(struct vcpu_vmx *vcpu);
static int inject_exception(struct vcpu_vmx *vcpu, u32 exception, u32 error_code);
static int mark_exception_for_injection(struct vcpu_vmx *vcpu, u32 exception, exception_additional_info additional_info);

typedef struct _exception_details
{
    char    *name;
    u8      is_available;
    u8      has_error_code;
    u8      has_specific_info;
}exception_details;

static const exception_details exception_info[NUMBER_OF_RESERVED_EXCEPTIONS] = 
{
    [X86_TRAP_DE] =     {.name = "Divide Error",                        .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_DB] =     {.name = "Debug Exception",                     .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_NMI] =    {.name = "NMI Interrupt",                       .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_BP] =     {.name = "Breakpoint",                          .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_OF] =     {.name = "Overflow",                            .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_BR] =     {.name = "Bound Range Exceeded",                .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_UD] =     {.name = "Invalid Opcode",                      .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_NM] =     {.name = "Device Not Available",                .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_DF] =     {.name = "Double Fault",                        .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_TS] =     {.name = "Invalid TSS",                         .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_NP] =     {.name = "Segment Not Present",                 .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_SS] =     {.name = "Stack-Segment Fault",                 .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_GP] =     {.name = "General Protection",                  .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_PF] =     {.name = "Page Fault",                          .is_available = 1, .has_error_code = 1, .has_specific_info = 1},
    [X86_TRAP_MF] =     {.name = "Math Fault",                          .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_AC] =     {.name = "Alignment Check",                     .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_MC] =     {.name = "Machine Check",                       .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_XF] =     {.name = "SIMD Floating-Point Exception",       .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
};


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

	asm volatile(__ex(VBH_ASM_VMX_INVEPT)
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

static u32 get_cpl(void)
{
	u32 access_rights;
	access_rights = vmcs_read32(GUEST_SS_AR_BYTES);
	
	return VMX_AR_DPL(access_rights);
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

//	Description:	A method for handling guest software exceptions
int handle_exception_exit(void)
{
	int error = 0;
    exception_additional_info additional_info = {0};

    vm_entry_int_info interruption_information = 
		vm_entry_info_unpack(vmcs_read32(VM_EXIT_INTR_INFO));

	u32 interruption_error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);

	int allow = 0;
	error = hvi_handle_exception(interruption_information, interruption_error_code, &allow);
	if (error) {
		pr_err("vmx-root: %s failed with error: %d\n", __func__, error);
		return error;
	} else if (allow) {		
		//	Reinject the exception
        additional_info.exception_error_code = interruption_error_code;
		mark_exception_for_injection(this_cpu_ptr(vcpu), interruption_information.fields.vector, additional_info);
	}

    if (!allow)
    {
		// In this case we want to skip the instruction that generated the exception that was handled 
        vmx_switch_skip_instruction();
    }

    return error;
}
void handle_ept_violation(struct vcpu_vmx *vcpu)
{
	unsigned long exit_qual = vmcs_readl(EXIT_QUALIFICATION);
	unsigned long long gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	unsigned long gla = vmcs_readl(GUEST_LINEAR_ADDRESS);
	unsigned long g_rsp, g_rip;

	int allow = 0;

	g_rsp = vmcs_readl(GUEST_RSP);
	g_rip = vmcs_readl(GUEST_RIP);

	pr_err("EPT_VIOLATION at GPA -> 0x%llx GVA -> 0x%lx, exit_qulification = 0x%lx, G_RSP = 0x%lx, G_RIP=0x%lx\n",
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

	int cpl = get_cpl();

	if (cpl != 0)
		goto out;

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

out:
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
    int error = 0;
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
	vcpu_ptr->cr2 = read_cr2();
	reg_area[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
	reg_area[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);

	vmexit_reason = vmcs_read32(VM_EXIT_REASON);
	vcpu_ptr->instruction_skipped = false;
	vcpu_ptr->skip_instruction_not_used = false;

	switch (vmexit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		pr_err("<1> vmexit_reason: EXIT_REASON_EXCEPTION_NMI or EXCEPTION_EXIT\n");
		handle_exception_exit();
		break;
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
        vmx_switch_skip_instruction();
		break;
	}

    // At the end of every vmexit, inject pending interrupts/exceptions
    error = inject_pending_vcpu_exceptions(vcpu_ptr);
    if (error)
    {
        pr_err("inject_pending_vcpu_exceptions failed with error = 0x%016X !\n", error);
    }

	if (vcpu_ptr->instruction_skipped == true)
		vmcs_writel(GUEST_RIP, reg_area[VCPU_REGS_RIP]);

	if (vcpu_ptr->cr2 != read_cr2())
		write_cr2(vcpu_ptr->cr2);

	put_cpu();
}

void vmx_switch_skip_instruction(void)
{
	struct vcpu_vmx *vcpu_ptr;

	vcpu_ptr = this_cpu_ptr(vcpu);
	skip_emulated_instruction(vcpu_ptr);
}

int inject_trap(int vcpu_nr, u8 trap_number, u32 error_code, u64 cr2)
{
    struct vcpu_vmx *vcpu_ptr = NULL;
    exception_additional_info additional_info = {0};

    vcpu_ptr = (struct vcpu_vmx*)get_vcpu(vcpu_nr);
    if(vcpu_ptr != this_cpu_ptr(vcpu))
    {
        // Function not implemented
        // For now we can only inject on the current vcpu.
        return -ENOSYS;
    }

    additional_info.exception_error_code = error_code;
    switch (trap_number)
    {
        case X86_TRAP_PF:
        {
            additional_info.specific_additional_info.page_fault_specific.virtual_address = cr2;
            set_bit(virtual_address, additional_info.specific_additional_info.page_fault_specific.field_is_ok);
            
            break;
        }
        default:
        {
            break;
        }
    }

    return mark_exception_for_injection(vcpu_ptr, trap_number, additional_info);
}

static int mark_exception_for_injection(struct vcpu_vmx *vcpu, u32 exception, exception_additional_info additional_info)
{	
    if ((exception >= NUMBER_OF_RESERVED_EXCEPTIONS)|| (!(exception_info[exception].is_available)))
    {
        return -EINVAL;
    }

    vcpu->vcpu_exception.exception_injection_mask |= VCPU_INJECT_EXCEPTION_MASK(exception);
    vcpu->vcpu_exception.additional_info[exception] = additional_info;
    
    return 0;
}

static int inject_pending_vcpu_exceptions(struct vcpu_vmx *vcpu)
{
    // The order is the following, based on Intel System Programming Manual:
    // Chapter 6.9: Priority Among Simultaneous Exceptions and Interrupts
    //   INIT / SIPI
    //   Breakpoint
    //   NMI
    //   Hardware interrupts (PIC, LAPIC)
    //   Low priority exceptions (GP etc)

    //
    //  1. Hardware resets / MC
    //  2. Trap on TSS
    //  3. External hardware interventions (flush, stopclk, SMI, INIT)
    //  4. Traps on the previous instruction (breakpoints, debug trap exceptions)
    //  5. NMI
    //  6. Maskable hardware interrupts
    //  7. Code breakpoint fault
    //  8. Faults from fetching next instruction (code-segment limit violation, code page fault)
    //  9. Faults from decoding next instruction (instruction length > 15, invalid opcode, coprocessor not available)
    // 10. Fault on executing an instruction (overflow, bound error, invalid TSS, segment not present, stack fault, GP, data page fault,
    //     alignment check, x87 FPU FP exception, SIMD FP exception)
    //
	int error = 0;
    exception_additional_info additional_info;

    if (vcpu == NULL)
    {
        return -EINVAL;
    }

    // If there's nothing in pending
    if (vcpu->vcpu_exception.exception_injection_mask == 0x0)
    {
        return 0;
    }

    if (vcpu->vcpu_exception.exception_injection_mask & VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_PF))
    {
        additional_info = vcpu->vcpu_exception.additional_info[X86_TRAP_PF];
        
        // Reset the injection flag.
        vcpu->vcpu_exception.exception_injection_mask &= ~(VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_PF));

        // Effectively inject a PF
        error = inject_exception(vcpu, X86_TRAP_PF, additional_info.exception_error_code);
        if (error)
        {
            pr_err("inject_exception failed with error = 0x%016X !\n", error);
			return error;
        }

        // Handle specific info, if exist and valid
        if(!(exception_info[X86_TRAP_PF].has_specific_info))
        {
            return 0;
        }

        //
        // If inject_exception succeeded, then we can handle exception custom informations
        //
        // Is virtual_address field from additional_info valid?
        if(test_bit(virtual_address, additional_info.specific_additional_info.page_fault_specific.field_is_ok))
        {
            //vcpu->regs[VCPU_REGS_CR2] = additional_info.specific_additional_info.page_fault_specific.virtual_address;
            vcpu->cr2 = additional_info.specific_additional_info.page_fault_specific.virtual_address;
        }

        return 0;
    }

    // Debug exception
    if (vcpu->vcpu_exception.exception_injection_mask & VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_BP))
    {
        // Reset the injection flag.
        vcpu->vcpu_exception.exception_injection_mask &= ~(VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_BP));

        // Effectively inject
        error = inject_exception(vcpu, X86_TRAP_BP, 0);
        if (error)
        {
            pr_err("inject_exception failed with error = 0x%016X !\n", error);
			return error;
        }
        
        return 0;
    }

	// Command is not implemened
	return -EOPNOTSUPP;
}

static int inject_exception(struct vcpu_vmx *vcpu, u32 exception, u32 error_code)
{
    u64 guest_cr0;
    u32 entry_interruption_information_raw = 0;
    vm_entry_int_info entry_interruption_information;

    printk(KERN_INFO "inject_exception exception = 0x%016X, name = %s\n", exception, exception_info[exception].name);
    
    entry_interruption_information.value = 0;

    // Read guest cr0
    guest_cr0 = vmcs_readl(GUEST_CR0);

    // Populate interruption information fields
    entry_interruption_information.fields.valid = 1;
    entry_interruption_information.fields.vector = exception;

    // If ProtectedMode bit is set in CR0 (bit0) and the vector is at most 31,
    // the event should be injected as a HardwareException
    if ((guest_cr0 & PE) == 0)
    {
        entry_interruption_information.fields.interruption_type = INTERRUPTION_TYPE_EXTERNAL_INTERRUPT;
        entry_interruption_information.fields.deliver_error_code = 0;
        
        goto inject;
    }

    if(exception == X86_TRAP_BP)
    {
        // Software exception
        entry_interruption_information.fields.interruption_type = INTERRUPTION_TYPE_SOFTWARE_EXCEPTION;

        // If VM entry successfully injects (with no nested exception) an event with interruption type software
        // interrupt, privileged software exception, or software exception, the current guest RIP is incremented by the
        // VM-entry instruction length before being pushed on the stack.
        vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 0);

        goto inject;
    }
    else
    {
        entry_interruption_information.fields.interruption_type = INTERRUPTION_TYPE_HARDWARE_EXCEPTION;
    }
    
    if (exception_info[exception].has_error_code)
    {
        entry_interruption_information.fields.deliver_error_code = 1;
        vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
    }

inject:
    entry_interruption_information_raw = vm_entry_info_pack(entry_interruption_information);
    vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, entry_interruption_information_raw);

    return 0;
}
