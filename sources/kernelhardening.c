#include <linux/kernel.h>
#include <linux/smp.h>
#include <asm/vmx.h>
#include "vmx_common.h"

extern unsigned long *vmx_msr_bitmap_switch;
extern void vmx_switch_skip_instruction(void);

static void enable_msr_control(unsigned long msr, unsigned long* bitmap);
static void disable_msr_control(unsigned long msr, unsigned long* bitmap);

void vmx_switch_update_cr_mask (bool enable, unsigned long mask, unsigned long mask_reg, unsigned long guest_reg, unsigned long shadow_reg);
void vmx_switch_update_msr_control(bool enable, unsigned long msr_reg, unsigned int type);

void handle_read_msr(struct vcpu_vmx *vcpu);
void handle_write_msr(struct vcpu_vmx *vcpu);


void post_handle_vmexit_mov_to_cr (void)
{
	vmx_switch_skip_instruction();
}

void handle_cr_monitor_req(cpu_control_params_t* cpu_param)
{
	switch (cpu_param->cpu_reg) {
		case CPU_REG_CR0:
			vmx_switch_update_cr_mask(cpu_param->enable, cpu_param->mask, CR0_GUEST_HOST_MASK, GUEST_CR0, CR0_READ_SHADOW);
			break;
		case CPU_REG_CR4:
			vmx_switch_update_cr_mask(cpu_param->enable, cpu_param->mask, CR4_GUEST_HOST_MASK, GUEST_CR4, CR4_READ_SHADOW);
			break;
		
		default:
			break;				
	}
}

void handle_msr_monitor_req(msr_control_params_t* msr_param)
{
	// TODO:  msr_write only?
	vmx_switch_update_msr_control(msr_param->enable, msr_param->msr_reg, MSR_TYPE_W);		
}

void handle_kernel_hardening_hypercall (u64 params)
{
	vmcall_params_t *vmcall_params = (vmcall_params_t *)params;
	
	printk(KERN_ERR "<1>handle_kernel_hardening_hypercall: req_id=%d", vmcall_params->id);
	switch (vmcall_params->id) {
		case CPU_MONITOR_REQ:
			handle_cr_monitor_req((cpu_control_params_t*)vmcall_params->params) ;
			break;
		case MSR_MONITOR_REQ:
			handle_msr_monitor_req((msr_control_params_t*)vmcall_params->params);
			break;
		default:
			break;
	}
}

void vmx_switch_update_cr_mask(bool enable, unsigned long mask, unsigned long mask_reg, unsigned long guest_reg, unsigned long shadow_reg)
{
	unsigned long current_mask = vmcs_readl(mask_reg);
	unsigned long guest_value = vmcs_readl(guest_reg);
	
	bool root_owned = false;

	printk(KERN_ERR "vmx_switch_update_cr_mask called on %x\n", smp_processor_id());

	if ((current_mask & mask) == mask) {
		printk(KERN_ERR "mask %lx is already owned by vmx root", mask);
		root_owned = true;
	}

	if (enable) {
		if (!root_owned) {
			printk(KERN_ERR "update_cr0_mask done successfully\n");
			current_mask = current_mask | mask;
			vmcs_writel(mask_reg, current_mask);
			vmcs_writel(shadow_reg, guest_value);
		}
	}
	else {
		if (root_owned) {
			current_mask = current_mask & ~mask;
			vmcs_writel(mask_reg, current_mask);
		}
	}	
}

void vmx_switch_update_msr_control(bool enable, unsigned long msr, unsigned int type)
{	
	int f = sizeof(unsigned long);		
	
	if (type == MSR_TYPE_R)
	{
		if (LOW_MSR_RANGE_LOW <= msr && msr <= LOW_MSR_RANGE_HIGH)
		{
			if (enable)
				enable_msr_control(msr, vmx_msr_bitmap_switch + 0x000 / f);
			else
				disable_msr_control(msr, vmx_msr_bitmap_switch + 0x000 / f);
		}
		else if (HI_MSR_RANGE_LOW <= msr && msr <= HI_MSR_RANGE_HIGH)
		{
			if (enable)
				enable_msr_control(msr & 0x1FFF, vmx_msr_bitmap_switch + 0x400 / f);
			else
				disable_msr_control(msr & 0x1FFF, vmx_msr_bitmap_switch + 0x400 / f);
		}
	}
	else if (type == MSR_TYPE_W)
	{
		if (LOW_MSR_RANGE_LOW <= msr && msr <= LOW_MSR_RANGE_HIGH)
		{
			if (enable)
				enable_msr_control(msr, vmx_msr_bitmap_switch + 0x800 / f);
			else
				disable_msr_control(msr, vmx_msr_bitmap_switch + 0x800 / f);
		}
		else if (HI_MSR_RANGE_LOW <= msr && msr <= HI_MSR_RANGE_HIGH)
		{
			if (enable)
				enable_msr_control(msr & 0x1FFF, vmx_msr_bitmap_switch + 0xC00 / f);
			else
				disable_msr_control(msr & 0x1FFF, vmx_msr_bitmap_switch + 0xC00 / f);
		}		
	}
}

static void enable_msr_control(unsigned long msr, unsigned long* bitmap)
{
	set_bit(msr, bitmap);			
		
	// write updated msr bitmask value back		
	vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_switch));
}

static void disable_msr_control(unsigned long msr, unsigned long* bitmap)
{
	clear_bit(msr, bitmap);
	
	// write updated msr bitmask value back		
	vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_switch));
}
