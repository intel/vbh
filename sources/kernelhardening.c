#include <linux/kernel.h>
#include <linux/smp.h>
#include <asm/vmx.h>
#include "vmx_common.h"
#include "vbh_status.h"

static void enable_msr_control(unsigned long msr, unsigned long *bitmap);
static void disable_msr_control(unsigned long msr, unsigned long *bitmap);

static void vbh_update_cr_mask(bool enable, unsigned long mask,
	unsigned long mask_reg, unsigned long guest_reg,
	unsigned long shadow_reg);

static void vbh_update_msr_control(bool enable, unsigned long msr_reg,
	unsigned int type);

void post_handle_vmexit_mov_to_cr(void)
{
	vmx_switch_skip_instruction();
}

void handle_cr_monitor_req(cpu_control_params_t *cpu_param)
{
	switch (cpu_param->cpu_reg) {
	case CPU_REG_CR0:
		vbh_update_cr_mask(cpu_param->enable, cpu_param->mask,
			CR0_GUEST_HOST_MASK, GUEST_CR0, CR0_READ_SHADOW);
		break;
	case CPU_REG_CR4:
		vbh_update_cr_mask(cpu_param->enable, cpu_param->mask,
			CR4_GUEST_HOST_MASK, GUEST_CR4, CR4_READ_SHADOW);
		break;
	default:
		break;
	}
}

void handle_msr_monitor_req(msr_control_params_t *msr_param)
{
	// TODO:  msr_write only?
	vbh_update_msr_control(msr_param->enable,
		msr_param->msr_reg, MSR_TYPE_W);
}

void handle_kernel_hardening_hypercall(u64 params)
{
	vmcall_params_t *vmcall_params = (vmcall_params_t *)params;

	pr_err("<1> %s: req_id=%d", __func__, vmcall_params->id);
	switch (vmcall_params->id) {
	case CPU_MONITOR_REQ:
		handle_cr_monitor_req(
			(cpu_control_params_t *)vmcall_params->params);
		break;
	case MSR_MONITOR_REQ:
		handle_msr_monitor_req(
			(msr_control_params_t *)vmcall_params->params);
		break;
	default:
		break;
	}
}

//	Description:	The method called from vmx-root in order to update the exception bitmap,
//					page fault code match and page fault code mask 
//	In:				exception_bitmap_update_params = pointer to a exception_bitmap_params_t structure that contains data by
//					which the exception bitmap will be updated
//	Out:			0 if success, else error
int handle_ex_bitmap_update_hypercall(exception_bitmap_params_t *exception_bitmap_update_params)
{
	exception_bitmap_update_flags flags;

	flags = update_flags_unpack(exception_bitmap_update_params->update_flags);
	
	if (flags.update_exception_bitmap)
	{
		printk(KERN_INFO "Update exception bitmap on cpu %d.\n", smp_processor_id());
		vmcs_write32(EXCEPTION_BITMAP, exception_bitmap_update_params->ex_bitmap_structure);
	}
	if (flags.update_exception_pagefault_mask)
	{
		printk(KERN_INFO "Update exception page fault mask on cpu %d.\n", smp_processor_id());
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, exception_bitmap_update_params->pagefault_mask);
	}
	if (flags.update_exception_pagefault_match)
	{
		printk(KERN_INFO "Update exception page fault match on cpu %d.\n", smp_processor_id());
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, exception_bitmap_update_params->pagefault_match);
	}

	return 0;
}

void vbh_update_cr_mask(bool enable, unsigned long mask,
	unsigned long mask_reg, unsigned long guest_reg,
	unsigned long shadow_reg)
{
	unsigned long current_mask = vmcs_readl(mask_reg);
	unsigned long guest_value = vmcs_readl(guest_reg);

	bool root_owned = false;

	if ((current_mask & mask) == mask) {
		pr_err("mask %lx is already owned by vmx root.\n", mask);
		root_owned = true;
	}

	if (enable) {
		if (!root_owned) {
			pr_err("update_cr_mask on guest_reg=0x%lx done successfully.\n",
				guest_reg);
			current_mask = current_mask | mask;
			vmcs_writel(mask_reg, current_mask);
			vmcs_writel(shadow_reg, guest_value);
		}
	} else {
		if (root_owned) {
			pr_err("update_cr_mask on guest_reg=0x%lx root owned cr_mask is disabled.\n",
				guest_reg);
			current_mask = current_mask & ~mask;
			vmcs_writel(mask_reg, current_mask);
		}
	}
}

void vbh_update_msr_control(bool enable, unsigned long msr, unsigned int type)
{
	int f = sizeof(unsigned long);

	pr_err("<1> %s: enable=%d, msr=0x%lx, type=%d.\n",
		__func__, enable, msr, type);

	if (type == MSR_TYPE_R) {
		if (msr >= LOW_MSR_RANGE_LOW && msr <= LOW_MSR_RANGE_HIGH) {
			if (enable)
				enable_msr_control(msr,
				vmx_msr_bitmap_switch + 0x000 / f);
			else
				disable_msr_control(msr,
				vmx_msr_bitmap_switch + 0x000 / f);
		} else if (msr >= HI_MSR_RANGE_LOW &&
			msr <= HI_MSR_RANGE_HIGH) {
			if (enable)
				enable_msr_control(msr & 0x1FFF,
				vmx_msr_bitmap_switch + 0x400 / f);
			else
				disable_msr_control(msr & 0x1FFF,
				vmx_msr_bitmap_switch + 0x400 / f);
		}
	} else if (type == MSR_TYPE_W) {
		if (msr >= LOW_MSR_RANGE_LOW &&
			msr <= LOW_MSR_RANGE_HIGH) {
			if (enable)
				enable_msr_control(msr,
				vmx_msr_bitmap_switch + 0x800 / f);
			else
				disable_msr_control(msr,
					vmx_msr_bitmap_switch + 0x800 / f);
		} else if (msr >= HI_MSR_RANGE_LOW &&
			msr <= HI_MSR_RANGE_HIGH) {
			if (enable)
				enable_msr_control(msr & 0x1FFF,
				vmx_msr_bitmap_switch + 0xC00 / f);
			else
				disable_msr_control(msr & 0x1FFF,
				vmx_msr_bitmap_switch + 0xC00 / f);
		}
	}
}

static void enable_msr_control(unsigned long msr, unsigned long *bitmap)
{
	set_bit(msr, bitmap);

	// write updated msr bitmask value back
	vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_switch));
}

static void disable_msr_control(unsigned long msr, unsigned long *bitmap)
{
	clear_bit(msr, bitmap);

	// write updated msr bitmask value back
	vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_switch));
}
