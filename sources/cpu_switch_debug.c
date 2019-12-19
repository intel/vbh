// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>

#include "vmx_common.h"
#include "cpu_switch_debug.h"

void dump_host_state(int cpu)
{
	u16 cs_selector, ss_selector;
	cs_selector = vmcs_read16(HOST_CS_SELECTOR);
	ss_selector = vmcs_read16(HOST_SS_SELECTOR);
	
	printk(KERN_ERR "<1> CPU-%d: HOST cs_selector=0x%x, ss_selector=0x%x.\n", cpu, cs_selector, ss_selector);
}

void dump_guest_state(int cpu)
{
	u16 selector;
	u64 base;
	u32 access_rights;
	u32 limit;

	selector = vmcs_read16(GUEST_CS_SELECTOR);

	access_rights = vmcs_read32(GUEST_CS_AR_BYTES);
	base = vmcs_readl(GUEST_CS_BASE);
	limit = vmcs_read32(GUEST_CS_LIMIT);

	printk(KERN_ERR "<1> CPU-%d: GUEST cs_selector=0x%x, cs_ar_bytes=0x%x, cs_base=0x%llx, cs_limit=0x%x\n", cpu, selector, access_rights, base, limit);

	selector = vmcs_read16(GUEST_SS_SELECTOR);
	
	access_rights = vmcs_read32(GUEST_SS_AR_BYTES);
	base = vmcs_readl(GUEST_SS_BASE);
	limit = vmcs_read32(GUEST_SS_LIMIT);
	
	printk(KERN_ERR "<1> CPU-%d: GUEST ss_selector=0x%x, ss_ar_bytes=0x%x, ss_base=0x%llx, ss_limit=0x%x\n", cpu, selector, access_rights, base, limit);
}

void print_control_info(int cpu, struct vmcs_config *vmcs_config_p)
{
	printk(KERN_ERR "<1> CPU-%d: pin_based_exec_ctrl=0x%x", cpu, vmcs_config_p->pin_based_exec_ctrl);
	printk(KERN_ERR "<1> CPU-%d: cpu_based_exec_ctrl=0x%x", cpu, vmcs_config_p->cpu_based_exec_ctrl);
	printk(KERN_ERR "<1> CPU-%d: cpu_based_2nd_exec_ctrl=0x%x", cpu, vmcs_config_p->cpu_based_2nd_exec_ctrl);
	printk(KERN_ERR "<1> CPU-%d: vmexit_ctrl=0x%1x", cpu, vmcs_config_p->vmexit_ctrl);
	printk(KERN_ERR "<1> CPU-%d: vmentry_ctrl=0x%x", cpu, vmcs_config_p->vmentry_ctrl);
	printk(KERN_ERR "<1> CPU-%d: vmentry_intr_info_ctrl=0x%x", cpu, vmcs_config_p->vmentry_intr_info_ctrl);
}
