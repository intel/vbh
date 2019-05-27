#include <linux/module.h>
#include <asm/vmx.h>

#include "hypervisor_introspection.h"
#include "vmx_common.h"
#include "offsets.h"

#define __SUCCESS(x)			((x) >= 0)

static DEFINE_SPINLOCK(pause_lock);

static int vcpus_locked;

//hv_event_callback global_event_callback;
struct hvi_event_callback global_event_callbacks[max_event];

static int get_min_req_size(hvi_query_info_e query);

static int get_min_req_size(hvi_query_info_e query)
{
	switch (query) {
	case registers_state:
		return sizeof(struct x86_regs);
	case msr:
		return sizeof(u64);
	case idtr:
	case gdtr:
		return sizeof(struct x86_dtable);
	case cpu_count:
	case current_tid:
	case cs_type:
	case cs_ring:
		return sizeof(int);
	case general_purpose_registers:
		return 16*sizeof(unsigned long);
	case segment_registers:
		return sizeof(struct x86_sregs);
	}

	return 0;
}

/*
 *Query specific guest information.
 **/
int hvi_query_guest_info(int vcpu, hvi_query_info_e query_type,
	unsigned char *param, unsigned char *buffer, int *size)
{
	int me;
	int min_size;

	struct vcpu_request *req;

	me = smp_processor_id();

	min_size = get_min_req_size(query_type);

	if (buffer == NULL || *size < min_size) {
		pr_err("<1> %s: Not enough buffer space.\n",
			__func__);
		return -1;
	}

	if (!all_vcpus_paused()) {
		pr_err("<1> %s: Error. Must pause all vcpus before proceed.\n",
			__func__);
		return -1;
	}

	req = per_cpu_ptr(&vcpu_req, vcpu == me ? me : vcpu);

	req->guest_data_sz = 0;

	req->query_gstate_type = query_type;

	// sof far param is only used to pass which msr to query
	if (param != NULL)
		req->query_gstate_param = *param;

	if (vcpu != me)
		make_request_on_cpu(vcpu, VBH_REQ_GUEST_STATE, true);
	else
		get_guest_state_pcpu();

	if (req->guest_data_sz > 0) {
		memcpy(buffer, (unsigned char *)&req->guest_data,
			req->guest_data_sz);

		*size = req->guest_data_sz;

		return 0;
	}

	return -1;
}
EXPORT_SYMBOL(hvi_query_guest_info);

/*
 *Set rflags register of specified vcpu.
 **/
int hvi_set_register_rflags(int vcpu, unsigned long new_value)
{
	int me;
	struct vcpu_request *req;

	if (!all_vcpus_paused()) {
		pr_err("<1> %s: Error.  Must pause all vcpus before proceed.\n",
			__func__);
		return -1;
	}

	me = smp_processor_id();

	pr_err("<1> %s: curr_cpu=%d, request_cpu=%d, curr_value=0x%lx, new_value=0x%lx",
		__func__, me, vcpu, vmcs_readl(GUEST_RFLAGS), new_value);

	if (vcpu == me)
		vmcs_writel(GUEST_RFLAGS, new_value);
	else {
		req = per_cpu_ptr(&vcpu_req, vcpu);
		req->new_value = new_value;
		make_request_on_cpu(vcpu, VBH_REQ_SET_RFLAGS, true);
	}

	return 0;
}
EXPORT_SYMBOL(hvi_set_register_rflags);

/*
 *Set rip register of specified vcpu.
 **/
int hvi_set_register_rip(int vcpu, unsigned long new_value)
{
	int me;
	struct vcpu_vmx *vcpu_ptr;
	struct vcpu_request *req;

	// basic error checking
	if (new_value == 0)
		return -1;

	if (!all_vcpus_paused()) {
		pr_err("<1> %s: Error.  Must pause all vcpus before proceed.\n",
			__func__);
		return -1;
	}

	vcpu_ptr = (struct vcpu_vmx *)get_vcpu(vcpu);
	if (!vcpu_ptr)
		return -1;

	me = smp_processor_id();

	pr_err("<1> %s: curr_cpu=%d, request_cpu=%d, new_value=0x%lx.\n",
		__func__, me, vcpu, new_value);

	if (vcpu == me) {
		vmcs_writel(GUEST_RIP, new_value);

		pr_err("<1> %s: guest_rip=0x%lx.\n",
			__func__, vmcs_readl(GUEST_RIP));

		vcpu_ptr->skip_instruction_not_used = 1;
	} else {
		req = per_cpu_ptr(&vcpu_req, vcpu);
		req->new_value = new_value;
		vcpu_ptr->skip_instruction_not_used = 1;

		wmb();  // req is smp shared variable.

		make_request_on_cpu(vcpu, VBH_REQ_SET_RIP, true);
	}

	return 0;
}
EXPORT_SYMBOL(hvi_set_register_rip);

/*
 *Pause all vcpus.
 **/
int hvi_request_vcpu_pause(int immediate)
{
	int ret;

	spin_lock(&pause_lock);

	if (vcpus_locked) {
		spin_unlock(&pause_lock);
		return -1;
	}

	vcpus_locked = 1;

	spin_unlock(&pause_lock);

	ret = pause_other_vcpus(immediate);

	return ret;
}
EXPORT_SYMBOL(hvi_request_vcpu_pause);

/*
 *Resume paused vcpus.
 **/
int hvi_request_vcpu_resume(void)
{
	int ret;

	ret = resume_other_vcpus();

	vcpus_locked = 0;

	return ret;
}
EXPORT_SYMBOL(hvi_request_vcpu_resume);

/*
 *Map a guest physical adress inside the hvi address space.
 **/
int hvi_physmem_map_to_host(unsigned long phy_addr, unsigned long length,
	unsigned long flags, void **host_ptr)
{
    // todo: perform some checks first, e.g. phy_addr is valid
	*host_ptr = (void *)__va(phy_addr);

	return (host_ptr == NULL);
}
EXPORT_SYMBOL(hvi_physmem_map_to_host);

/*
 *Unmap a page which is previously mapped.
 **/
int hvi_physmem_unmap(void **host_ptr)
{
	*host_ptr = NULL;

	return 0;
}
EXPORT_SYMBOL(hvi_physmem_unmap);

/*
 *Give GPA address, query the EPT access rights.
 **/
int hvi_get_ept_page_protection(unsigned long addr, unsigned char *read,
	unsigned char *write, unsigned char *execute)
{
	unsigned long *ept_entry = get_ept_entry(addr);

	if (ept_entry == NULL)
		return -1;

	return get_ept_entry_prot(*ept_entry);
}
EXPORT_SYMBOL(hvi_get_ept_page_protection);

/*
 *Modify the EPT access rights for the indicated GPA address.
 **/
int hvi_set_ept_page_protection(unsigned long addr, unsigned char read,
	unsigned char write, unsigned char execute)
{
	unsigned long *ept_entry;

	if (!all_vcpus_paused()) {
		pr_err("<1> %s: Error.  Must pause all vcpus before proceed.\n",
			__func__);

		return -1;
	}

	// update ept
	ept_entry = get_ept_entry(addr);

	if (ept_entry == NULL)
		return -1;

	set_ept_entry_prot(ept_entry, read, write, execute);

	// invept on this cpu
	vbh_tlb_shootdown();

	// need to invept on every other cpu
	make_request(VBH_REQ_INVEPT, true);

	return 0;
}
EXPORT_SYMBOL(hvi_set_ept_page_protection);

/*
 *Modify whether write msr causes vmexit.
 **/
int hvi_modify_msr_write_exit(unsigned long msr, unsigned char is_enable)
{
	if (!all_vcpus_paused()) {
		pr_err("<1> %s: Error.  Must pause all vcpus before proceed.\n",
			__func__);

		return -1;
	}

	// setup new policy
	msr_ctrl.enable = is_enable;

	msr_ctrl.msr_reg = msr;

	wmb();  // msr_ctrl is smp shared variable.

	// update policy on this cpu
	handle_msr_monitor_req(&msr_ctrl);

	// make request to other vcpus
	make_request(VBH_REQ_MODIFY_MSR, true);

	return 0;
}
EXPORT_SYMBOL(hvi_modify_msr_write_exit);

/*
 *Modify whether write indicated cr causes vmexit.
 **/
int hvi_modify_cr_write_exit(unsigned long cr, unsigned int mask,
	unsigned char is_enable)
{
	if (!all_vcpus_paused()) {
		pr_err("<1> %s: Error.  Must pause all vcpus before proceed.\n",
			__func__);

		return -1;
	}

	// setup policy
	cr_ctrl.enable = is_enable;
	cr_ctrl.cpu_reg = cr;

	cr_ctrl.mask = mask;

	// cr_ctrl is smp shared variable
	wmb();

	// update cr policy on this cpu
	handle_cr_monitor_req(&cr_ctrl);

	// make request to every other cpu
	make_request(VBH_REQ_MODIFY_CR, true);

	return 0;

}
EXPORT_SYMBOL(hvi_modify_cr_write_exit);

/*
 *Inject a #PF in guest.
 **/
int hvi_force_guest_page_fault(unsigned long virtual_addr, unsigned long error)
{
	return -1;
}

/*
 *Enable mtf.
 **/
int hvi_enable_mtf(void)
{
	u32 cpu_based_exec_ctrl;

	cpu_based_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);

	if ((cpu_based_exec_ctrl & CPU_BASED_MONITOR_TRAP_FLAG) == 0)
		cpu_based_exec_ctrl |= CPU_BASED_MONITOR_TRAP_FLAG;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_exec_ctrl);

	return 0;
}
EXPORT_SYMBOL(hvi_enable_mtf);

/*
 *Disable mtf.
 **/
int hvi_disable_mtf(void)
{
	u32 cpu_based_exec_ctrl;

	cpu_based_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);

	if (cpu_based_exec_ctrl & CPU_BASED_MONITOR_TRAP_FLAG)
		cpu_based_exec_ctrl &= ~CPU_BASED_MONITOR_TRAP_FLAG;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_exec_ctrl);

	return 0;
}
EXPORT_SYMBOL(hvi_disable_mtf);

/*
 *Register event report call back
 **/
int hvi_register_event_callback(struct hvi_event_callback hvi_event_handlers[],
	size_t num_handlers)
{
	int i = 0;

	vcpus_locked = 0;

	if (num_handlers >= max_event)
		return -1;

	for (i = 0; i < num_handlers; i++) {
		struct hvi_event_callback *handler = &hvi_event_handlers[i];

		if (handler->callback != NULL && handler->event < max_event)
			global_event_callbacks[handler->event].callback =
				handler->callback;
		else
			return -1;
	}

	return 0;
}
EXPORT_SYMBOL(hvi_register_event_callback);

/*
 *Un-register event report call back
 **/
int hvi_unregister_event_callback(hv_event_e event)
{
	if (global_event_callbacks[event].callback != NULL)
		global_event_callbacks[event].callback = NULL;

	return 0;
}
EXPORT_SYMBOL(hvi_unregister_event_callback);

/*
 *Switch to nonroot mode.
 **/
int hvi_switch_to_nonroot(void)
{
	if (__SUCCESS(vmx_switch_to_nonroot()))
		return 0;

	return -1;
}
EXPORT_SYMBOL(hvi_switch_to_nonroot);

/*
 *Check whether vbh is loaded or not.
 **/
int hvi_is_vbh_loaded(void)
{
	return check_vbh_status();
}
EXPORT_SYMBOL(hvi_is_vbh_loaded);

int hvi_inject_trap(int vcpu_nr, u8 trap_number, u32 error_code, u64 cr2)
{
    return inject_trap(vcpu_nr, trap_number, error_code, cr2);
}
EXPORT_SYMBOL(hvi_inject_trap);