#include "hypervisor_introspection.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <asm/vmx.h>
#include "vmx_common.h"
#include "offsets.h"

#define __SUCCESS(x)                            (x) >= 0

//hv_event_callback global_event_callback;
struct hvi_event_callback global_event_callbacks[max_event];

// todo: move this into a header file
unsigned long* get_ept_entry (unsigned long long gpa);
void set_ept_entry_prot(unsigned long*, int, int, int);

int get_ept_entry_prot(unsigned long entry);

extern void handle_cr_monitor_req(cpu_control_params_t* cpu_param);

extern void handle_msr_monitor_req(msr_control_params_t* msr_param);

extern void cpu_switch_flush_tlb_smp(void);

extern int pause_other_vcpus(void);

extern int resume_other_vcpus(void);

// functions related to query guest info
extern int get_register_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_msr(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_idtr(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_gdtr(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_cpu_count(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_current_tid(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_gpr_registers_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_cs_type(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_cs_ring(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern int get_seg_registers_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
extern void make_request(int request, int wait);
extern void vbh_tlb_shootdown(void);

extern void* get_vcpu(void);

extern int vmx_switch_to_nonroot(void);
extern bool check_vbh_status(void);

static int (*hvi_ept_violation_callback)(unsigned long long gpa, unsigned long long gla, int* allow);

int hvi_register_ept_violation_handler(int(*callback)(unsigned long long gpa, unsigned long long gla, int* allow))
{
    if (NULL != hvi_ept_violation_callback)
    {
        printk(KERN_ERR "hvi_register_ept_violation_handler: there is already a registered callback\n");
        return -1;
    }
    hvi_ept_violation_callback = callback;
    return 0;
}
EXPORT_SYMBOL(hvi_register_ept_violation_handler);


int hvi_unregister_ept_violation_handler(void)
{
    hvi_ept_violation_callback = NULL;
    return 0;
}
EXPORT_SYMBOL(hvi_unregister_ept_violation_handler);


int hvi_invoke_ept_violation_handler(unsigned long long gpa, unsigned long long gla, int* allow)
{
    if (NULL == hvi_ept_violation_callback)
    {
        printk (KERN_ERR "an ept violation occured but there is no hvi callback available.\n");
        return -1;
    }
    
    return hvi_ept_violation_callback(gpa, gla, allow);
}

/*
 *Query specific guest information.
 **/
int hvi_query_guest_info(int vcpu, hvi_query_info_e query_type, unsigned char* param, unsigned char* buffer, int* size)
{
	int result = 0;
	
	switch (query_type)
	{
	case registers_state:
		result = get_register_state(vcpu, param, buffer, size);
		break;
		
	case msr:
		result = get_msr(vcpu, param, buffer, size);
		break;
		
	case idtr:
		result = get_idtr(vcpu, param, buffer, size);
		break;
		
	case gdtr:
		result = get_gdtr(vcpu, param, buffer, size);
		break;
		
	case cpu_count:
		result = get_cpu_count(vcpu, param, buffer, size);
		break;
		
	case current_tid:
		result = get_current_tid(vcpu, param, buffer, size);
		break;
		
	case gpr_registers_state:
		result = get_gpr_registers_state(vcpu, param, buffer, size);
		break;
		
	case cs_type:
		result = get_cs_type(vcpu, param, buffer, size);
		break;
		
	case cs_ring:
		result = get_cs_ring(vcpu, param, buffer, size);
		break;
		
	case seg_registers_state:
		result = get_seg_registers_state(vcpu, param, buffer, size);
		break;		
		
	default:
		*size = 0;
		result = -1;
		break;
	}
	
	if (result == 0)
		return 0;
	
	return -1;
}
EXPORT_SYMBOL(hvi_query_guest_info);

/*
 *Set rflags register of specified vcpu.
 **/
int hvi_set_register_rflags(int vcpu, unsigned long new_value)
{
	vmcs_writel(GUEST_RFLAGS, new_value);
	
	return 0;
}
EXPORT_SYMBOL(hvi_set_register_rflags);

/*
 *Set rip register of specified vcpu.
 **/
int hvi_set_register_rip(int vcpu, unsigned long new_value)
{
	struct vcpu_vmx *vcpu_ptr;

	// basic error checking
	if(new_value == 0)
		return - 1;
		
	vcpu_ptr = (struct vcpu_vmx*)get_vcpu();
	
	if (vcpu_ptr == NULL)
		return -1;
	
	vmcs_writel(GUEST_RIP, new_value);	
	
	vcpu_ptr->skip_instruction_not_used = 1;
	
	return 0;
}
EXPORT_SYMBOL(hvi_set_register_rip);

/*
 *Pause all vcpus.
 **/
int hvi_request_vcpu_pause(void)
{
	int ret;
	ret = pause_other_vcpus();
	
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
	
	return ret;
}EXPORT_SYMBOL(hvi_request_vcpu_resume);

/*
 *Map a guest physical adress inside the hvi address space.
 **/
int hvi_physmem_map_to_host(unsigned long phy_addr, unsigned long length, unsigned long flags, void** host_ptr)
{
    // todo: perform some checks first, e.g. phy_addr is valid
    *host_ptr = (void*)__va(phy_addr);
    return (NULL == host_ptr);
}
EXPORT_SYMBOL(hvi_physmem_map_to_host);

/*
 *Unmap a page which is previously mapped.
 **/
int hvi_physmem_unmap(void** host_ptr)
{
    *host_ptr = NULL;
    return 0;
}
EXPORT_SYMBOL(hvi_physmem_unmap);

/*
 *Give GPA address, query the EPT access rights.
 **/
int hvi_get_ept_page_protection(unsigned long addr, unsigned char *read, unsigned char *write, unsigned char* execute)
{
	unsigned long *ept_entry = get_ept_entry(addr);
	
	if (NULL == ept_entry)
		return -1;
	
	return get_ept_entry_prot(*ept_entry);
}
EXPORT_SYMBOL(hvi_get_ept_page_protection);

/*
 *Modify the EPT access rights for the indicated GPA address.
 **/
int hvi_set_ept_page_protection(unsigned long addr, unsigned char read, unsigned char write, unsigned char execute)
{
	unsigned long *ept_entry;

	if (__SUCCESS(pause_other_vcpus()))
	{
		// update ept
		ept_entry = get_ept_entry(addr);

		if (NULL == ept_entry)
			return -1;

		set_ept_entry_prot(ept_entry, read, write, execute);

		// invept on this cpu
		vbh_tlb_shootdown();
		
		// need to invept on every other cpu
		make_request(VBH_REQ_INVEPT, true);
	
		return 0;		
	}
	
	return -1;
}
EXPORT_SYMBOL(hvi_set_ept_page_protection);

/*
 *Modify whether write msr causes vmexit.
 **/
int hvi_modify_msr_write_exit(unsigned long msr, unsigned char is_enable)
{
	msr_control_params_t msr_ctrl;
	
	msr_ctrl.enable = is_enable;
	msr_ctrl.msr_reg = msr;

	handle_msr_monitor_req(&msr_ctrl);

	return 0;
}EXPORT_SYMBOL(hvi_modify_msr_write_exit);

/*
 *Modify whether write indicated cr causes vmexit.
 **/
int hvi_modify_cr_write_exit(unsigned long cr, unsigned int mask, unsigned char is_enable)
{
	cpu_control_params_t cr_ctrl;
	
	// pause all vcpus
	if (__SUCCESS(pause_other_vcpus()))
	{
		// update cr policy on this cpu
		cr_ctrl.enable = is_enable;
		cr_ctrl.cpu_reg = cr;
	
		cr_ctrl.mask = mask;
	
		handle_cr_monitor_req(&cr_ctrl);	
		
		// make request to every other cpu
		make_request(VBH_REQ_MODIFY_CR, true);
		
		return 0;
	}
	
	return -1;
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
 *Enable mtf.*/
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
int hvi_register_event_callback(struct hvi_event_callback hvi_event_handlers[], size_t num_handlers)
{
	int i = 0;
	
	if (num_handlers >= max_event)
		return -1;
	
	for (i = 0; i < num_handlers; i++)
	{
		struct hvi_event_callback *handler = &hvi_event_handlers[i];
		
		if (handler->callback != NULL && handler->event < max_event)			
			global_event_callbacks[handler->event].callback = handler->callback;
		else
		{
			return -1;
		}
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

