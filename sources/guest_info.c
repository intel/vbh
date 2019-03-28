#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/smp.h>

#include "offsets.h"
#include "vmx_common.h"
#include "hypervisor_introspection.h"

#define SEGMENT_AR_L					13
#define SEGMENT_AR_DB					14

#define SEGMENT_CPL_MASK				0x3

#define __CHECK_BIT_IS_SET_(var,pos) (((var) & (1<<(pos))) >> pos)
	
#define __GET_SREG_STATE_(sreg, name) do { \
	sreg.padding = 0;	\
	sreg.base = vmcs_readl(GUEST_##name##_BASE);	\
	sreg.limit = vmcs_read32(GUEST_##name##_LIMIT);	\
	sreg.selector = vmcs_read16(GUEST_##name##_SELECTOR);	\
	sreg.ar = vmcs_read32(GUEST_##name##_AR_BYTES);	\
}while(0)					

static void get_guest_descriptor(struct vcpu_request *requ, int field_base, int field_limit);

static void get_register_state(struct vcpu_request *requ);
static void get_msr(struct vcpu_request *req);
static void get_idtr(struct vcpu_request *req);
static void get_gdtr(struct vcpu_request *req);
static void get_cpu_count(struct vcpu_request *req);
static void get_current_tid(struct vcpu_request *req);
static void get_cs_type(struct vcpu_request *req);
static void get_cs_ring(struct vcpu_request *req);
static void get_sreg_state(struct vcpu_request *req);
static void get_gpr_state(unsigned char *buffer, int* size);

void get_guest_state_pcpu(void);

void get_guest_state_pcpu(void)
{
	struct vcpu_request *req = NULL;
	
	req = this_cpu_ptr(&vcpu_req);
	
	switch (req->query_gstate_type)
	{
	case registers_state:
		return get_register_state(req);
		
	case msr:
		return get_msr(req);
		
	case idtr:
		return get_idtr(req);

	case gdtr:
		return get_gdtr(req);
		
	case cpu_count:
		return get_cpu_count(req);
		
	case current_tid:
		return get_current_tid(req);
		
	case general_purpose_registers:		
		get_gpr_state((unsigned char*)&req->guest_data.g_gprs, &req->guest_data_sz);
		return;
		
	case cs_type:
		return get_cs_type(req);
		
	case cs_ring:
		return get_cs_ring(req);
		
	case segment_registers:
		return get_sreg_state(req);		
		
	default:
		req->guest_data_sz = 0;
		return;
	}
}

/*
 *Get register states including gprs, rip, flag and control registers
 **/
static void get_register_state(struct vcpu_request *req)
{	
	hvi_x86_registers_t *p_regs = &req->guest_data.g_states;
	
	p_regs->_pad = 0;
	
	// get value of gprs
	get_gpr_state((unsigned char*)&p_regs->gprs, &req->guest_data_sz);
	
	p_regs->cr0 = vmcs_readl(GUEST_CR0);
	
	p_regs->cr3 = vmcs_readl(GUEST_CR3);
	
	p_regs->cr4 = vmcs_readl(GUEST_CR4);
	
	p_regs->dr7 = vmcs_readl(GUEST_DR7);
	
	p_regs->rsp = vmcs_readl(GUEST_RSP);
	
	p_regs->rip = vmcs_readl(GUEST_RIP);
	
	p_regs->rflags = vmcs_readl(GUEST_RFLAGS);
	
	p_regs->sysenter_cs = vmcs_read32(GUEST_SYSENTER_CS);
	
	p_regs->sysenter_esp = vmcs_readl(GUEST_SYSENTER_ESP);
	
	p_regs->sysenter_eip = vmcs_readl(GUEST_SYSENTER_EIP);
	
	p_regs->msr_efer = vmcs_read64(GUEST_IA32_EFER);
	
	p_regs->fs_base = vmcs_readl(GUEST_FS_BASE);
	
	p_regs->gs_base = vmcs_readl(GUEST_GS_BASE);
	
	p_regs->cs_arbytes = vmcs_read32(GUEST_CS_AR_BYTES);
	
	req->guest_data_sz = sizeof(hvi_x86_registers_t);	
}

static void get_msr(struct vcpu_request *req)
{
	unsigned msr = req->query_gstate_param;
	
	printk(KERN_ERR "<1>get_msr: requested msr=0x%x", msr);
	
	rdmsrl(msr, req->guest_data.g_msr);
	
	req->guest_data_sz = sizeof(u64);
}

static void get_idtr(struct vcpu_request *req)
{
	return get_guest_descriptor(req, GUEST_IDTR_BASE, GUEST_IDTR_LIMIT);
}

static void get_gdtr(struct vcpu_request *req)
{	
	return get_guest_descriptor(req, GUEST_GDTR_BASE, GUEST_GDTR_LIMIT);
}

// Get cpu count.
static void get_cpu_count(struct vcpu_request *req)
{
	req->guest_data.g_num_cpus = num_online_cpus();
	
	req->guest_data_sz = sizeof(req->guest_data.g_num_cpus);
}

// Get current vcpu
static void get_current_tid(struct vcpu_request *req)
{	
	req->guest_data.g_current_tid = smp_processor_id();
	
	req->guest_data_sz = sizeof(req->guest_data.g_current_tid);
}

static void get_gpr_state(unsigned char *buffer, int* size)
{
	unsigned long *gpr_reg_area;
	
	// 16 general purpose registers
	int gprs_size = 16 * sizeof(unsigned long);

	gpr_reg_area = this_cpu_ptr(reg_scratch);
	
	memcpy((void*)buffer, gpr_reg_area, gprs_size);	
	
	*size = gprs_size;
}

/*
 *Get curent code segment type: 16, 32 or 64 bit
 **/
static void get_cs_type(struct vcpu_request *req)
{
	u32 cs_ar;
	
	cs_ar = vmcs_read32(GUEST_CS_AR_BYTES);
	
	if (__CHECK_BIT_IS_SET_(cs_ar, SEGMENT_AR_L))
	{
		req->guest_data.g_cs_type = KVI_CS_TYPE_64_BIT;
	}
	else if (__CHECK_BIT_IS_SET_(cs_ar, SEGMENT_AR_DB))
	{
		req->guest_data.g_cs_type = KVI_CS_TYPE_32_BIT;
	}
	else
	{
		req->guest_data.g_cs_type = KVI_CS_TYPE_16_BIT;
	}

	req->guest_data_sz = sizeof(req->guest_data.g_cs_type);
}

/*
 *Get current privilege level
 **/
static void get_cs_ring(struct vcpu_request *req)
{
	int cs_selector;

	cs_selector = vmcs_read32(GUEST_CS_SELECTOR);
	
	if ((cs_selector & SEGMENT_CPL_MASK) == KVI_CPL_KERNEL)
		req->guest_data.g_cs_ring = KVI_CPL_KERNEL;
	else if ((cs_selector & SEGMENT_CPL_MASK) == KVI_CPL_USER)
		req->guest_data.g_cs_ring = KVI_CPL_USER;
	else // should never reach hear.  only ring 0 and ring 3 are used.
	{
		req->guest_data.g_cs_ring = -1;
		req->guest_data_sz = 0;
		
		return;
	}
	
	req->guest_data_sz = sizeof(req->guest_data.g_cs_ring);
}

/*
 *Get base, limit, selector and rights of all segment registers: cs, ds, ss, es, fs, gs
 **/
static void get_sreg_state(struct vcpu_request *req)
{
	// cs
	__GET_SREG_STATE_(req->guest_data.g_segment_registers.cs, CS);
	
	// ds
	__GET_SREG_STATE_(req->guest_data.g_segment_registers.ds, DS);
	
	// ss
	__GET_SREG_STATE_(req->guest_data.g_segment_registers.ss, SS);
	
	//es
	__GET_SREG_STATE_(req->guest_data.g_segment_registers.es, ES);
	
	//fs
	__GET_SREG_STATE_(req->guest_data.g_segment_registers.fs, FS);
	
	//gs
	__GET_SREG_STATE_(req->guest_data.g_segment_registers.gs, GS);
	
	//req->p_gdata = &req->guest_data.g_segment_registers;
	
	req->guest_data_sz = sizeof(req->guest_data.g_segment_registers);
}

static void get_guest_descriptor(struct vcpu_request *req, int field_base, int field_limit)
{
	req->guest_data.dtr.base = vmcs_readl(field_base);
	req->guest_data.dtr.limit = vmcs_read32(field_limit);
	
	//req->p_gdata = &req->guest_data.dtr;
	req->guest_data_sz = sizeof(req->guest_data.dtr);
}
