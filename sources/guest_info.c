#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/smp.h>

#include "offsets.h"
#include "vmx_common.h"
#include "hypervisor_introspection.h"

#define SEGMENT_AR_L					13
#define SEGMENT_AR_DB					14

#define SEGMENT_CPL_MASK				0x3

#define __CHECK_ERROR_(buf, psize, min)	do { \
	if (buf == 0 || *psize < min) \
	{\
		psize = 0; \
		return -1;	\
	}\
}while(0)
	
#define __CHECK_BIT_IS_SET_(var,pos) (((var) & (1<<(pos))) >> pos)
	
#define __GET_SREG_STATE_(sreg, name) do { \
	sreg.padding = 0;	\
	sreg.base = vmcs_readl(GUEST_##name##_BASE);	\
	sreg.limit = vmcs_read32(GUEST_##name##_LIMIT);	\
	sreg.selector = vmcs_read16(GUEST_##name##_SELECTOR);	\
	sreg.ar = vmcs_read32(GUEST_##name##_AR_BYTES);	\
}while(0)					
	
static int get_guest_descriptor(int vcpu, unsigned char* buffer, int* size, int field_base, int field_limit);

int get_register_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_msr(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_idtr(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_gdtr(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_cpu_count(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_current_tid(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_gpr_registers_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_cs_type(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_cs_ring(int vcpu, unsigned char* param, unsigned char* buffer, int* size);
int get_seg_registers_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size);

extern unsigned long* get_scratch_register(void);

/*
 *Get register states including gprs, rip, flag and control registers
 **/
int get_register_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	hvi_x86_registers_t registers = { ._pad = 0 };
	
	int gpr_size = sizeof(hvi_x86_gpr_t);
	
	__CHECK_ERROR_(buffer, size, sizeof(registers));
	
	// copy gpr states
	get_gpr_registers_state(vcpu, NULL, (unsigned char*)&registers.gprs, &gpr_size);
	
	registers.cr0 = vmcs_readl(GUEST_CR0);
	
	registers.cr3 = vmcs_readl(GUEST_CR3);
	
	registers.cr4 = vmcs_readl(GUEST_CR4);
	
	registers.dr7 = vmcs_readl(GUEST_DR7);
	
	registers.rsp = vmcs_readl(GUEST_RSP);
	
	registers.rip = vmcs_readl(GUEST_RIP);
	
	registers.rflags = vmcs_readl(GUEST_RFLAGS);
	
	registers.sysenter_cs = vmcs_read32(GUEST_SYSENTER_CS);
	
	registers.sysenter_esp = vmcs_readl(GUEST_SYSENTER_ESP);
	
	registers.sysenter_eip = vmcs_readl(GUEST_SYSENTER_EIP);
	
	registers.msr_efer = vmcs_read64(GUEST_IA32_EFER);
	
	registers.fs_base = vmcs_readl(GUEST_FS_BASE);
	
	registers.gs_base = vmcs_readl(GUEST_GS_BASE);
	
	registers.cs_arbytes = vmcs_read32(GUEST_CS_AR_BYTES);
	
	memcpy(buffer, &registers, sizeof(registers));
	*size = sizeof(registers);
	
	return 0;
}

int get_msr(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	u64 msr_value;
	unsigned msr = (unsigned)*param;
	
	__CHECK_ERROR_(buffer, size, sizeof(u64));	
	
	rdmsrl(msr, msr_value);
	
	memcpy((void*)buffer, &msr_value, sizeof(u64));
	
	*size = sizeof(u64);
	
	return 0;
}

int get_idtr(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	return get_guest_descriptor(vcpu, buffer, size, GUEST_IDTR_BASE, GUEST_IDTR_LIMIT);
}

int get_gdtr(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{	
	return get_guest_descriptor(vcpu, buffer, size, GUEST_GDTR_BASE, GUEST_GDTR_LIMIT);
}

// Get cpu count.
int get_cpu_count(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	int cpu_count;
	
	__CHECK_ERROR_(buffer, size, sizeof(int));
	
	cpu_count = num_online_cpus();
	
	memcpy((void*)buffer, &cpu_count, sizeof(cpu_count));
	
	*size = sizeof(cpu_count);
	
	return 0;
}

// Get current vcpu
int get_current_tid(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	int cpu;
	
	__CHECK_ERROR_(buffer, size, sizeof(int));
	
	cpu = smp_processor_id();
	
	memcpy((void*)buffer, (void*)&cpu, sizeof(int));
	*size = sizeof(int);
	
	return 0;
}

// Get value of general purpose registers
int get_gpr_registers_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	unsigned long *gpr_reg_area;
	
	// 16 general purpose registers
	int gprs_size = 16 * sizeof(unsigned long);

	__CHECK_ERROR_(buffer, size, gprs_size);
	
	gpr_reg_area = get_scratch_register();
	
	memcpy((void*)buffer, gpr_reg_area, gprs_size);
	
	*size = gprs_size;
	
	return 0;
}

/*
 *Get curent code segment type: 16, 32 or 64 bit
 **/
int get_cs_type(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	u32 cs_ar;
	
	int value = 0;
	
	__CHECK_ERROR_(buffer, size, sizeof(int));
	
	cs_ar = vmcs_read32(GUEST_CS_AR_BYTES);
	
	if (__CHECK_BIT_IS_SET_(cs_ar, SEGMENT_AR_L))
	{
		value = KVI_CS_TYPE_64_BIT;
	}
	else if (__CHECK_BIT_IS_SET_(cs_ar, SEGMENT_AR_DB))
	{
		value = KVI_CS_TYPE_32_BIT;
	}
	else
	{
		value = KVI_CS_TYPE_16_BIT;
	}
		
	memcpy(buffer, &value, sizeof(int));
	*size = sizeof(int);
	
	return 0;
}

/*
 *Get current privilege level
 **/
int get_cs_ring(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	int privilege = -1;
	int cs_selector;
	
	__CHECK_ERROR_(buffer, size, sizeof(int));
	
	cs_selector = vmcs_read32(GUEST_CS_SELECTOR);
	
	if ((cs_selector & SEGMENT_CPL_MASK) == KVI_CPL_KERNEL)
		privilege = KVI_CPL_KERNEL;
	else if ((cs_selector & SEGMENT_CPL_MASK) == KVI_CPL_USER)
		privilege = KVI_CPL_USER;
	else // should never reach hear.  only ring 0 and ring 3 are used.
	{
		*size = 0;
		buffer = NULL;
		return -1;
	}
	
	memcpy(buffer, &privilege, sizeof(int));
	*size = sizeof(int);
	
	return 0;
}

/*
 *Get base, limit, selector and rights of all segment registers: cs, ds, ss, es, fs, gs
 **/
int get_seg_registers_state(int vcpu, unsigned char* param, unsigned char* buffer, int* size)
{
	struct x86_sregs sregs;
	
	__CHECK_ERROR_(buffer, size, sizeof(sregs));
	
	// cs
	__GET_SREG_STATE_(sregs.cs, CS);
	
	// ds
	__GET_SREG_STATE_(sregs.ds, DS);
	
	// ss
	__GET_SREG_STATE_(sregs.ss, SS);
	
	//es
	__GET_SREG_STATE_(sregs.es, ES);
	
	//fs
	__GET_SREG_STATE_(sregs.fs, FS);
	
	//gs
	__GET_SREG_STATE_(sregs.gs, GS);
	
	memcpy(buffer, &sregs, sizeof(sregs));
	*size = sizeof(sregs);
	
	return 0;
}

static int get_guest_descriptor(int vcpu, unsigned char* buffer, int* size, int field_base, int field_limit)
{
	struct x86_dtable dt = { .padding = { 0 } };
	
	__CHECK_ERROR_(buffer, size, sizeof(dt));
	
	dt.base = vmcs_readl(field_base);
	dt.limit = vmcs_read32(field_limit);
	
	memcpy(buffer, &dt, sizeof(dt));
	
	*size = sizeof(dt);
	
	return 0;
}
