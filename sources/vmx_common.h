#ifndef _VMX_COMMON_H_
#define _VMX_COMMON_H_

#include <linux/percpu.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <asm/vmx.h>
#include <asm/traps.h>

#include "offsets.h"
#include "hypervisor_introspection.h"

/* Get exception mask for X. See exception_injection_mask field in struct vcpu_vmx */
#define VCPU_INJECT_EXCEPTION_MASK(X)       (BIT(X))	
#define NUMBER_OF_RESERVED_EXCEPTIONS       32
#define MOST_INSIGNIFICANT_N_BITS_MASK(N)   (BIT(N) - 1)

/*
    Custom additional info structure per exception. 
    Fields in each structure can be garbage or good to use.
    In order to see that, at the end of every structure we
    can find an BITMAP. If bit k is set, field k is not garbage.
    
    TODO: Each new field included in the structure 
    must also be included in the structure-specific enumeration.
    The fields in the enumeration and the structure MUST HAVE the same order!  
*/

enum page_fault_field_encoding
{
    /* Write fields from page_fault_additional_info 
    in the same order */
    virtual_address,
    page_fault_field_encoding_end
};

typedef struct _page_fault_additional_info
{
    u64         virtual_address;                                            /* Value to set CR2 */

    /* See  page_fault_field_encoding */
    DECLARE_BITMAP(field_is_ok, page_fault_field_encoding_end);             /* Bitmap to see if a field in struct is garbage or good to use */
}page_fault_additional_info;

typedef struct _exception_additional_info
{
    /* Common fields here */
    u32     exception_error_code;       /* Exception error code - valid only for some exceptions. */

    /* Specific fields per exception here.
    If the byte has_specific_info is set in global vector exception_info, 
    then a structure specific to that exception must be found in the union below. */
    union
    {
        page_fault_additional_info  page_fault_specific;
    } specific_additional_info;
}exception_additional_info;

typedef enum _INTERRUPTION_TYPE
{
    INTERRUPTION_TYPE_EXTERNAL_INTERRUPT                = 0,
    INTERRUPTION_TYPE_NON_MASKABLE_INTERRUPT            = 2,
    INTERRUPTION_TYPE_HARDWARE_EXCEPTION,
    INTERRUPTION_TYPE_SOFTWARE_INTERRUPT,
    INTERRUPTION_TYPE_PRIVILEGED_SOFTWARE_EXCEPTION,
    INTERRUPTION_TYPE_SOFTWARE_EXCEPTION,
    INTERRUPTION_TYPE_OTHER_EVENT,
}INTERRUPTION_TYPE;

typedef union _vm_entry_int_info
{
    struct
    {
        u32           vector                :       8;
        u32           interruption_type     :       3;
        u32           deliver_error_code    :       1;
        u32           reserved              :       19;
        u32           valid                 :       1;
    }fields;

    u32               value;
} vm_entry_int_info;

/*  Bitfields problem: compiler might lay the bit field out differently 
    depending on the endianness of the target platform.
    We need pack/unpack functions to maintain compatibility. */
static __always_inline u32 vm_entry_info_pack(vm_entry_int_info vm_entry_info)
{
    return ((vm_entry_info.fields.vector << 0) | (vm_entry_info.fields.interruption_type << 8) | (vm_entry_info.fields.deliver_error_code << 11) | (vm_entry_info.fields.valid << 31));
}

static __always_inline vm_entry_int_info vm_entry_info_unpack(u32 raw)
{
    vm_entry_int_info vmEntryInfo = { 0 };

    vmEntryInfo.fields.vector = raw & MOST_INSIGNIFICANT_N_BITS_MASK(8);
    raw >>= 8;

    vmEntryInfo.fields.interruption_type = raw & MOST_INSIGNIFICANT_N_BITS_MASK(3);
    raw >>= 3;

    vmEntryInfo.fields.deliver_error_code = raw & MOST_INSIGNIFICANT_N_BITS_MASK(1);
    raw >>= 1;

    vmEntryInfo.fields.reserved = raw & MOST_INSIGNIFICANT_N_BITS_MASK(19);
    raw >>= 19;

    vmEntryInfo.fields.valid = raw & MOST_INSIGNIFICANT_N_BITS_MASK(1);

    return vmEntryInfo;
}

typedef enum {
	CPU_REG_CR0 = 0,
	CPU_REG_CR3 = 3,
	CPU_REG_CR4 = 4,

	CPU_REG_UNKNOWN
}cpu_reg_e;

typedef enum
{
	//MSR_REG_STAR = 0xC0000081,
	MSR_REG_STAR = 0xCE,
	MSR_REG_UNKNOWN
}msr_reg_e;

#define KERNEL_HARDENING_HYPERCALL  40
#define DFO_HYPERCALL				42
#define VCPU_REQUEST_HYPERCALL		60

typedef enum {
	CPU_MONITOR_REQ = 1,
	MSR_MONITOR_REQ,
	MONITOR_REQ_END,
	VMCS_UPDATE_VMCS

}hypercall_id_e;

typedef struct {
	cpu_reg_e cpu_reg;
	bool enable;
	unsigned long mask;
	unsigned int vcpu;
} cpu_control_params_t;

typedef struct
{
	msr_reg_e msr_reg;
	bool enable;
	unsigned int vcpu;
}msr_control_params_t;

typedef struct
{
	unsigned long size;  // size of params
	hypercall_id_e id;
	u64 params;
}vmcall_params_t;

typedef struct
{
	vmcall_params_t call_params;
	unsigned call_type;
} vmcall_t;

typedef struct 
{
    u32 update_exception_bitmap : 1;
    u32 update_exception_pagefault_mask : 1;
    u32 update_exception_pagefault_match : 1;
}exception_bitmap_update_flags;

typedef struct exception_bitmap_params
{
    u32 update_flags;
    u32 ex_bitmap_structure;
    u32 pagefault_mask;
    u32 pagefault_match;
}exception_bitmap_params_t;

static __always_inline u32 update_flags_pack(exception_bitmap_update_flags flags)
{
    return ((flags.update_exception_bitmap << 0) | (flags.update_exception_pagefault_mask << 1) | (flags.update_exception_pagefault_match << 2));
}

static __always_inline exception_bitmap_update_flags update_flags_unpack(u32 raw)
{
    exception_bitmap_update_flags flags = { 0 };
    flags.update_exception_bitmap = !!(raw & BIT(0));
    flags.update_exception_pagefault_mask = !!(raw & BIT(1));
    flags.update_exception_pagefault_match = !!(raw & BIT(2));

    return flags;
}

union guest_state
{
	struct x86_regs g_states;
	struct x86_sregs g_segment_registers;
	struct x86_dtable dtr;  //gdtr or idtr
	u64 g_msr;
	int g_num_cpus;
	int g_current_tid;
	struct hvi_x86_gpr g_gprs;
	int g_cs_type;
	int g_cs_ring;
};

struct vcpu_request
{
	unsigned long new_value;
	DECLARE_BITMAP(pcpu_requests, 64);  	// bitmap for all requests on a vcpu
	int query_gstate_type;					// what guest info to get
	int query_gstate_param;					// parameter for a specific guest info
	union guest_state guest_data;
	int guest_data_sz;
};

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct vcpu_vmx {
    struct vmcs     *pcpu_vmcs;
    struct vmcs     *vmxarea;
    u64             vcpu_stack;
    unsigned long   *regs;
    u64 cr2;
    bool            instruction_skipped;
    bool            skip_instruction_not_used;
    struct
    {
        u32                         exception_injection_mask;                       /* Each bit selects an exception. If the bit is set, the according exception will be injected in guest.*/
        exception_additional_info   additional_info[NUMBER_OF_RESERVED_EXCEPTIONS]; /* Exception additional info. Common & specific per exception */
    }vcpu_exception;
};

DECLARE_PER_CPU(struct vcpu_request, vcpu_req);

extern struct vcpu_vmx __percpu* vcpu;
DECLARE_PER_CPU(unsigned long[NR_VCPU_REGS], reg_scratch);
extern unsigned long *vmx_eptp_pml4;

extern cpu_control_params_t cr_ctrl;
extern msr_control_params_t msr_ctrl;
extern exception_bitmap_params_t exception_ctrl;

struct vmcs_config {
	int size;
	int order;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
	u32 vmentry_intr_info_ctrl;
};

struct vmx_capability {
	u32 ept;
	u32 vpid;
};

#define __ex(x) x

#define LOW_MSR_RANGE_LOW			0x00000000
#define LOW_MSR_RANGE_HIGH			0x00001FFF
#define HI_MSR_RANGE_LOW			0xC0000000
#define HI_MSR_RANGE_HIGH			0xC0001FFF

#define MSR_TYPE_R	1
#define MSR_TYPE_W	2

/* CR0 constants */
#define PE BIT(0)
#define MP BIT(1)
#define EM BIT(2)
#define TS BIT(3)
#define ET BIT(4)
#define NE BIT(5)
#define WP BIT(16)
#define AM BIT(18)
#define NW BIT(29)
#define CD BIT(30)
#define PG BIT(31)

/* CR4 constants */
#define VME BIT(0)
#define PVI BIT(1)
#define TSD BIT(2)
#define DE  BIT(3)
#define PSE BIT(4)
#define PAE BIT(5)
#define MCE BIT(6)
#define PGE BIT(7)
#define PCE BIT(8)
#define OSFXSR BIT(9)
#define OSXMMEXCPT BIT(10)
#define VMXE BIT(13)
#define SMXE BIT(14)
#define PCIDE BIT(17)
#define OSXSAVE BIT(18)
#define SMEP BIT(20)
#define SMAP BIT(21)

/* vbh_req bitmask*/
#define VBH_REQ_PAUSE					BIT(0)
#define VBH_REQ_RESUME					BIT(1)
#define VBH_REQ_SET_RFLAGS				BIT(2)
#define VBH_REQ_SET_RIP					BIT(3)
#define VBH_REQ_MODIFY_MSR				BIT(4)
#define VBH_REQ_MODIFY_CR				BIT(5)
#define VBH_REQ_INVEPT					BIT(6)
#define VBH_REQ_GUEST_STATE				BIT(7)
#define VBH_REQ_MODIFY_EXCEPTION_BITMAP	BIT(8)

// Latest kernel use asm instructions to replace .byte stream.
// This time still use .byte stream and will combine with kvm's interfaces.
#define VBH_ASM_VMX_VMPTRLD_RAX       ".byte 0x0f, 0xc7, 0x30"
#define VBH_ASM_VMX_VMREAD_RDX_RAX    ".byte 0x0f, 0x78, 0xd0"
#define VBH_ASM_VMX_VMWRITE_RAX_RDX   ".byte 0x0f, 0x79, 0xd0"
#define VBH_ASM_VMX_INVEPT            ".byte 0x66, 0x0f,0x38, 0x80, 0x08"

static __always_inline unsigned long __vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile(VBH_ASM_VMX_VMREAD_RDX_RAX
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static __always_inline u16 vmcs_read16(unsigned long field)
{
	return __vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field)
{
	return __vmcs_readl(field);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return __vmcs_readl(field);
#else
	return __vmcs_readl(field) | ((u64)__vmcs_readl(field + 1) << 32);
#endif
}

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	return __vmcs_readl(field);
}

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	pr_err("vmwrite error: reg %lx value %lx (err %d)\n",
		field,
		value,
		vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static __always_inline void __vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile(__ex(VBH_ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value),
		"d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

static __always_inline void vmcs_write16(unsigned long field, u16 value)
{
	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write32(unsigned long field, u32 value)
{
	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write64(unsigned long field, u64 value)
{
	__vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile("");
	__vmcs_writel(field + 1, value >> 32);
#endif
}

static __always_inline void vmcs_writel(unsigned long field, unsigned long value)
{
	__vmcs_writel(field, value);
}

static __always_inline void asm_pause_cpu(void)
{
	asm volatile("pause" ::: "memory");
}

static inline u16 kvm_read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

#ifdef CONFIG_X86_64
static inline unsigned long read_msr(unsigned long msr)
{
	u64 value;

	rdmsrl(msr, value);
	return value;
}
#endif


extern unsigned long *vmx_msr_bitmap_switch;

extern void vmx_switch_skip_instruction(void);

extern unsigned long *get_ept_entry(unsigned long long gpa);
extern void set_ept_entry_prot(unsigned long*, int, int, int);

extern int get_ept_entry_prot(unsigned long entry);

extern void monitor_cpu_events(unsigned long mask, bool enable, cpu_reg_e reg);
extern void get_guest_state_pcpu(void);

extern void handle_cr_monitor_req(cpu_control_params_t *cpu_param);

extern void handle_msr_monitor_req(msr_control_params_t *msr_param);

extern void cpu_switch_flush_tlb_smp(void);

extern int pause_other_vcpus(int immediate);

extern int resume_other_vcpus(void);

extern void handle_msr_monitor_req(msr_control_params_t *msr_param);
extern inline int all_vcpus_paused(void);
extern void make_request(int request, int wait);
extern void make_request_on_cpu(int cpu, int request, int wait);
extern void vbh_tlb_shootdown(void);
extern void set_guest_rip(void);

extern void* get_vcpu(int cpu);

extern int vmx_switch_to_nonroot(void);
extern bool check_vbh_status(void);

extern void handle_read_msr(struct vcpu_vmx *vcpu);
extern void handle_write_msr(struct vcpu_vmx *vcpu);

extern int hvi_handle_event_cr(__u16 cr, unsigned long old_value, unsigned long new_value, int* allow);
extern int hvi_handle_event_msr(__u32 msr, __u64 old_value, __u64 new_value, int* allow);
extern int hvi_handle_event_vmcall(void);
extern int hvi_handle_event_dfo(int *params);

extern void dump_entries(u64 gpa);
extern void handle_kernel_hardening_hypercall(u64 params);
extern void post_handle_vmexit_mov_to_cr(void);
extern void handle_read_msr(struct vcpu_vmx *vcpu);
extern void handle_write_msr(struct vcpu_vmx *vcpu);

extern void vmx_switch_skip_instruction(void);

extern void cpu_switch_flush_tlb_smp(void);

extern void vbh_tlb_shootdown(void);

extern void vcpu_exit_request_handler(unsigned int request);

extern void asm_make_vmcall(unsigned int hypercall_id, void *params);

extern void handle_vcpu_request_hypercall(struct vcpu_vmx *vcpu, u64 params);

extern int hvi_handle_ept_violation(__u64 gpa, __u64 gla, int *allow);

extern void vmx_switch_and_exit_handle_vmexit(void);

extern void setup_ept_tables(void);
extern void unload_vbh_per_cpu(void *info);
extern int vmx_switch_to_nonroot(void);
extern bool check_vbh_status(void);

extern void make_request(int request, int wait);
extern void make_request_on_cpu(int cpu, int request, int wait);
extern int pause_other_vcpus(int immediate);
extern void handle_vcpu_request_hypercall(struct vcpu_vmx *vcpu, u64 params);

extern int inject_trap(int vcpu_nr, u8 trap_number, u32 error_code, u64 cr2);

extern int hvi_handle_exception(vm_entry_int_info exception_info, __u32 interruption_error_code, int *allow);
extern int handle_ex_bitmap_update_hypercall(exception_bitmap_params_t *exception_bitmap_update_params);

#endif
