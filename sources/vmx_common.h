#include <linux/percpu.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <asm/vmx.h>

#include "offsets.h"
#include "hypervisor_introspection.h"

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
	struct vmcs *pcpu_vmcs;
	struct vmcs *vmxarea;
	u64 vcpu_stack;
	unsigned long *regs;
	bool instruction_skipped;
	bool skip_instruction_not_used;
};

DECLARE_PER_CPU(struct vcpu_request, vcpu_req);

extern struct vcpu_vmx __percpu* vcpu;
DECLARE_PER_CPU(unsigned long[NR_VCPU_REGS], reg_scratch);
extern unsigned long *vmx_eptp_pml4;

extern cpu_control_params_t cr_ctrl;
extern msr_control_params_t msr_ctrl;

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
#define VBH_REQ_PAUSE		BIT(0)
#define VBH_REQ_RESUME		BIT(1)
#define VBH_REQ_SET_RFLAGS	BIT(2)
#define VBH_REQ_SET_RIP		BIT(3)
#define VBH_REQ_MODIFY_MSR	BIT(4)
#define VBH_REQ_MODIFY_CR	BIT(5)
#define VBH_REQ_INVEPT		BIT(6)
#define VBH_REQ_GUEST_STATE	BIT(7)



static __always_inline unsigned long __vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile(ASM_VMX_VMREAD_RDX_RAX
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

	asm volatile(__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
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
