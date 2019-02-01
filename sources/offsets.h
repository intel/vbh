#define	VCPU_REGS_RAX  0
#define	VCPU_REGS_RCX  1
#define	VCPU_REGS_RDX  2
#define	VCPU_REGS_RBX  3
#define	VCPU_REGS_RSP  4
#define	VCPU_REGS_RBP  5
#define	VCPU_REGS_RSI  6
#define	VCPU_REGS_RDI  7
//#define VCPU_REGS_RIP  8
//#define NR_VCPU_REGS   9
#ifdef CONFIG_X86_64
#define	VCPU_REGS_R8  8
#define	VCPU_REGS_R9  9
#define	VCPU_REGS_R10  10
#define	VCPU_REGS_R11  11
#define	VCPU_REGS_R12  12
#define	VCPU_REGS_R13  13
#define	VCPU_REGS_R14  14
#define	VCPU_REGS_R15  15
#define	VCPU_REGS_RIP 16
#define	NR_VCPU_REGS 17
#endif
