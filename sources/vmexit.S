#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/asm.h>
#include <asm/percpu.h>

#include "offsets.h"

ENTRY(vmx_switch_and_exit_handle_vmexit)
	push %rax
	push %rbx
	push %rcx
	push %rdx

	mov $0x4402, %edx // read vmexit reason
	vmread %rdx, %rax
	cmp $0x1a, %rax
	jne other_than_vmxoff

	mov $0x681e, %edx // read guest rip
	vmread %rdx, %rax
	mov %rax, %rcx

	mov $0x440c, %edx // read guest rip length
	vmread %rdx, %rax
	add %rax, %rcx

	mov    $0x681c, %edx  //read guest rsp
	vmread %rdx, %rax
	mov    %rax, %rbx

	mov    $0x6820, %edx  //read guest rflags
	vmread %rdx, %rax

	mov %rsp, %rdx
	mov %rbx, %rsp

	push $0x18 //push the guest state on stack for iretq
	push %rbx
	push %rax
	push $0x10
	push %rcx

	mov 0x18(%rdx), %rax
	mov 0x10(%rdx), %rbx
	mov 0x08(%rdx), %rcx
	mov (%rdx), %rdx

	call vmcs_clear

	vmxoff

	iretq

other_than_vmxoff:
	pop %rdx
	pop %rcx
	pop %rbx
	pop %rax
//push rcx
	push %rcx
//move reg scratch to rcx
	PER_CPU(reg_scratch, %rcx)
//copy rax thru rbp thru r11 to offsets within rcx
//use enum*8 as offset
	mov %rax, (VCPU_REGS_RAX*8)(%rcx)
	mov %rbx, (VCPU_REGS_RBX*8)(%rcx)
	mov %rdx, (VCPU_REGS_RDX*8)(%rcx)
	mov %rsi, (VCPU_REGS_RSI*8)(%rcx)
	mov %rdi, (VCPU_REGS_RDI*8)(%rcx)
	mov %rbp, (VCPU_REGS_RBP*8)(%rcx)
	mov %rsp, (VCPU_REGS_RSP*8)(%rcx)
	popq (VCPU_REGS_RCX*8)(%rcx)
	mov %r8 , (VCPU_REGS_R8*8)(%rcx)
	mov %r9 , (VCPU_REGS_R9*8)(%rcx)
	mov %r10, (VCPU_REGS_R10*8)(%rcx)
	mov %r11, (VCPU_REGS_R11*8)(%rcx)
	mov %r12, (VCPU_REGS_R12*8)(%rcx)
	mov %r13, (VCPU_REGS_R13*8)(%rcx)
	mov %r14, (VCPU_REGS_R14*8)(%rcx)
	mov %r15, (VCPU_REGS_R15*8)(%rcx)
    mov %cr2, %rax
    mov %rax, (VCPU_REGS_CR2*8)(%rcx)
//call the C part of handler
	call vmx_switch_and_exit_handler
//copy values from memory into registers
	PER_CPU(reg_scratch, %rcx)
    mov (VCPU_REGS_CR2*8)(%rcx), %rax
    mov %rax, %cr2
	mov (VCPU_REGS_RAX*8)(%rcx), %rax
	mov (VCPU_REGS_RBX*8)(%rcx), %rbx
	mov (VCPU_REGS_RDX*8)(%rcx), %rdx
	mov (VCPU_REGS_RSI*8)(%rcx), %rsi
	mov (VCPU_REGS_RDI*8)(%rcx), %rdi
	mov (VCPU_REGS_RBP*8)(%rcx), %rbp
	mov (VCPU_REGS_R8*8)(%rcx),  %r8
	mov (VCPU_REGS_R9*8)(%rcx), %r9
	mov (VCPU_REGS_R10*8)(%rcx), %r10
	mov (VCPU_REGS_R11*8)(%rcx), %r11
	mov (VCPU_REGS_R12*8)(%rcx), %r12
	mov (VCPU_REGS_R13*8)(%rcx), %r13
	mov (VCPU_REGS_R14*8)(%rcx), %r14
	mov (VCPU_REGS_R15*8)(%rcx), %r15
	mov (VCPU_REGS_RCX*8)(%rcx), %rcx
//vmresume
	.byte 0x0f, 0x01, 0xc3
	ret
END(vmx_switch_and_exit_handle_vmexit)
