#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/asm.h>

ENTRY(asm_make_vmcall)
pushq %rax
pushq %rbx

movq %rdi, %rax
movq %rsi, %rbx

vmcall

popq %rbx
popq %rax

ret
END(asm_make_vmcall)
