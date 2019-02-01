#pragma once

void dump_host_state(int cpu);
void dump_guest_state(int cpu);

static inline long get_rflag(void)
{
	long flag;
	
	__asm__ __volatile__("pushf \n\t"
						"popq %%rax\n\t"
						"movq %%rax, %0\n\t"
						: "=m"(flag)
						:
						: "%rax"
		);
	
	return flag;
}
