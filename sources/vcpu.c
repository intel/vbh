#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/processor.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/time.h>

#include "vmx_common.h"

DECLARE_BITMAP(paused_vcpus, NR_CPUS);

static atomic_t resume = ATOMIC_INIT(0);

static void pause_vcpu_work_handler(struct work_struct *work);

static void pause_vcpu(void* info);

extern void asm_make_vmcall(unsigned int hypercall_id, void *params);

int pause_other_vcpus(void);

static void pause_vcpu_work_handler(struct work_struct *work)
{
	int cpu;
	
	cpu = smp_processor_id();
		
	// use vmcall to enter root mode
	asm_make_vmcall(PAUSE_VCPU_HYPERCALL, NULL);
	
	printk(KERN_ERR "<1> CPU-[%d] pause_vcpu_work_handler is back to guest. \n", cpu);
}

// This function is in ipi interrupt context.  Don't block.
static void pause_vcpu(void* info)
{
	int cpu;

	cpu = get_cpu();
		
	printk(KERN_ERR "<1> pause_vcpu is received on CPU-[%d].\n", cpu);
	
	pause_vcpu_work_handler(NULL);
	
	put_cpu();
}

int resume_other_vcpus(void)
{	
	printk(KERN_ERR "<1> resume_other_vcpus is called on CPU-[%d]: resuming....\n", smp_processor_id());
	
	atomic_set(&resume, 1);
	
	return 0;
}

int pause_other_vcpus(void)
{
	char cpumask_print_buf[1024] = { 0 };
	int buf_len;
	
	struct timeval start, end;
	unsigned long elapsed;

	int me, cpu;

	int total_cpus = num_online_cpus();
	
	cpumask_t pause_mask = { CPU_BITS_NONE };
	
	me = smp_processor_id();

	bitmap_zero(paused_vcpus, total_cpus);
	
	printk(KERN_ERR "<1> pause_other_vcpus is called on cpu: %d, total online cpu = %d.\n", me, total_cpus);
	
	if (total_cpus > 1)
	{	
		bitmap_set(paused_vcpus, me, 1);
		
		for_each_online_cpu(cpu)
		{
			if (cpu != me)
			{									
				cpumask_set_cpu(cpu, &pause_mask);
			}				
		}
		
		buf_len = cpumap_print_to_pagebuf(1, cpumask_print_buf, &pause_mask);
		
		printk(KERN_ERR "<1> pause_other_vcpus: Ready to send IPI, pause_mask=%s, interrupt is %s.\n", cpumask_print_buf, irqs_disabled()?"disabled":"enabled");
		
		do_gettimeofday(&start);
		
		on_each_cpu_mask(&pause_mask, pause_vcpu, NULL, 0);
		
		spin_until_cond(bitmap_full(paused_vcpus,total_cpus));
		
		do_gettimeofday(&end);
		
		elapsed = timeval_to_ns(&end) - timeval_to_ns(&start);
		
		printk(KERN_ERR "<1> pause_other_vcpus: It takes %ld ns to pause all vcpus.\n", elapsed);
		
		//return paused_vcpus[0];
		return 0;
	}
	
	return -1;
}

void handle_pause_vcpu_hypercall(struct vcpu_vmx *vcpu, u64 params)
{
	struct timeval start, end;
	unsigned long paused_time;
	
	int cpu = smp_processor_id();
	
	printk(KERN_ERR "<1>handle_pause_vcpu_hypercall on vcpu=%d.\n", cpu);
	
	do_gettimeofday(&start);
	
	bitmap_set(paused_vcpus, cpu, 1);
	
	while (!atomic_read(&resume))
	{
		asm_pause_cpu();
	};

	do_gettimeofday(&end);
	
	paused_time = timeval_to_ns(&end) - timeval_to_ns(&start);
	
	printk(KERN_ERR "<1>vcpu-[%d] has been paused %ld ns. Resuming....\n", cpu, paused_time);			
}
