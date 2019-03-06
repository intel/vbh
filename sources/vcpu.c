#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/processor.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/time.h>

#include "vmx_common.h"

DECLARE_BITMAP(paused_cpus, NR_CPUS);

static atomic_t resume = ATOMIC_INIT(0);

//struct pause_vcpu_workq_struct
//{
//	struct pause_vcpu_work_data *work_data;
//	struct workqueue_struct *work_q;
//};

//struct pause_vcpu_workq_struct** workq_array[NR_CPUS] = { 0 };

static void pause_vcpu_work_handler(struct work_struct *work);

static void pause_vcpu(void* info);

extern void asm_make_vmcall(unsigned int hypercall_id, void *params);

int pause_other_vcpus(void);

static void pause_vcpu_work_handler(struct work_struct *work)
{
	int cpu;
	//struct vcpu_vmx *vcpu_ptr;
	
	cpu = smp_processor_id();
	//cpu = get_cpu();
	
	//vcpu_ptr = this_cpu_ptr(vcpu);
	
	//printk(KERN_ERR "<1> CPU-[%d] pause_vcpu_work_handler is kicked off.  Ready to halt in root mode.\n", cpu);
		
	// use vmcall to enter root mode
	asm_make_vmcall(PAUSE_VCPU_HYPERCALL, NULL);
	//bitmap_set(paused_cpus, cpu, 1);
	
	printk(KERN_ERR "<1> CPU-[%d] pause_vcpu_work_handler is back to guest. \n", cpu);
	// clean up
//	if(vcpu_ptr->pause_vcpu_work != NULL)
//		kfree(vcpu_ptr->pause_vcpu_work);
//	
//	flush_workqueue(vcpu_ptr->pause_vcpu_wq);
//	
//	destroy_workqueue(vcpu_ptr->pause_vcpu_wq);
	
	//put_cpu();
}

// This function is in ipi interrupt context.  Don't block.
static void pause_vcpu(void* info)
{
	int cpu;

	//struct vcpu_vmx *vcpu_ptr;
	
	cpu = get_cpu();
		
#if 0
	vcpu_ptr = this_cpu_ptr(vcpu);
	printk(KERN_ERR "<1> pause_vcpu is received on cpu <%d>. Ready to queue work.\n", cpu);
	queue_work_on(cpu, vcpu_ptr->pause_vcpu_wq, &vcpu_ptr->pause_vcpu_work->work);
#else
	printk(KERN_ERR "<1> pause_vcpu is received on CPU-[%d].\n", cpu);
	pause_vcpu_work_handler(NULL);
#endif
	
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
	//struct vcpu_vmx *vcpu_ptr;

	int total_cpus = num_online_cpus();
	
	cpumask_t pause_mask = { CPU_BITS_NONE };
	
	me = smp_processor_id();

	bitmap_zero(paused_cpus, total_cpus);
	
	printk(KERN_ERR "<1> pause_other_vcpus is called on cpu: %d, total online cpu = %d.\n", me, total_cpus);
	
	if (total_cpus > 1)
	{	
		bitmap_set(paused_cpus, me, 1);
		
		for_each_online_cpu(cpu)
		{
			if (cpu != me)
			{				
//				vcpu_ptr = per_cpu_ptr(vcpu, cpu);
//				
//				vcpu_ptr->pause_vcpu_work = kmalloc(sizeof(struct pause_vcpu_work_data), GFP_ATOMIC);						
//				vcpu_ptr->pause_vcpu_wq = create_workqueue("pause_vcpu_wq");
//				
//				vcpu_ptr->pause_vcpu_work->data = cpu;
//				
//				INIT_WORK(&vcpu_ptr->pause_vcpu_work->work, pause_vcpu_work_handler);
					
				cpumask_set_cpu(cpu, &pause_mask);
			}				
		}
		
		buf_len = cpumap_print_to_pagebuf(1, cpumask_print_buf, &pause_mask);
		
		printk(KERN_ERR "<1> pause_other_vcpus: Ready to send IPI, pause_mask=%s, interrupt is %s.\n", cpumask_print_buf, irqs_disabled()?"disabled":"enabled");
		
		do_gettimeofday(&start);
		
		on_each_cpu_mask(&pause_mask, pause_vcpu, NULL, 0);
		
		spin_until_cond(bitmap_full(paused_cpus,total_cpus));
		
		//printk(KERN_ERR "<1> pause_other_vcpus: All cpus are paused, paused_cpus=0x%lx.\n", paused_cpus[0]);
		
		do_gettimeofday(&end);
		
		elapsed = timeval_to_ns(&end) - timeval_to_ns(&start);
		
		printk(KERN_ERR "<1> pause_other_vcpus: It takes %ld ns to pause all vcpus.\n", elapsed);
		
		//put_cpu();
		return paused_cpus[0];
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
	
	bitmap_set(paused_cpus, cpu, 1);
	
	while (!atomic_read(&resume))
	{
		asm_pause_cpu();
	};

	do_gettimeofday(&end);
	
	paused_time = timeval_to_ns(&end) - timeval_to_ns(&start);
	
	printk(KERN_ERR "<1>vcpu-[%d] has been paused %ld ns. Resuming....\n", cpu, paused_time);			
}
