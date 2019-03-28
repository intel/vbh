#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/processor.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/time.h>

#include "vmx_common.h"
#include "hypervisor_introspection.h"

cpu_control_params_t cr_ctrl;
msr_control_params_t msr_ctrl;

DEFINE_PER_CPU(struct vcpu_request, vcpu_req);

// Each bit represents a vcpu.  The corresponding vcpu is paused when a bit is set.
static DECLARE_BITMAP(paused_vcpus, NR_CPUS);

// Each bit represents a vcpu.  The bit is cleared after pending request on a vcpu is handled.
static DECLARE_BITMAP(pending_request_on_vcpus, NR_CPUS);

static void pause_vcpu(void* info);

inline int all_vcpus_paused(void);

extern void vcpu_exit_request_handler(unsigned int request);
extern void handle_cr_monitor_req(cpu_control_params_t* cpu_param);
extern void handle_msr_monitor_req(msr_control_params_t* msr_param);
extern void vbh_tlb_shootdown(void);
extern int get_guest_state_pcpu(hvi_query_info_e query_type);

void make_request(int request, int wait);

void make_request_on_cpu(int cpu, int request, int wait);

int pause_other_vcpus(void);

void handle_vcpu_request_hypercall(struct vcpu_vmx *vcpu, u64 params);

inline int all_vcpus_paused(void)
{
	return bitmap_full(paused_vcpus, num_online_cpus());
}

// This function is in ipi context.  Don't block.
static void pause_vcpu(void* info)
{
	int cpu;

	cpu = get_cpu();
		
	printk(KERN_ERR "<1> pause_vcpu is received on CPU-[%d].\n", cpu);
	
	vcpu_exit_request_handler(VCPU_REQUEST_HYPERCALL);
	
	put_cpu();
}

void make_request_on_cpu(int cpu, int request, int wait)
{
	struct vcpu_request *req=NULL;
	
	req = &per_cpu(vcpu_req, cpu);
	
	set_bit(request, req->pcpu_requests);
	
	if (test_and_set_bit(cpu, pending_request_on_vcpus))
		printk(KERN_ERR "<1> make_request: VCPU-[%d] still has pending request.\n", cpu);
	
	if (wait)
		spin_until_cond(test_bit(request, req->pcpu_requests)==0 && test_bit(cpu, pending_request_on_vcpus)==0);
}

void make_request(int request, int wait)
{
	int me, cpu, online_cpus;

	me = smp_processor_id();
	online_cpus = num_online_cpus();
	
	for_each_online_cpu(cpu)
	{
		if (cpu != me)
		{	
			make_request_on_cpu(cpu , request, false);
		}				
	}
	
	wmb();
	
	if (wait)
		spin_until_cond(bitmap_empty(pending_request_on_vcpus, num_online_cpus()));
}

int resume_other_vcpus(void)
{	
	int online_cpus = num_online_cpus();
	
	printk(KERN_ERR "<1> resume_other_vcpus is called on CPU-[%d]: resuming....\n", smp_processor_id());	
	
	if (!all_vcpus_paused())
	{
		char buf[100] = { 0 };
		
		bitmap_print_to_pagebuf(true, buf, paused_vcpus, online_cpus);
		
		printk(KERN_ERR "<!ERROR!> resume_other_vcpus:  Only vcpus: %s are paused.\n", buf);
		
		make_request(VBH_REQ_RESUME, false);
		
		return -1;
	}
			
	make_request(VBH_REQ_RESUME, true);
	
	return 0;
}

int pause_other_vcpus(void)
{
	char cpumask_print_buf[100] = { 0 };
	
	struct timeval start, end;
	unsigned long elapsed;

	int cpu;
	int me = smp_processor_id();	
	
	int online_cpus = num_online_cpus();
	
	cpumask_t pause_mask = { CPU_BITS_NONE };
	
	printk(KERN_ERR "<1> pause_other_vcpus is called on cpu: %d, total online cpu = %d.\n", me, online_cpus);
	
	bitmap_zero(paused_vcpus, online_cpus);
	
	bitmap_set(paused_vcpus, me, 1);
	
	// if all vcpus are already paused (including self), there is nothing to do.
	if(all_vcpus_paused())
	{
		printk(KERN_ERR "<1>pause_other_vcpus: already paused.\n");
		return 0;
	}
	
	make_request(VBH_REQ_PAUSE, false);		
		
	// only send ipi to other cpus except self	
	for_each_online_cpu(cpu)
		if (cpu != me)
			cpumask_set_cpu(cpu, &pause_mask);
	
	cpumap_print_to_pagebuf(true, cpumask_print_buf, &pause_mask);		
	printk(KERN_ERR "<1> pause_other_vcpus: Ready to send IPI, pause_mask=%s, interrupt is %s.\n", cpumask_print_buf, irqs_disabled() ? "disabled" : "enabled");
	
	do_gettimeofday(&start);
		
	// send ipi to all other vcpus
	on_each_cpu_mask(&pause_mask, pause_vcpu, NULL, 0);
		
	// wait until all cpus enter root mode
	spin_until_cond(bitmap_full(paused_vcpus,online_cpus));
		
	do_gettimeofday(&end);
		
	elapsed = timeval_to_ns(&end) - timeval_to_ns(&start);
		
	printk(KERN_ERR "<1> pause_other_vcpus: It takes %ld ns to pause all vcpus.\n", elapsed);
		
	return 0;
}

void handle_vcpu_request_hypercall(struct vcpu_vmx *vcpu, u64 params)
{
	struct timeval start, end;
	unsigned long paused_time;
	struct vcpu_request *req;
	
	int pause_requested = 0;
	
	int me = smp_processor_id();	
	
	req = this_cpu_ptr(&vcpu_req);

	do_gettimeofday(&start);

	do
	{	
		// If I have a pending request
		if (test_bit(me, pending_request_on_vcpus))
		{		
			if (test_and_clear_bit(VBH_REQ_PAUSE, req->pcpu_requests))
			{
				printk(KERN_ERR "<1>handle_vcpu_request: PAUSE on vcpu=%d\n", me);
			
				pause_requested = 1;
			
				// let requestor know that I'm paused.
				set_bit(me, paused_vcpus);				
			}
				
			if (test_and_clear_bit(VBH_REQ_RESUME, req->pcpu_requests))
			{
				printk(KERN_ERR "<1>handle_vcpu_request: RESUME on vcpu=%d.\n", me);		
			
				pause_requested = 0;
			}
					
			if (test_bit(VBH_REQ_SET_RFLAGS, req->pcpu_requests))
			{					
				printk(KERN_ERR "<1>handle_vcpu_request: SET_RFLAGS on vcpu=%d, curr_value=0x%lx, new_value=0x%lx.\n", me, vmcs_readl(GUEST_RFLAGS), req->new_value);
				
				vmcs_writel(GUEST_RFLAGS, req->new_value);
				
				clear_bit(VBH_REQ_SET_RFLAGS, req->pcpu_requests);
			}
			
			if (test_bit(VBH_REQ_GUEST_STATE, req->pcpu_requests))
			{
				printk(KERN_ERR "<1>handle_vcpu_request: VBH_REQ_GUEST_STATE on vcpu=%d.\n", me);
				get_guest_state_pcpu(req->query_gstate_type);
				clear_bit(VBH_REQ_GUEST_STATE, req->pcpu_requests);
			}
					
			if (test_and_clear_bit(VBH_REQ_SET_RIP, req->pcpu_requests))
			{
				printk(KERN_ERR "<1>handle_vcpu_request: SET_RIP on vcpu=%d, new_value=0x%lx.\n", me, req->new_value);
				
				if (req->new_value != 0)					
					vmcs_writel(GUEST_RIP, req->new_value);
				else
					printk(KERN_ERR "<!ERROR!>handle_vcpu_request: SET_RIP on vcpu=%d.  Invalid RIP value.\n", me);
			}
					
			if (test_and_clear_bit(VBH_REQ_INVEPT, req->pcpu_requests))
			{			
				printk(KERN_ERR "<1>handle_vcpu_request: INVEPT on vcpu=%d.\n", me);			
			
				vbh_tlb_shootdown();			
			}
				
			if (test_and_clear_bit(VBH_REQ_MODIFY_CR, req->pcpu_requests))
			{
				printk(KERN_ERR "<1>handle_vcpu_request: MODIFY_CR on vcpu=%d.\n", me);
			
				handle_cr_monitor_req(&cr_ctrl);
			}
				
			if (test_and_clear_bit(VBH_REQ_MODIFY_MSR, req->pcpu_requests))
			{
				printk(KERN_ERR "<1>handle_vcpu_request: MODIFY_MSR on vcpu=%d.\n", me);
			
				handle_msr_monitor_req(&msr_ctrl);
			}
			
			// Done processing request
			clear_bit(me, pending_request_on_vcpus);
		}
		
		asm_pause_cpu();
		
	} while (pause_requested);

	do_gettimeofday(&end);
	
	paused_time = timeval_to_ns(&end) - timeval_to_ns(&start);
	
	printk(KERN_ERR "<1>vcpu-[%d] has been paused %ld ns. Resuming....\n", me, paused_time);			
}
