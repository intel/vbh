// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/processor.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>

#include "vmx_common.h"
#include "hypervisor_introspection.h"
#include "vbh_status.h"

// The first timeout is 10 us
#define INIT_IPI_TIMEOUT_1				10
// The second timeout is 1ms
#define INIT_IPI_TIMEOUT_2				1000
// The thirst timeout is 10ms
#define INIT_IPI_TIMEOUT_3				(10*1000)
// timeout every 10ms
#define VCPU_PAUSE_WAIT_TIMEOUT_IN_US	(10*1000)

cpu_control_params_t cr_ctrl;
msr_control_params_t msr_ctrl;
exception_bitmap_params_t exception_ctrl;

DEFINE_PER_CPU(struct vcpu_request, vcpu_req);

// Each bit represents a vcpu.
// The corresponding vcpu is paused when a bit is set.
static DECLARE_BITMAP(paused_vcpus, NR_CPUS);

// Each bit represents a vcpu.
// The bit is cleared after pending request on a vcpu is handled.
static DECLARE_BITMAP(pending_request_on_vcpus, NR_CPUS);

static int vbh_cpu_present_to_apicid(int cpu);

static void pause_vcpu(void *info);

static void vbh_timer_set(struct timespec *start);
static int vbh_timed_out(int timeout_in_ns, struct timespec *start);

inline int all_vcpus_paused(void);

int handle_ex_bitmap_update_hypercall(exception_bitmap_params_t *exception_bitmap_update_params);

inline int all_vcpus_paused(void)
{
	return bitmap_full(paused_vcpus, num_online_cpus());
}

static int vbh_cpu_present_to_apicid(int cpu)
{
	return cpu_data(cpu).apicid;
}

static void vbh_timer_set(struct timespec *start)
{
	getnstimeofday(start);
}

static int vbh_timed_out(int timeout_in_us, struct timespec *start)
{
	struct timespec end;

	getnstimeofday(&end);

	if ((end.tv_nsec - start->tv_nsec)/1000 >= timeout_in_us)
		return true;

	return false;
}

// This function is in ipi context.  Don't block.
static void pause_vcpu(void *info)
{
	int cpu;

	cpu = get_cpu();

	pr_err("<1> %s is received on CPU-[%d].\n", __func__, cpu);

	vcpu_exit_request_handler(VCPU_REQUEST_HYPERCALL);

	put_cpu();
}

void make_request_on_cpu(int cpu, int request, int wait)
{
	struct vcpu_request *req = NULL;

	req = &per_cpu(vcpu_req, cpu);

	set_bit(request, req->pcpu_requests);

	if (test_and_set_bit(cpu, pending_request_on_vcpus))
		pr_err("<1> make_request: VCPU-[%d] still has pending request.\n",
		cpu);

	if (wait)
		spin_until_cond(test_bit(request, req->pcpu_requests) == 0 &&
		test_bit(cpu, pending_request_on_vcpus) == 0);
}

void make_request(int request, int wait)
{
	int me, cpu, online_cpus;

	me = smp_processor_id();
	online_cpus = num_online_cpus();

	for_each_online_cpu(cpu) {
		if (cpu != me)
			make_request_on_cpu(cpu, request, false);
	}

	wmb();

	if (wait)
		spin_until_cond(bitmap_empty(pending_request_on_vcpus,
			num_online_cpus()));
}

int resume_other_vcpus(void)
{
	int online_cpus = num_online_cpus();

	pr_err("<1> %s is called on CPU-[%d]: resuming....\n",
		__func__, smp_processor_id());

	if (!all_vcpus_paused()) {
		char buf[100] = { 0 };

		bitmap_print_to_pagebuf(true, buf, paused_vcpus, online_cpus);

		pr_err("<!ERROR!> %s: Only vcpus: %s are paused.\n",
			__func__, buf);

		make_request(VBH_REQ_RESUME, false);

		return -1;
	}

	make_request(VBH_REQ_RESUME, true);

	return 0;
}

static void vbh_send_init_ipi(int cpu, int delay_in_us)
{
	int apicid;

	apicid = vbh_cpu_present_to_apicid(cpu);

	// asserting init ipi line
	apic_icr_write(APIC_INT_LEVELTRIG |
		APIC_INT_ASSERT | APIC_DM_INIT, apicid);

	udelay(delay_in_us);

	// de-asserting
	apic_icr_write(APIC_INT_LEVELTRIG | APIC_DM_INIT, apicid);

	udelay(delay_in_us);
}

static int _immediate_exit_with_timeout(int timeout_in_us)
{
	int cpu;

	int online_cpus;
	struct timespec start;

	online_cpus = num_online_cpus();

	for_each_online_cpu(cpu) {
		if (test_bit(cpu, paused_vcpus))
			continue;

		vbh_send_init_ipi(cpu, timeout_in_us);
	}

	vbh_timer_set(&start);

	spin_until_cond(bitmap_full(paused_vcpus, online_cpus) ||
		vbh_timed_out(VCPU_PAUSE_WAIT_TIMEOUT_IN_US, &start));

	if (bitmap_full(paused_vcpus, online_cpus))
		return 0;

	return -1;
}

static int immediate_exit(void)
{
	DECLARE_BITMAP(un_paused_vcpus, NR_CPUS);

	struct timespec start, end;
	unsigned long elapsed;
	int ret;

	char buf[256] = { 0 };

	getnstimeofday(&start);

	// take chance the first time
	if (_immediate_exit_with_timeout(INIT_IPI_TIMEOUT_1) == 0) {
		ret = 0;
		goto done;
	}

	// be more patient the second time
	bitmap_complement(un_paused_vcpus, paused_vcpus, num_online_cpus());
	bitmap_print_to_pagebuf(true, buf, un_paused_vcpus, num_online_cpus());
	pr_err("<1> %s: Second try on %s...\n", __func__, buf);

	if (_immediate_exit_with_timeout(INIT_IPI_TIMEOUT_2) == 0) {
		ret = 0;
		goto done;
	}

	// last time
	bitmap_complement(un_paused_vcpus, paused_vcpus, num_online_cpus());
	bitmap_print_to_pagebuf(true, buf, un_paused_vcpus, num_online_cpus());
	pr_err("<1> %s: Third try... on %s\n", __func__, buf);

	if (_immediate_exit_with_timeout(INIT_IPI_TIMEOUT_3) == 0) {
		ret = 0;
		goto done;
	}

	ret = -1;

done:
	getnstimeofday(&end);

	elapsed = end.tv_nsec - start.tv_nsec;
	bitmap_print_to_pagebuf(true, buf, paused_vcpus, num_online_cpus());
	pr_err("<1> %s: It takes %ld ns to pause vcpus: %s.\n",
		__func__, elapsed, buf);
	return ret;
}

int pause_other_vcpus(int immediate)
{
	char cpumask_print_buf[100] = { 0 };

	struct timespec start, end;
	unsigned long elapsed;

	int cpu;
	int me = smp_processor_id();

	int online_cpus = num_online_cpus();

	cpumask_t pause_mask = { CPU_BITS_NONE };

	pr_err("<1> %s is called on cpu: %d, total online cpu = %d.\n",
		__func__, me, online_cpus);

	bitmap_zero(paused_vcpus, online_cpus);

	bitmap_set(paused_vcpus, me, 1);

	// if all vcpus are already paused (including self),
	// there is nothing to do.
	if (all_vcpus_paused()) {
		pr_err("<1>%s: already paused.\n", __func__);
		return 0;
	}

	make_request(VBH_REQ_PAUSE, false);

	if (immediate)
		return immediate_exit();

	// only send ipi to other cpus except self
	for_each_online_cpu(cpu)
		if (cpu != me)
			cpumask_set_cpu(cpu, &pause_mask);

	cpumap_print_to_pagebuf(true, cpumask_print_buf, &pause_mask);
	pr_err("<1> %s: Ready to send IPI, pause_mask=%s, interrupt is %s.\n",
		__func__, cpumask_print_buf,
		irqs_disabled() ? "disabled" : "enabled");

	getnstimeofday(&start);

	// send ipi to all other vcpus
	on_each_cpu_mask(&pause_mask, pause_vcpu, NULL, 0);

	// wait until all cpus enter root mode
	spin_until_cond(bitmap_full(paused_vcpus, online_cpus));

	getnstimeofday(&end);

	elapsed = end.tv_nsec - start.tv_nsec;

	pr_err("<1> %s: It takes %ld ns to pause all vcpus.\n",
		__func__, elapsed);

	return 0;
}

void handle_vcpu_request_hypercall(struct vcpu_vmx *vcpu, u64 params)
{
	struct timespec start, end;
	unsigned long paused_time;
	struct vcpu_request *req;

	int pause_requested = 0;

	int me = smp_processor_id();

	req = this_cpu_ptr(&vcpu_req);

	getnstimeofday(&start);

	do {
		// If I have a pending request
		if (test_bit(me, pending_request_on_vcpus)) {
			if (test_and_clear_bit(VBH_REQ_PAUSE, req->pcpu_requests)) {
				pr_err("<1>handle_vcpu_request: PAUSE on vcpu=%d\n",
					me);

				pause_requested = 1;

				// let requestor know that I'm paused.
				set_bit(me, paused_vcpus);
			}

			if (test_bit(VBH_REQ_SET_RFLAGS, req->pcpu_requests)) {
				pr_err("<1>handle_vcpu_request: SET_RFLAGS on vcpu=%d, curr_value=0x%lx, new_value=0x%lx.\n",
					me, vmcs_readl(GUEST_RFLAGS), req->new_value);

				vmcs_writel(GUEST_RFLAGS, req->new_value);

				clear_bit(VBH_REQ_SET_RFLAGS, req->pcpu_requests);
			}

			if (test_bit(VBH_REQ_GUEST_STATE, req->pcpu_requests)) {
				pr_err("<1>handle_vcpu_request: VBH_REQ_GUEST_STATE on vcpu=%d.\n",
					me);
				get_guest_state_pcpu();
				clear_bit(VBH_REQ_GUEST_STATE, req->pcpu_requests);
			}

			if (test_and_clear_bit(VBH_REQ_SET_RIP, req->pcpu_requests)) {
				if (req->new_value != 0)
					vmcs_writel(GUEST_RIP, req->new_value);
				else
					pr_err("<!ERROR!>handle_vcpu_request: SET_RIP on vcpu=%d.  Invalid RIP value.\n",
					me);

				pr_err("<1>handle_vcpu_request: SET_RIP, new guest_rip=0x%lx.\n",
					vmcs_readl(GUEST_RIP));
			}

			if (test_and_clear_bit(VBH_REQ_INVEPT, req->pcpu_requests)) {
				pr_err("<1>handle_vcpu_request: INVEPT on vcpu=%d.\n", me);

				vbh_tlb_shootdown();
			}

			if (test_and_clear_bit(VBH_REQ_MODIFY_CR, req->pcpu_requests)) {
				pr_err("<1>handle_vcpu_request: MODIFY_CR on vcpu=%d.\n", me);

				handle_cr_monitor_req(&cr_ctrl);
			}

			if (test_and_clear_bit(VBH_REQ_MODIFY_MSR, req->pcpu_requests)) {
				pr_err("<1>handle_vcpu_request: MODIFY_MSR on vcpu=%d.\n", me);

				handle_msr_monitor_req(&msr_ctrl);
			}

			if (test_and_clear_bit(VBH_REQ_MODIFY_EXCEPTION_BITMAP, req->pcpu_requests))
			{
				pr_err("handle_vcpu_request: VBH_REQ_MODFY_EXCEPTION_BITMAP on vcpu=%d.\n", me);

				handle_ex_bitmap_update_hypercall(&exception_ctrl);
			}

			if (test_and_clear_bit(VBH_REQ_RESUME, req->pcpu_requests)) {
				pr_err("<1>handle_vcpu_request: RESUME on vcpu=%d.\n", me);

				pause_requested = 0;
			}

			// Done processing request
			clear_bit(me, pending_request_on_vcpus);
		}

		asm_pause_cpu();

	} while (pause_requested);

	getnstimeofday(&end);

	paused_time = end.tv_nsec - start.tv_nsec;

	pr_err("<1>vcpu-[%d] has been paused %ld ns. Resuming....\n",
		me, paused_time);
}
