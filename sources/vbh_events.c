#include <linux/slab.h>
#include "vbh_status.h"
#include "vmx_common.h"

extern struct hvi_event_callback global_event_callbacks[];

static int hvi_report_event(hv_event_e event, void *data, int size, int *allow);

int hvi_handle_event_cr(__u16 cr, unsigned long old_value,
	unsigned long new_value, int *allow)
{
	struct hvi_event_cr cr_event;

	cr_event.cr = cr;

	cr_event.old_value = old_value;

	cr_event.new_value = new_value;

	return hvi_report_event(cr_write, (void *)&cr_event,
		sizeof(struct hvi_event_cr), allow);
}

int hvi_handle_event_msr(__u32 msr, __u64 old_value,
	__u64 new_value, int *allow)
{
	struct hvi_event_msr msr_event;

	msr_event.msr = msr;

	msr_event.old_value = old_value;

	msr_event.new_value = new_value;

	return hvi_report_event(msr_write, (void *)&msr_event,
		sizeof(struct hvi_event_msr), allow);
}

int hvi_handle_event_dfo(int *params)
{
	int allow;

	return hvi_report_event(vmcall, params, sizeof(int *), &allow);
}

int hvi_handle_event_vmcall(void)
{
	int allow;

	return hvi_report_event(vmcall, NULL, 0, &allow);
}

int hvi_handle_ept_violation(__u64 gpa, __u64 gla, int *allow)
{
	struct hvi_event_ept_violation ept_violation_event = {0};

	ept_violation_event.gpa = gpa;
	ept_violation_event.gla = gla;

	return hvi_report_event(ept_violation, (void *)&ept_violation_event,
		sizeof(struct hvi_event_ept_violation), allow);
}

int hvi_handle_exception(vm_entry_int_info exception_info, __u32 interruption_error_code, int* allow)
{
	struct hvi_event_exception exception_event;

	exception_event.exception_number = exception_info.fields.vector;
	exception_event.interruption_error_code = interruption_error_code;

    return hvi_report_event(exception, &exception_event, sizeof(exception_event), allow);
}

static int hvi_report_event(hv_event_e event, void *data, int size, int *allow)
{
	if (global_event_callbacks[event].callback != NULL) {
		global_event_callbacks[event].callback(event,
			(unsigned char *)data, size, allow);
		return 0;
	}

	return -1;
}
