#include <linux/slab.h>

#include "hypervisor_introspection.h"

extern hv_event_callback global_event_callback;

void hvi_handle_event_cr(__u16 cr, unsigned long old_value, unsigned long new_value);

int hvi_report_event(hv_event_e event, void* data, int size);

void hvi_handle_event_cr(__u16 cr, unsigned long old_value, unsigned long new_value)
{
	struct hvi_event_cr cr_event;
	
	cr_event.cr = cr;
	
	cr_event.old_value = old_value;
	
	cr_event.new_value = new_value;
	
	hvi_report_event(cr_write, (void*)&cr_event, sizeof(struct hvi_event_cr));
}

void hvi_handle_event_msr(__u32 msr, __u64 old_value, __u64 new_value)
{
	struct hvi_event_msr msr_event;
	
	msr_event.msr = msr;
	
	msr_event.old_value = old_value;
	
	msr_event.new_value = new_value;
	
	hvi_report_event(msr_write, (void*)&msr_event, sizeof(struct hvi_event_msr));
}

void hvi_handle_event_vmcall(void)
{
	hvi_report_event(vmcall, NULL, 0);
}

int hvi_report_event(hv_event_e event, void* data, int size)
{
	if (global_event_callback != NULL)
	{
		global_event_callback(event, (unsigned char*)data, size);
		return 0;
	}
		
	return -1;
}
