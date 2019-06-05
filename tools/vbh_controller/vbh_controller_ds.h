#pragma once
#ifndef __VBH_CONTROLLER_DS_H
#define __VBH_CONTROLLER_DS_H

#include <linux/types.h>

struct vmx_event_cr {
	__u16 cr;
	__u16 padding[3];
	__u64 old_value;
	__u64 new_value;
};

struct vmx_event_msr {
	__u32 msr;
	__u32 padding;
	__u64 old_value;
	__u64 new_value;
};

struct vmx_event_ept_violation
{
	__u64 gla;
	__u64 gpa;
	__u64 g_rip;
	__u64 g_rsp;
	__u32 mode;
	__u32 padding;	
};

typedef struct 
{
	__u32 vcpu;
	__u32 event_type;
	__u64 payload_size;
}vmx_event_metadata_t;

struct vmx_event
{
	vmx_event_metadata_t metadata;
	union
	{
		struct vmx_event_cr cr_event;
		struct vmx_event_msr msr_event;
		struct vmx_event_ept_violation ept_violation;
	};
};
#endif
