#pragma once
#ifndef __VBH_CONTROLLER_H
#define __VBH_CONTROLLER_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rwlock_types.h>

//#define LOG_BUFFER_SIZE			8*PAGE_SIZE		// each log buffer take 8 pages
# define LOG_BUFFER_SIZE			48

#define NUM_LOG_BUFFERS				4				// # of log buffers per cpu

#define PENDING_REQUEST_UNLOAD				BIT(0)
#define PENDING_REQUEST_SET_POLICY			BIT(1)
#define PENDING_REQUEST_BUFFER_READY		BIT(2)
#define PENDING_REQUEST_LOG_OFF				BIT(3)

// list of log buffers which are ready to be transferred to user space
extern struct list_head *ready_list;
extern rwlock_t ready_list_lock; 			// lock for ready list, only used when manipulate list

struct vbh_msg
{
	__u16 number;						// buffer number: useful for debug
	__u16 vcpu;
	__u32 size;							// remaining buffer size in bytes
	unsigned char *msg;
	struct list_head list;	
};

//__percpu struct vbh_msg *_vbh_msg;

void asm_make_vmcall(unsigned int hypercall_id, void *params);
void raise_request(int request);
void append_to_pending_policy_list(struct list_head *policy);
void move_msg_logs(struct vbh_msg *pmsg);
void reset_msg_logs(void);
void unregister_vbh_event_handlers(void);
int register_vbh_event_handlers(void);
void process_readall_request(void);

#endif // !__VBH_CONTROLLER_H
