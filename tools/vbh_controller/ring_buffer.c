#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "vbh_controller_ds.h"
#include "ring_buffer.h"

// The hidden definition of our ring buffer structure
struct ring_buffer {
	struct vmx_event *buffer;
	size_t head;
	size_t tail;
	size_t max;   //of the buffer
	bool full;
	spinlock_t lock;
};

rbuf_handle_t ring_buf_init(size_t size)
{
	rbuf_handle_t rbuf = NULL;
	if (size <= 0)
		return NULL;

	rbuf = kmalloc(sizeof(ring_buffer_t), GFP_KERNEL);
	if (!rbuf)
	{
		printk(KERN_ERR "%s failed to allocate ring buffer.", __func__);
		return NULL;
	}

	rbuf->buffer = kmalloc(sizeof(struct vmx_event)*size, GFP_KERNEL);
	if (!rbuf->buffer)
	{
		printk(KERN_ERR "%s failed to allocate memory.", __func__);
		
		kfree(rbuf);
		
		return NULL;
	}
	
	spin_lock_init(&rbuf->lock);
	
	rbuf->max = size;
	ring_buf_reset(rbuf);

	return rbuf;
}

static void ring_buf_reset_internal(rbuf_handle_t rbuf)
{
	rbuf->head = 0;
	rbuf->tail = 0;
	rbuf->full = false;
}

void ring_buf_reset(rbuf_handle_t rbuf)
{
	if (!rbuf)
		return;
	
	spin_lock(&rbuf->lock);
	
	ring_buf_reset_internal(rbuf);
	
	spin_unlock(&rbuf->lock);
}

void ring_buf_free(rbuf_handle_t rbuf)
{
	spin_lock(&rbuf->lock);
	if (rbuf)
		if (rbuf->buffer)
			kfree(rbuf->buffer);
		kfree(rbuf);
	
	spin_unlock(&rbuf->lock);
}

bool ring_buf_full(rbuf_handle_t rbuf)
{
	if(rbuf)
		return rbuf->full;
	
	return 0;
}

bool ring_buf_empty(rbuf_handle_t rbuf)
{
	if (rbuf)
		return (!rbuf->full && (rbuf->head == rbuf->tail));
	
	return 0;
}

size_t ring_buf_capacity(rbuf_handle_t rbuf)
{
	if (rbuf)
		return rbuf->max;
	
	return 0;
}

size_t ring_buf_size(rbuf_handle_t rbuf)
{
	size_t size;
	if (!rbuf)
		return 0;

	size = rbuf->max;

	if (!rbuf->full) {
		if (rbuf->head >= rbuf->tail)
			size = (rbuf->head - rbuf->tail);
		else
			size = (rbuf->max + rbuf->head - rbuf->tail);
	}

	return size;
}

static void advance_head(rbuf_handle_t rbuf)
{
	if (!rbuf)
		return;
	
	if (rbuf->full)
		rbuf->tail = (rbuf->tail + 1) % rbuf->max;

	rbuf->head = (rbuf->head + 1) % rbuf->max;
	rbuf->full = (rbuf->head == rbuf->tail);
}

static void advance_tail(rbuf_handle_t rbuf)
{
	if (!rbuf)
		return;

	rbuf->full = false;
	rbuf->tail = (rbuf->tail + 1) % rbuf->max;
}

struct vmx_event *ring_buf_insert(rbuf_handle_t rbuf)
{
	struct vmx_event *pcurrent;
	
	if (!rbuf || !rbuf->buffer)
		return NULL;

	spin_lock(&rbuf->lock);
	
	pcurrent = &rbuf->buffer[rbuf->head];

	advance_head(rbuf);
	
	spin_unlock(&rbuf->lock);
	
	return pcurrent;
}

struct vmx_event *ring_buf_remove(rbuf_handle_t rbuf)
{
	struct vmx_event *pcurrent = NULL;
	
	if(!rbuf || !rbuf->buffer)
		return NULL ;

	spin_lock(&rbuf->lock);
	if(!ring_buf_empty(rbuf))
	{
		pcurrent = &rbuf->buffer[rbuf->tail] ;
		advance_tail(rbuf) ;
	}

	spin_unlock(&rbuf->lock);
	return pcurrent ;
}

int ring_buf_copy_to_user(rbuf_handle_t rbuf, char __user *user_buffer, int length)
{
	int bytes_copied = 0;
	int data_size = 0;
	
	spin_lock(&rbuf->lock);
	
	data_size = ring_buf_size(rbuf) * sizeof(struct vmx_event);
	
	if (length < data_size)
	{
		spin_unlock(&rbuf->lock);
		return 0;
	}
	
	if (rbuf->head > rbuf->tail)
	{
		if (copy_to_user(user_buffer, &rbuf->buffer[rbuf->tail], data_size) == 0)
			bytes_copied = data_size;
		
		printk(KERN_ERR "<vbh_controller>: %s-1 bytes_copied = %d.\n", __func__, bytes_copied);
	}
	else
	{
		// first get data from tail to end
		int to_be_copied = ring_buf_capacity(rbuf) - rbuf->tail;
		
		data_size = to_be_copied * sizeof(struct vmx_event);
		
		if (copy_to_user(user_buffer, &rbuf->buffer[rbuf->tail], data_size) == 0)
			bytes_copied = data_size;
		
		// then get data from begin to head
		to_be_copied = rbuf->head;
		
		data_size = to_be_copied * sizeof(struct vmx_event);
		
		if (copy_to_user(user_buffer, rbuf->buffer, data_size) == 0)
			bytes_copied += data_size;
		
		printk(KERN_ERR "<vbh_controller>: %s-2 bytes_copied = %d.\n", __func__, bytes_copied);
	}
	
	ring_buf_reset_internal(rbuf);
	
	spin_unlock(&rbuf->lock);

	return bytes_copied;
}
