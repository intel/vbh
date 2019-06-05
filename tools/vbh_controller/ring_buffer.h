#pragma once
#ifndef __RING_BUFFER_H
#define __RING_BUFFER_H

#include <linux/types.h>

#include "vbh_controller_ds.h"

typedef struct ring_buffer ring_buffer_t;
typedef ring_buffer_t* rbuf_handle_t;

/*
 * Initialize ring buffer, set its capacity
 * to size
 * */
rbuf_handle_t ring_buf_init(size_t size);

/*
 * Free allocated memory
 * */
void ring_buf_free(rbuf_handle_t rbuf);

/*
 * Reset ring buffer, head == tail
 **/
void ring_buf_reset(rbuf_handle_t rbuf);

/*
 * Add data to ring buffer
 **/ 
struct vmx_event *ring_buf_insert(rbuf_handle_t rbuf);

/*
 * Retrieve data from ring buffer
 **/
struct vmx_event *ring_buf_remove(rbuf_handle_t rbuf);

/*
 * Return true if ring buffer is empty
 **/
bool ring_buf_empty(rbuf_handle_t rbuf);

/*
 * Return true if ring buffer is full
 **/
bool ring_buf_full(rbuf_handle_t rbuf);

/*
 * Return the maximum capacity of ring buffer
 **/ 
size_t ring_buf_capacity(rbuf_handle_t rbuf);

/*
 * Return the current number of elements in ring buffer
 **/ 
size_t ring_buf_size(rbuf_handle_t rbuf);

/*
 * Copy data in ring buffer to user buffer up to length of bytes
 **/
int ring_buf_copy_to_user(rbuf_handle_t rbuf, char __user *user_buffer, int length);

#endif
