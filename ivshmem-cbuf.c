/*
 * Copyright (c) 2008-2015 Travis Geiselbrecht
 * Copyright 2019-2020 NXP
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include "ivshmem-iovec.h"
#include "ivshmem-cbuf.h"
#include "debug.h"


#define MIN(x,y) ((x) < (y) ? x : y)
#define MAX(x,y) ((x) > (y) ? x : y)

#define DEBUG_ASSERT(cond) BUG_ON(!(cond))
#define event_init(x, y, z) init_completion(x)
#define event_signal(x, y) complete_all(x)
#define event_wait(x) wait_for_completion(x)
#define event_unsignal(x) reinit_completion(x)
#define thread_preempt schedule

#ifndef CBUF_MAX_INCREASE_SIZE
#define CBUF_MAX_INCREASE_SIZE (128 << 10) /* do no increase more than 128kB */
#endif

typedef unsigned long spin_lock_saved_state_t;

/* From little kernel include/pow2.h */

/* routines for dealing with power of 2 values for efficiency */
static inline __always_inline bool ispow2(uint val)
{
    return ((val - 1) & val) == 0;
}

static inline __always_inline uint log2_uint(uint val)
{
    if (val == 0)
        return 0; // undefined

    return (sizeof(val) * 8) - 1 - __builtin_clz(val);
}

static inline __always_inline uint valpow2(uint valp2)
{
    return 1U << valp2;
}

static inline __always_inline uint divpow2(uint val, uint divp2)
{
    return val >> divp2;
}

static inline __always_inline uint modpow2(uint val, uint modp2)
{
    return val & ((1UL << modp2) - 1);
}

// Cribbed from:
// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
static inline __always_inline uint32_t round_up_pow2_u32(uint32_t v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}


#define INC_POINTER(cbuf, ptr, inc) \
    modpow2(((ptr) + (inc)), (cbuf)->len_pow2)

void cbuf_initialize(cbuf_t *cbuf, size_t len)
{
    cbuf_initialize_etc(cbuf, len, vmalloc(len));
}

void cbuf_initialize_etc(cbuf_t *cbuf, size_t len, void *buf)
{
    DEBUG_ASSERT(cbuf);
    DEBUG_ASSERT(len > 0);
    DEBUG_ASSERT(ispow2(len));

    cbuf->head = 0;
    cbuf->tail = 0;
    cbuf->len_pow2 = log2_uint(len);
    cbuf->buf = buf;
    event_init(&cbuf->event, false, 0);
    spin_lock_init(&cbuf->lock);
    mutex_init(&cbuf->mlock);

    printlk(LK_VERBOSE, "%s:%d: len %zd, len_pow2 %u\n", __PRETTY_FUNCTION__,
            __LINE__, len, cbuf->len_pow2);
}

size_t cbuf_space_avail(cbuf_t *cbuf)
{
    uint consumed = modpow2((uint)(cbuf->head - cbuf->tail), cbuf->len_pow2);
    return valpow2(cbuf->len_pow2) - consumed - 1;
}

size_t cbuf_space_used(cbuf_t *cbuf)
{
    return modpow2((uint)(cbuf->head - cbuf->tail), cbuf->len_pow2);
}

int cbuf_increase(cbuf_t *cbuf, unsigned len)
{
    spin_lock_saved_state_t state;
    void *new, *prev;
    unsigned prev_head, prev_tail, new_pow, prev_size;
    cbuf_t prev_cbuf = *cbuf;
    int ret = 0;

    prev = cbuf->buf;
    new_pow = cbuf->len_pow2;
    prev_size = valpow2(cbuf->len_pow2);

retry:
    new_pow++;
    DEBUG_ASSERT(valpow2(new_pow) <= CBUF_MAX_INCREASE_SIZE);
    if (unlikely(valpow2(new_pow) <= prev_size + len))
        goto retry;

    new = vmalloc(valpow2(new_pow));

    if (!new) {
        ret = -ENOMEM;
        goto out;
    }

    spin_lock_irqsave(&cbuf->lock, state);
    /* Make sure there is not enought room in cbuf before changing pointers, in
     * case some bytes were consumed while mutex was being taken. */
    if (len && unlikely(len < cbuf_space_avail(cbuf))) {
        spin_unlock_irqrestore(&cbuf->lock, state);
        vfree(new);
        goto out;
    }

    prev_head = cbuf->head;
    prev_tail = cbuf->tail;

    if (prev_head > prev_tail) {
        memcpy(new, prev + prev_tail, prev_head - prev_tail);
    } else {
        unsigned pos = 0;
        memcpy(new, prev + prev_tail, prev_size - prev_tail);
        pos += prev_size - prev_tail;
        memcpy(new + pos, prev, prev_head);
    }
    cbuf->head = cbuf_space_used(&prev_cbuf);
    cbuf->tail = 0;
    cbuf->buf = new;
    cbuf->len_pow2 = new_pow;

    spin_unlock_irqrestore(&cbuf->lock, state);
    vfree(prev);

out:
    return ret;
}

size_t cbuf_write(cbuf_t *cbuf, const void *_buf, size_t len, bool canreschedule)
{
    const char *buf = (const char *)_buf;
    spin_lock_saved_state_t state;
    size_t write_len;
    size_t pos = 0;


    printlk(LK_VERBOSE, "%s:%d: len %zd\n", __PRETTY_FUNCTION__, __LINE__, len);

    DEBUG_ASSERT(cbuf);
    DEBUG_ASSERT(len < valpow2(cbuf->len_pow2));

    spin_lock_irqsave(&cbuf->lock, state);

    while (pos < len && cbuf_space_avail(cbuf) > 0) {
        if (cbuf->head >= cbuf->tail) {
            if (cbuf->tail == 0) {
                // Special case - if tail is at position 0, we can't write all
                // the way to the end of the buffer. Otherwise, head ends up at
                // 0, head == tail, and buffer is considered "empty" again.
                write_len =
                    MIN(valpow2(cbuf->len_pow2) - cbuf->head - 1, len - pos);
            } else {
                // Write to the end of the buffer.
                write_len =
                    MIN(valpow2(cbuf->len_pow2) - cbuf->head, len - pos);
            }
        } else {
            // Write from head to tail-1.
            write_len = MIN(cbuf->tail - cbuf->head - 1, len - pos);
        }

        // if it's full, abort and return how much we've written
        if (write_len == 0) {
            break;
        }

        if (NULL == buf) {
            memset(cbuf->buf + cbuf->head, 0, write_len);
        } else {
            memcpy(cbuf->buf + cbuf->head, buf + pos, write_len);
        }

        cbuf->head = INC_POINTER(cbuf, cbuf->head, write_len);
        pos += write_len;
    }

    if (cbuf->head != cbuf->tail)
        event_signal(&cbuf->event, false);

    spin_unlock_irqrestore(&cbuf->lock, state);

    // XXX convert to only rescheduling if
    if (canreschedule)
        thread_preempt();

    return pos;
}

size_t cbuf_read(cbuf_t *cbuf, void *_buf, size_t buflen, bool block)
{
    char *buf = (char *)_buf;
    spin_lock_saved_state_t state;
    size_t ret = 0;

    DEBUG_ASSERT(cbuf);

retry:
    // block on the cbuf outside of the lock, which may
    // unblock us early and we'll have to double check below
    if (block)
        event_wait(&cbuf->event);

    spin_lock_irqsave(&cbuf->lock, state);

    // see if there's data available
    if (cbuf->tail != cbuf->head) {
        size_t pos = 0;

        // loop until we've read everything we need
        // at most this will make two passes to deal with wraparound
        while (pos < buflen && cbuf->tail != cbuf->head) {
            size_t read_len;
            if (cbuf->head > cbuf->tail) {
                // simple case where there is no wraparound
                read_len = MIN(cbuf->head - cbuf->tail, buflen - pos);
            } else {
                // read to the end of buffer in this pass
                read_len = MIN(valpow2(cbuf->len_pow2) - cbuf->tail, buflen - pos);
            }

            // Only perform the copy if a buf was supplied
            if (NULL != buf) {
                memcpy(buf + pos, cbuf->buf + cbuf->tail, read_len);
            }

            cbuf->tail = INC_POINTER(cbuf, cbuf->tail, read_len);
            pos += read_len;
        }

        if (cbuf->tail == cbuf->head) {
            DEBUG_ASSERT(pos > 0);
            // we've emptied the buffer, unsignal the event
            event_unsignal(&cbuf->event);
        }

        ret = pos;
    }

    spin_unlock_irqrestore(&cbuf->lock, state);

    // we apparently blocked but raced with another thread and found no data, retry
    if (block && ret == 0)
        goto retry;

    return ret;
}

size_t cbuf_peek(cbuf_t *cbuf, iovec_t *regions)
{
    spin_lock_saved_state_t state;

    size_t ret;
    size_t sz;
    DEBUG_ASSERT(cbuf && regions);

    spin_lock_irqsave(&cbuf->lock, state);

    ret = cbuf_space_used(cbuf);
    sz  = cbuf_size(cbuf);

    DEBUG_ASSERT(cbuf->tail < sz);
    DEBUG_ASSERT(ret <= sz);

    regions[0].iov_base = ret ? (cbuf->buf + cbuf->tail) : NULL;
    if (ret + cbuf->tail > sz) {
        regions[0].iov_len  = sz - cbuf->tail;
        regions[1].iov_base = cbuf->buf;
        regions[1].iov_len  = ret - regions[0].iov_len;
    } else {
        regions[0].iov_len  = ret;
        regions[1].iov_base = NULL;
        regions[1].iov_len  = 0;
    }

    spin_unlock_irqrestore(&cbuf->lock, state);
    return ret;
}

#if 0
size_t cbuf_write_char(cbuf_t *cbuf, char c, bool canreschedule)
{
    spin_lock_saved_state_t state;
    DEBUG_ASSERT(cbuf);

    spin_lock_irqsave(&cbuf->lock, state);

    size_t ret = 0;
    if (cbuf_space_avail(cbuf) > 0) {
        cbuf->buf[cbuf->head] = c;

        cbuf->head = INC_POINTER(cbuf, cbuf->head, 1);
        ret = 1;

        if (cbuf->head != cbuf->tail)
            event_signal(&cbuf->event, canreschedule);
    }

    spin_unlock_irqrestore(&cbuf->lock, state);

    return ret;
}

size_t cbuf_read_char(cbuf_t *cbuf, char *c, bool block)
{
    spin_lock_saved_state_t state;
    DEBUG_ASSERT(cbuf);
    DEBUG_ASSERT(c);

retry:
    if (block)
        event_wait(&cbuf->event);

    spin_lock_irqsave(&cbuf->lock, state);

    // see if there's data available
    size_t ret = 0;
    if (cbuf->tail != cbuf->head) {

        *c = cbuf->buf[cbuf->tail];
        cbuf->tail = INC_POINTER(cbuf, cbuf->tail, 1);

        if (cbuf->tail == cbuf->head) {
            // we've emptied the buffer, unsignal the event
            event_unsignal(&cbuf->event);
        }

        ret = 1;
    }

    spin_unlock_irqrestore(&cbuf->lock, state);

    if (block && ret == 0)
        goto retry;

    return ret;
}

#endif
