/*
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

#ifndef __IVSHMEM_RPMSG_H
#define __IVSHMEM_RPMSG_H

#include <linux/rpmsg.h>
#include "ivshmem-iovec.h"
#include "ivshmem-endpoint.h"

#define MIN(x,y) ((x) < (y) ? x : y)
#define MAX(x,y) ((x) > (y) ? x : y)


/* RPMSG device need to adds its own pkt header to rpmsg message payload */
#define IVSHMEM_PKT_HDR				BIT(0)
#define IVSHMEM_ENDPOINT_FLAGS_MASK		(BIT(16) - 1)

struct ivshm_rpmsg_endpoint {
	struct rpmsg_endpoint rpmsg_ept;
	struct ivshm_endpoint *ivshm_ept;
	struct device *dev;
	unsigned long flags;
	int magic;
	int cmd;
	int pad;
	struct mutex cmd_lock;
	spinlock_t pkt_lock;
	struct list_head pkt_list;
	unsigned size;
};

#define to_ivshm_rpmsg_endpoint(d) \
	container_of(d, struct ivshm_rpmsg_endpoint, rpmsg_ept)

/**
 ** @struct ivshm_ept_param
 **    This struct is usefull during ivshm endpoint creation, to pass usefull
 **    information to ivshm low level drivers
 **/
struct ivshm_ept_param {
    /**
     * @brief Unique ID associated to the endpoint
     */
    unsigned id;
    /**
     * @brief Buffer allocated to the endpoint, for data exchange through shared
     * memory
     */
    uint64_t bufsize;
    /**
     * @brief Flags to handle different behaviors between endpoints
     */
    unsigned long flags;
    /**
     * @brief Private data to be stored in rpdev priv->field
     */
    void *priv;
};

/* This struct is used to transmit further paramaters in shared mem packet
 * header when the IVSHMEM_PKT_HDR flag is active */
struct ivshm_imx8_priv_hdr {
    unsigned private[IVSHM_HDR_CUST_PARAMS_MAX];
    int cmd;
    void *data;
};

struct rpmsg_cbuf {
    char *buf;
    uint64_t size;
    uint64_t avail;
    uint64_t head;
    uint64_t tail;
    spinlock_t lock;
};

static unsigned inline rpmsg_cbuf_get_buffer(
       struct rpmsg_cbuf *cbuf, iovec_t *vec)
{
    vec[0].iov_base = cbuf->buf + cbuf->tail;
    if (cbuf->avail == 0)
        return 0;

    if (cbuf->head > cbuf->tail) {
        /* single run of data, between tail and head */
        vec[0].iov_len = cbuf->head - cbuf->tail;
        return 1;
    } else if (cbuf->head == cbuf->tail) {
        vec[0].iov_len = cbuf->size - cbuf->tail;

        if (cbuf->head == 0)
            return 1;

        vec[1].iov_base = cbuf->buf;
        vec[1].iov_len = cbuf->head;
        return 2;
    } else {
        vec[0].iov_len = cbuf->size - cbuf->tail;

        if (cbuf->head > 0) {
            /* two segments */
            vec[1].iov_base = cbuf->buf;
            vec[1].iov_len = cbuf->head;
            return 2;
        } else {
            return 1;
        }
    }

    return 0;
}

static ssize_t inline rpmsg_cbuf_read(
        struct rpmsg_cbuf *cbuf, char *buf, size_t len)
{
    unsigned count, i;
    iovec_t vec[2];
    size_t chars_read = 0;

    spin_lock(&cbuf->lock);

    count = rpmsg_cbuf_get_buffer(cbuf, vec);
    if (count ==  0) {
        spin_unlock(&cbuf->lock);
        return 0;
    }

    for (i = 0; i < count; i++) {
        size_t sz = MIN(len, vec[i].iov_len);

        if (buf) {
            memcpy(buf, vec[i].iov_base, sz);
            buf += sz;
        }

        chars_read += sz;
        len -= sz;
    }

    cbuf->tail = (cbuf->tail + chars_read) % cbuf->size;
    cbuf->avail -= chars_read;
    spin_unlock(&cbuf->lock);

    return chars_read;
}

static ssize_t inline rpmsg_cbuf_write(
        struct rpmsg_cbuf *cbuf, char *buf, size_t len)
{
    unsigned newhead, newtail;
    size_t remaining = len;

    spin_lock(&cbuf->lock);

    while (remaining) {
        bool overlap = false;
        size_t sz;

        sz = MIN(cbuf->size - cbuf->head, remaining);

        memcpy(cbuf->buf + cbuf->head, buf, sz);
        buf += sz;
        remaining -= sz;

        newhead = cbuf->head + sz;

        if (newhead >= cbuf->size) {
            newhead -= cbuf->size;
            overlap = true;
        }

        if ((cbuf->head < cbuf->tail && (newhead >= cbuf->tail || overlap))
                || (cbuf->head > cbuf->tail && newhead >= cbuf->tail && overlap)) {
            newtail = newhead;
            if (newtail >= cbuf->size)
                newtail -= cbuf->size;
            cbuf->tail = newtail;
        }
        cbuf->head = newhead;
    }
    cbuf->avail += len;
    spin_unlock(&cbuf->lock);

    return len;
}

static size_t inline rpmsg_cbuf_space_avail(struct rpmsg_cbuf *cbuf)
{
    size_t space;

    spin_lock(&cbuf->lock);
    space = cbuf->size - cbuf->avail;
    spin_unlock(&cbuf->lock);

    return space;
}
#endif
