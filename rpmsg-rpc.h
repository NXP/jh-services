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

#ifndef __RPMSG_RPC_H
#define __RPMSG_RPC_H

#include "ivshmem-rpc.h"


struct rpmsg_rpc_dev;

/* rpmsg RPC API */
int rpmsg_rpc_call(struct rpmsg_rpc_dev *rpcdev, unsigned rpc_id,
                void *in, size_t len, void *out, size_t *out_len);

int rpmsg_rpc_reply(struct rpmsg_rpc_dev *rpcdev,
                struct rpc_client_callback *cb, void *d, size_t len);

struct rpmsg_rpc_dev *rpmsg_rpc_register_client(unsigned id,
                struct rpc_client_callback **cb, void *cookie);
void rpmsg_rpc_unregister_client(unsigned id);
void *rpmsg_rpc_get_cookie(struct rpmsg_rpc_dev *rpcdev);
bool is_rpmsg_rpc_ready(unsigned id);

#endif
