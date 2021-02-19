/*
 * Copyright 2019-2021 NXP
 *
 * the code contained herein is licensed under the gnu general public
 * license. you may obtain a copy of the gnu general public license
 * version 2 or later at the following locations:
 *
 * http://www.opensource.org/licenses/gpl-license.html
 * http://www.gnu.org/copyleft/gpl.html
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/rpmsg.h>
#include <linux/of.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/list.h>

#include "ivshmem-rpmsg.h"
#include "ivshmem-iovec.h"

#include "rpmsg-rpc.h"


//#define EN_DUMP_BUFFER

#define RPMSG_RPC_REPLY_BUFSIZE         512

struct rpmsg_rpc_dev {
    struct list_head list;
    unsigned endpoint_id;
    struct rpmsg_device *rpdev;
    struct rpmsg_endpoint *ept;
    char *server_buf;
    char *client_buf;
    spinlock_t server_lock;
    spinlock_t client_lock;
    struct mutex mutex;
    struct rpc_client_callback **callbacks;
    wait_queue_head_t wait;
    bool reply_rdy;
    unsigned tid;
    void *cookie;
};

static LIST_HEAD(rpmsg_rpc_list);
static DEFINE_SPINLOCK(rpmsg_rpc_lock);

/* API */
int rpmsg_rpc_call(struct rpmsg_rpc_dev *rpcdev, unsigned rpc_id,
                       void *in, size_t len, void *out, size_t *out_len)
{
    struct ivshm_rpc_header *hdr;
    int ret = 0;

    pr_debug("--> %s\n", __func__);

    if (len > RPMSG_RPC_REPLY_BUFSIZE)
        return -EPERM;

    if (!rpcdev || !rpcdev->ept)
        return -EINVAL;

    mutex_lock(&rpcdev->mutex);
    hdr = (struct ivshm_rpc_header *)rpcdev->client_buf;
    hdr->id = rpc_id;
    hdr->type = IVSHM_RPC_CALL;
    hdr->len = len;

    memcpy(hdr->payload, in, len);
    rpcdev->reply_rdy = false;;
    smp_wmb();

    ret = rpmsg_send(rpcdev->ept, hdr, sizeof(struct ivshm_rpc_header) + len);

    if (IVSHM_RPC_GET_SZ_OUT(rpc_id) == 0) {
        /* No response expected */
        ret = 0;
        goto out;
    }

    /* Wait for RPC response */
    ret = wait_event_timeout(rpcdev->wait, rpcdev->reply_rdy, msecs_to_jiffies(200));

    if (ret == 0) {
        pr_err("timeout\n");
        ret = -EIO;
        goto out;
    }

#ifdef EN_DUMP_BUFFER
    print_hex_dump(KERN_INFO, "response : ", DUMP_PREFIX_ADDRESS, 16, 1, hdr,
                           sizeof(struct ivshm_rpc_header) + hdr->len, true);
#endif

    /* hdr still point to client buffer, which contains response */
    BUG_ON(hdr->id != rpc_id);

    if (out)
        memcpy(out, hdr->payload, hdr->len);

    if (out_len)
        *out_len = hdr->len;

    ret = 0;

out:
    mutex_unlock(&rpcdev->mutex);

    return ret;
}
EXPORT_SYMBOL(rpmsg_rpc_call);

int rpmsg_rpc_reply(struct rpmsg_rpc_dev *rpcdev,
                        struct rpc_client_callback *cb, void *data, size_t len)
{
    struct ivshm_rpc_header *hdr;
    int ret;

    pr_debug("--> %s", __func__);

    if (len > RPMSG_RPC_REPLY_BUFSIZE)
        return -EPERM;

    spin_lock(&rpcdev->server_lock);

    /* Setup response buffer */
    hdr = (struct ivshm_rpc_header *)rpcdev->server_buf;
    hdr->id = cb->id;
    hdr->type = IVSHM_RPC_REPLY;
    hdr->len = len;
    hdr->tid = rpcdev->tid;
    memcpy(hdr->payload, data, len);

#ifdef EN_DUMP_BUFFER
    print_hex_dump(KERN_INFO, "reply message: ", DUMP_PREFIX_ADDRESS,
                           16, 1, hdr, sizeof(struct ivshm_rpc_header) + len, true);
#endif

    /* Send response */
    /* FIXME Can this be done inside spinlock ?!?!?! probably not
     Need to be queued */
    ret = rpmsg_send(rpcdev->ept, hdr, sizeof(struct ivshm_rpc_header) + len);

    spin_unlock(&rpcdev->server_lock);

    return ret;
}
EXPORT_SYMBOL(rpmsg_rpc_reply);

static LIST_HEAD(rpmsg_rpc_services_list);
struct rpmsg_rpc_id_cb_s {
    struct list_head list;
    unsigned id;
    struct rpc_client_callback **cb;
    void *cookie;
};

static void rpmsg_rpc_register_server(struct rpmsg_rpc_dev *rpcdev)
{

    struct rpmsg_rpc_id_cb_s *id_cb;
    spin_lock(&rpmsg_rpc_lock);
    list_for_each_entry(id_cb, &rpmsg_rpc_services_list, list) {
        if (id_cb->id == rpcdev->endpoint_id) {
            rpcdev->callbacks = id_cb->cb;
            rpcdev->cookie = id_cb->cookie;
        }
    }
    list_add(&rpcdev->list, &rpmsg_rpc_list);
    spin_unlock(&rpmsg_rpc_lock);
}

struct rpmsg_rpc_dev *rpmsg_rpc_register_client(unsigned id,
                                                struct rpc_client_callback **cb,
                                                void *cookie)
{
    struct rpmsg_rpc_dev *rpcdev;

    struct rpmsg_rpc_id_cb_s *id_cb =
                        kmalloc(sizeof(struct rpmsg_rpc_id_cb_s), GFP_KERNEL);

    BUG_ON(!cb);

    if (!id_cb)
        return ERR_PTR(-ENOMEM);

    id_cb->cb = cb;
    id_cb->id = id;
    id_cb->cookie = cookie;
    spin_lock(&rpmsg_rpc_lock);
    list_add(&id_cb->list, &rpmsg_rpc_services_list);

    list_for_each_entry(rpcdev, &rpmsg_rpc_list, list) {
        if (id == rpcdev->endpoint_id) {
            rpcdev->callbacks = cb;
            rpcdev->cookie = cookie;
            goto exit;
        }
    }

    rpcdev = NULL;
exit:
    spin_unlock(&rpmsg_rpc_lock);
    return rpcdev;
}
EXPORT_SYMBOL(rpmsg_rpc_register_client);

void rpmsg_rpc_unregister_client(unsigned id)
{

    struct rpmsg_rpc_dev *rpcdev;
    struct rpmsg_rpc_id_cb_s *id_cb;
    struct rpmsg_rpc_id_cb_s *id_cb_tmp;
    spin_lock(&rpmsg_rpc_lock);
    list_for_each_entry_safe(id_cb, id_cb_tmp, &rpmsg_rpc_services_list, list) {
        if (id_cb->id == id) {
            list_del(&id_cb->list);
            kfree(id_cb);
        }
    }

    list_for_each_entry(rpcdev, &rpmsg_rpc_list, list) {
        if (id == rpcdev->endpoint_id) {
            rpcdev->callbacks = NULL;
            rpcdev->cookie = NULL;
        }
    }

    spin_unlock(&rpmsg_rpc_lock);
}
EXPORT_SYMBOL(rpmsg_rpc_unregister_client);

void *rpmsg_rpc_get_cookie(struct rpmsg_rpc_dev *rpcdev)
{
    BUG_ON(!rpcdev);

    return rpcdev->cookie;
}
EXPORT_SYMBOL(rpmsg_rpc_get_cookie);

bool is_rpmsg_rpc_ready(unsigned id)
{
    struct rpmsg_rpc_dev *rpcdev;

    list_for_each_entry(rpcdev, &rpmsg_rpc_list, list) {
        if (id == rpcdev->endpoint_id)
            return true;
    }
    return false;
}
EXPORT_SYMBOL(is_rpmsg_rpc_ready);

/* RPMSG functions */
static int rpmsg_rpc_cb(struct rpmsg_device *rpdev, void *data, int len,
                            void *priv, u32 src)
{
    struct rpmsg_rpc_dev *rpcdev = dev_get_drvdata(&rpdev->dev);
    struct rpc_client_callback *rpc_callback;
    struct ivshm_rpc_header *hdr;
    int ret;

    pr_debug("--> %s\n", __func__);

#ifdef EN_DUMP_BUFFER
    print_hex_dump(KERN_INFO, "receiving message: ", DUMP_PREFIX_ADDRESS,
                           16, 1, data, len, true);
#endif

    if (!rpcdev->callbacks) {
        pr_err("No callbacks available\n");
        return 0;
    }

    hdr = (struct ivshm_rpc_header *)data;
    if (hdr->type == IVSHM_RPC_CALL) {
        int i = 0;

        while ((rpc_callback = *(rpcdev->callbacks + i)) != NULL) {
            if (rpc_callback->id == hdr->id)
                break;

            i++;
        }

        if (rpc_callback == NULL) {
             pr_err("No client callback available\n");
             return 0;
        }

        /* Store current transaction id */
        rpcdev->tid = hdr->tid;

        ret = rpc_callback->fn(rpcdev, rpc_callback, hdr->payload);
        if (ret < 0)
            pr_err("%s rpc_callback %d error %d\n", __func__, hdr->id, ret);
        return len;

    } else if (hdr->type == IVSHM_RPC_REPLY) {
        /* Store message in client buffer and wake-up client */
        memcpy(rpcdev->client_buf, data, len);

        rpcdev->reply_rdy = true;
        wake_up(&rpcdev->wait);

        return len;
    }

    pr_info("Unknown ID %X\n", hdr->id);

    return 0;
}

static int rpmsg_rpc_probe(struct rpmsg_device *rpdev)
{
    struct rpmsg_channel_info chinfo = {
        .src = rpdev->src,
        .dst = RPMSG_ADDR_ANY
    };
    struct device_node *np = rpdev->dev.of_node;
    struct ivshm_ept_param ept_param = { 0 };
    struct rpmsg_rpc_dev *rpcdev;
    unsigned id, val;
    int ret;

    /* Retrieve information from device tree */
    ret = of_property_read_u32(np, "id", &id);
    if (ret)
        id = 0;
    ept_param.id = id;

    ret = of_property_read_u32(np, "size", &val);
    if (!ret)
        ept_param.bufsize = (size_t)val;

    dev_dbg(&rpdev->dev, "chnl: 0x%x -> 0x%x : id %d : bufsize %llu\n", rpdev->src,
             rpdev->dst, ept_param.id, ept_param.bufsize);

    /* Create endpoint */
    rpdev->ept = rpmsg_create_ept(rpdev, rpmsg_rpc_cb, &ept_param, chinfo);

    if (IS_ERR(rpdev->ept)) {
        ret = PTR_ERR(rpdev->ept);
    }

    rpcdev = kzalloc(sizeof(*rpcdev), GFP_KERNEL);
    if (!rpcdev) {
        ret = -ENOMEM;
        goto free_ept;
    }

    /* Setup continuous Server and Client buffers, to be send exchanged rpmsg framework */
    rpcdev->client_buf = kzalloc(RPMSG_RPC_REPLY_BUFSIZE, GFP_KERNEL);
    if (!rpcdev->client_buf) {
        ret = -ENOMEM;
        goto free_rpcdev;
    }

    rpcdev->server_buf = kzalloc(RPMSG_RPC_REPLY_BUFSIZE, GFP_KERNEL);
    if (!rpcdev->server_buf) {
        ret = -ENOMEM;
        goto free_client_buf;
    }

    spin_lock_init(&rpcdev->server_lock);
    spin_lock_init(&rpcdev->client_lock);
    mutex_init(&rpcdev->mutex);
    rpcdev->ept = rpdev->ept;
    rpcdev->endpoint_id = id;
    rpcdev->rpdev = rpdev;

    init_waitqueue_head(&rpcdev->wait);
    dev_set_drvdata(&rpdev->dev, rpcdev);

    rpmsg_rpc_register_server(rpcdev);

    return ret;

free_client_buf:
    kfree(rpcdev->client_buf);
free_rpcdev:
    kfree(rpcdev);
free_ept:
    rpmsg_destroy_ept(rpdev->ept);

    return ret;
}

static void rpmsg_rpc_remove(struct rpmsg_device *rpdev)
{
    struct rpmsg_rpc_dev *rpcdev = dev_get_drvdata(&rpdev->dev);

    /* Do not destroy endpoint here. This is handled by rpmsg framework as ept
     * is stored into rpdev->ept
     * rpmsg_destroy_ept(rpdev->ept); */

    kfree(rpcdev->server_buf);
    kfree(rpcdev->client_buf);
    kfree(rpcdev);
}

static const struct of_device_id rpmsg_rpc_of_match[] = {
    { .compatible = "fsl,rpmsg-rpc"},
    {}
};
MODULE_DEVICE_TABLE(of, rpmsg_rpc_of_match);

static struct rpmsg_driver rpmsg_rpc_driver = {
    .drv = {
        .name   = KBUILD_MODNAME,
        .owner  = THIS_MODULE,
        .of_match_table = rpmsg_rpc_of_match,
    },
    .probe      = rpmsg_rpc_probe,
    .remove     = rpmsg_rpc_remove,
};
module_rpmsg_driver(rpmsg_rpc_driver);

MODULE_AUTHOR("Antoine Bouyer <antoine.bouyer@nxp.com>");
MODULE_DESCRIPTION("NXP rpmsg device driver for rpc dialog with LK");
MODULE_LICENSE("GPL v2");
