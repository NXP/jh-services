/*
 * Copyright 2018-2020 NXP
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

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/of.h>
#define DEBUG_ASSERT(cond) BUG_ON(!(cond))
/* linux internal header */
#include "rpmsg_internal.h"

#include "ivshmem-rpmsg.h"
#include "ivshmem-pipe.h"
#include "ivshmem-endpoint.h"

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

DEFINE_MUTEX(ivshm_services_lock);
#define _mutex_acquire mutex_lock_interruptible
#define _mutex_release mutex_unlock


struct ivshm_rpmsg_service {
    struct list_head node;
    struct rpmsg_device rpdev;
    const char *name;
    long unsigned flags;
    struct ivshm_info *info;
#ifdef CONFIG_DEBUG_FS
    struct dentry *debug;
#endif
};

static LIST_HEAD(services_list);
static DEFINE_MUTEX(services_list_lock);

#define to_ivshm_rpmsg_service(d) \
    container_of(d, struct ivshm_rpmsg_service, rpdev)

static void __ept_release(struct kref *kref)
{
    struct rpmsg_endpoint *ept = container_of(kref, struct rpmsg_endpoint,
                                              refcount);

    kfree(to_ivshm_rpmsg_endpoint(ept));
}

static void ivshm_rpmsg_destroy_ept(struct rpmsg_endpoint *rpmsg_ept)
{
    struct ivshm_rpmsg_endpoint *ept = to_ivshm_rpmsg_endpoint(rpmsg_ept);

    ivshm_endpoint_destroy(ept->ivshm_ept);
    kref_put(&rpmsg_ept->refcount, __ept_release);
}

static int ivshm_rpmsg_send(struct rpmsg_endpoint *rpmsg_ept, void *data, int len)
{
    struct ivshm_rpmsg_endpoint *ept = to_ivshm_rpmsg_endpoint(rpmsg_ept);
    struct ivshm_endpoint *ivshm_ept = ept->ivshm_ept;
    struct ivshm_ep_buf ep_buf;
    int extra_bytes;
    size_t sent;

    ivshm_ep_buf_init(&ep_buf);

    if (ept->flags & IVSHMEM_PKT_HDR) {
        /* Insert specific header fields before payload */
        struct ivshm_imx8_priv_hdr *priv_hdr = data;
        struct ivshm_imx8_hdr pkt_hdr = { 0 };

        print_hex_dump_debug("sending message:", DUMP_PREFIX_NONE,
                       16, 1, priv_hdr->data, len, true);

        pkt_hdr.magic = ept->magic;
        pkt_hdr.pad = ept->pad;
        pkt_hdr.cmd = priv_hdr->cmd;
        pkt_hdr.len = sizeof(pkt_hdr) + len;
        memcpy(&pkt_hdr.private, priv_hdr->private,
               IVSHM_HDR_CUST_PARAMS_MAX * sizeof(unsigned));

        smp_mb(); /* to force packet header being written as expected */

        ivshm_ep_buf_add(&ep_buf, priv_hdr->data, len);
        ivshm_ep_buf_add(&ep_buf, &pkt_hdr, sizeof(struct ivshm_imx8_hdr));
        extra_bytes = sizeof(struct ivshm_pkt_hdr);
        extra_bytes += sizeof(struct ivshm_imx8_hdr);
    } else {
        print_hex_dump_debug("sending message:", DUMP_PREFIX_NONE,
                       16, 1, data, len, true);

        /* Only send payload */
        ivshm_ep_buf_add(&ep_buf, data, len);
        extra_bytes = sizeof(struct ivshm_pkt_hdr);
    }

    sent = ivshm_endpoint_write(ivshm_ept, &ep_buf) - extra_bytes;

    DEBUG_ASSERT(sent == len);

    return 0;
}

static const struct rpmsg_endpoint_ops ivshm_rpmsg_endpoint_ops = {
    .destroy_ept = ivshm_rpmsg_destroy_ept,
    .send = ivshm_rpmsg_send,
//  .trysend = ivshm_rpmsg_trysend,
//  .poll = ivshm_rpmsg_poll,
};

static ssize_t ivshm_rpmsg_consume(struct ivshm_endpoint *ep, struct ivshm_pkt *pkt)
{
    struct rpmsg_endpoint *rpmsg_ept = *(struct rpmsg_endpoint **)&ep->private;
    struct ivshm_rpmsg_endpoint *ept;

    print_hex_dump_debug("incoming message:", DUMP_PREFIX_NONE,
                         16, 1, pkt, pkt->hdr.len, true);

    DEBUG_ASSERT(rpmsg_ept);
    DEBUG_ASSERT(rpmsg_ept->cb);
    DEBUG_ASSERT(rpmsg_ept->rpdev);

    ept = to_ivshm_rpmsg_endpoint(rpmsg_ept);
    if (ept->flags & IVSHMEM_PKT_HDR) {
        /* Decode intermediate pkt header; Use src field as command parameter */
        struct ivshm_imx8_pkt *imx8_pkt = (struct ivshm_imx8_pkt *)&pkt->payload;
        size_t len = imx8_pkt->hdr.len - sizeof(struct ivshm_imx8_hdr);

        return rpmsg_ept->cb(rpmsg_ept->rpdev, &imx8_pkt->payload, len,
                             rpmsg_ept->priv, imx8_pkt->hdr.cmd);
    }

    return rpmsg_ept->cb(rpmsg_ept->rpdev, &pkt->payload,
                         pkt->hdr.len - sizeof(struct ivshm_pkt),
                         rpmsg_ept->priv, RPMSG_ADDR_ANY);
}

#ifdef CONFIG_DEBUG_FS
static int ivshm_debug_id_get(void *data, u64 *val)
{
    struct ivshm_endpoint *ept = data;

    *val = IVSHM_EP_GET_ID(ept->id);
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(ivshm_debug_id_fops, ivshm_debug_id_get, NULL, "%llu\n");

static int ivshm_debug_prio_get(void *data, u64 *val)
{
    struct ivshm_endpoint *ept = data;

    *val = IVSHM_EP_GET_PRIO(ept->id);
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(ivshm_debug_prio_fops, ivshm_debug_prio_get, NULL, "%llu\n");

static int ivshm_debug_sched_get(void *data, u64 *val)
{
    struct ivshm_endpoint *ept = data;

    *val = IVSHM_EP_GET_SCHED(ept->id);
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(ivshm_debug_sched_fops, ivshm_debug_sched_get, NULL, "%llu\n");
#endif

static struct rpmsg_endpoint *ivshm_rpmsg_create_ept(struct rpmsg_device *rpdev,
                          rpmsg_rx_cb_t cb, void *priv,
                          struct rpmsg_channel_info chinfo)
{
    struct ivshm_rpmsg_service *service = to_ivshm_rpmsg_service(rpdev);
    struct ivshm_rpmsg_endpoint *ept;
    struct rpmsg_endpoint *rpmsg_ept;
    struct ivshm_ept_param *param = priv;
#ifdef CONFIG_DEBUG_FS
    struct dentry *d;
    char name[64];
#endif

    /* priv is mandatory, as we need endpoint id/size information at least */
    if (!priv)
        return NULL;

    ept = kzalloc(sizeof(*ept), GFP_KERNEL);
    if (!ept)
        return NULL;

    /* Fill in endpoint info */
    rpmsg_ept = &ept->rpmsg_ept;

    kref_init(&rpmsg_ept->refcount);

    rpmsg_ept->rpdev = rpdev;
    rpmsg_ept->cb = cb;
    rpmsg_ept->priv = param->priv;
    rpmsg_ept->ops = &ivshm_rpmsg_endpoint_ops;

    /* Create ivshmem endpoint */
    ept->size = (param->bufsize > IVSHM_EP_MIN_BUFSIZE) ?
                        param->bufsize : IVSHM_EP_MIN_BUFSIZE;

    ept->flags = param->flags & IVSHMEM_ENDPOINT_FLAGS_MASK;

    ept->dev = &rpdev->dev;
    mutex_init(&ept->cmd_lock);
    spin_lock_init(&ept->pkt_lock);
    INIT_LIST_HEAD(&ept->pkt_list);

    ept->ivshm_ept = ivshm_endpoint_create_w_private(
                 service->name,
                 param->id,
                 ivshm_rpmsg_consume,
                 service->info,
                 ept->size,
                 sizeof(struct rpmsg_endpoint *),
                 &rpmsg_ept);

    if (IS_ERR(ept->ivshm_ept)) {
        kfree(ept);
        return NULL;
    }

    dev_dbg(&rpdev->dev, "ivshm_ept created %p - rpmsg_ept %p\n",
            ept->ivshm_ept, rpmsg_ept);

#ifdef CONFIG_DEBUG_FS
    snprintf(name, 64, "%d", param->id);
    d = debugfs_create_dir(name, service->debug);
    if (IS_ERR(d))
        goto skip;

    debugfs_create_file("id", S_IRUGO, d, ept->ivshm_ept, &ivshm_debug_id_fops);
    debugfs_create_file("prio", S_IRUGO, d, ept->ivshm_ept, &ivshm_debug_prio_fops);
    debugfs_create_file("sched", S_IRUGO, d, ept->ivshm_ept, &ivshm_debug_sched_fops);
    debugfs_create_u32("size", S_IRUGO, d, &ept->size);
#ifdef IVSHMEM_MONITOR
    debugfs_create_u32("latency_mean", S_IRUGO, d, &ept->ivshm_ept->latency_mean);
    debugfs_create_u32("latency_max", S_IRUGO, d, &ept->ivshm_ept->latency_max);
    debugfs_create_u32("max", S_IRUGO, d, &ept->ivshm_ept->level_max);
    debugfs_create_u32("rx", S_IRUGO, d, &ept->ivshm_ept->num_rx);
    debugfs_create_u32("tx", S_IRUGO, d, &ept->ivshm_ept->num_tx);
#endif

skip:
#endif
    return rpmsg_ept;
}

static const struct rpmsg_device_ops ivshm_rpmsg_device_ops = {
    .create_ept = ivshm_rpmsg_create_ept,
};

static void ivshm_rpmsg_release_device(struct device *dev)
{
    struct rpmsg_device *rpdev = to_rpmsg_device(dev);
    struct ivshm_rpmsg_service *service = to_ivshm_rpmsg_service(rpdev);

#ifdef CONFIG_DEBUG_FS
    debugfs_remove_recursive(service->debug);
#endif

    kfree(service);
}

int ivshm_init_services(struct ivshm_info *info)
{
    struct ivshm_rpmsg_service *service;
    struct device *parent = &info->pdev->dev;
    struct rpmsg_device *rpdev;
    struct device_node *ivshm_rpmsg, *node;
    int ret;

//    printk(">>> ivshm_init_services()\n");
#ifdef CONFIG_DEBUG_FS
    struct dentry *d = debugfs_create_dir("ivshmem", NULL);

    if (IS_ERR(d))
        d = NULL;

    info->debug = d;
#endif

    ivshm_rpmsg = of_find_compatible_node(NULL, NULL, "fsl,ivshm-rpmsg");
    if (!ivshm_rpmsg) {
        dev_err(parent, "fsl,ivshm-rpmsg node not found !\n");
        return -ENODEV;
    }

    /* Retrieve priority config */
    memset(info->prio, 0, IVSHM_SCHED_PRIO_NUM_MAX * sizeof(uint32_t));
    ret = of_property_count_u32_elems(ivshm_rpmsg, "prio");
    BUG_ON(ret > IVSHM_SCHED_PRIO_NUM_MAX);
    if (ret > 0)
        ret = of_property_read_u32_array(ivshm_rpmsg, "prio", info->prio, ret);

    for_each_available_child_of_node(ivshm_rpmsg, node) {
        service = kzalloc(sizeof(*service), GFP_KERNEL);
        if (!service)
            return -ENOMEM;

        service->name = node->name;
        service->info = info;

#ifdef CONFIG_DEBUG_FS
        d = debugfs_create_dir(service->name, info->debug);

        if (IS_ERR(d))
            d = NULL;

        service->debug = d;
#endif

        rpdev = &service->rpdev;
        strncpy(rpdev->id.name, service->name, RPMSG_NAME_SIZE);
        rpdev->id.name[RPMSG_NAME_SIZE - 1] = '\0';
        rpdev->src = RPMSG_ADDR_ANY;
        rpdev->dst = RPMSG_ADDR_ANY;
        rpdev->dev.parent = parent;
        rpdev->dev.of_node = node;
        rpdev->dev.release = ivshm_rpmsg_release_device;

        /* Assign callbacks for rpmsg_device */
        rpdev->ops = &ivshm_rpmsg_device_ops;

        ret = rpmsg_register_device(rpdev);

        if (ret != 0) {
            put_device(&rpdev->dev);
            kfree(service);
            continue;
        }

        mutex_lock(&services_list_lock);
        list_add_tail(&service->node, &services_list);
        mutex_unlock(&services_list_lock);
    }

    return 0;
}

void ivshm_disable_services(struct ivshm_info *info)
{
    struct ivshm_rpmsg_service *service, *service_safe;
    struct rpmsg_channel_info chinfo;
    struct device *parent = &info->pdev->dev;

    mutex_lock(&services_list_lock);
    list_for_each_entry_safe(service, service_safe, &services_list, node) {
        dev_dbg(parent, "Unregister device %s\n", service->name);
        strncpy(chinfo.name, service->name, sizeof(chinfo.name));
        chinfo.name[sizeof(chinfo.name) - 1] = '\0';
        chinfo.src = RPMSG_ADDR_ANY;
        chinfo.dst = RPMSG_ADDR_ANY;

        list_del(&service->node);
        rpmsg_unregister_device(parent, &chinfo);
    }
    mutex_unlock(&services_list_lock);

#ifdef CONFIG_DEBUG_FS
    debugfs_remove(info->debug);
#endif
}

