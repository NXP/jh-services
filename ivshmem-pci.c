/*
 * Copyright 2018, 2020 NXP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifdef IVSHM_V2
#include <linux/ivshmem.h>

#define IVSHM_VID PCI_VENDOR_ID_SIEMENS
#define IVSHM_PID PCI_DEVICE_ID_IVSHMEM

#else

#define IVSHM_VID 0x1af4
#define IVSHM_PID 0x1110
#endif

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/virtio_ring.h>

#include "ivshm.h"
#include "ivshmem-pipe.h"

#define JAILHOUSE_CFG_SHMEM_PTR 0x40
#define JAILHOUSE_CFG_SHMEM_SZ  0x48
#define DRV_NAME "ivshmem"

#ifdef IVSHM_PING_PONG_TEST
static int limit = 100;
static inline void ivshm_send_irq(struct ivshm_info *info)
{
    iowrite32(1, info->io + IVSHM_REG_DBELL);
}

static irqreturn_t ivshm_handler(int irq, void *arg)
{
    struct ivshm_info *ivshm_info = arg;
    u32 val;
    BUG_ON(ivshm_info == NULL);
#if 0
    if (ivshm_info->dev->msix_enabled)
        return IRQ_HANDLED;
#endif
    val = readl(ivshm_info->shm);
    pr_info("IVSHMEM: %d: read %x\n", limit, val);
    writel(0xBAD0DAD0, ivshm_info->shm);

    if (limit-- > 0)
        ivshm_send_irq(ivshm_info);

    return IRQ_HANDLED;
}
#endif

static u64 get_config_qword(struct pci_dev *pdev, unsigned int pos)
{
    u32 lo, hi;

    pci_read_config_dword(pdev, pos, &lo);
    pci_read_config_dword(pdev, pos + 4, &hi);
    return lo | ((u64)hi << 32);
}

static int ivshm_pci_probe(struct pci_dev *pdev,
                    const struct pci_device_id *pci_id)
{
    int i;
    struct ivshm_info *ivshm_info;
    void __iomem *regs;
    resource_size_t state_section_sz, rw_section_sz, output_section_sz;
    phys_addr_t state_section_addr, rw_section_addr, output_section_addr;
    char *device_name;
#ifdef IVSHM_V2
    int vendor_cap;
    u32 id, cap_pos, dword;
#endif
    void *shm, *state_table;
    int ret;

//    printk("\n");
//    dev_info(&pdev->dev, ">>> ivshm_pci_probe()\n");
    ivshm_info = devm_kzalloc(&pdev->dev, sizeof(struct ivshm_info), GFP_KERNEL);
    if (!ivshm_info) {
        return -ENOMEM;
    }

    ret = pcim_enable_device(pdev);
    if (ret) {
        dev_err(&pdev->dev, "pci_enable_device: %d\n", ret);
        return ret;
    }

    ret = pcim_iomap_regions(pdev, BIT(0), DRV_NAME);
    if (ret) {
        dev_err(&pdev->dev, "pcim_iomap_regions: %d\n", ret);
        return ret;
    }

    regs = pcim_iomap_table(pdev)[0];
//    for (i = 0; i < 3; i++)
//        printk(">>> pcim_iomap_table[%d] = %p - %p\n", i, pcim_iomap_table(pdev)[i], virt_to_phys(pcim_iomap_table(pdev)[i]));

#ifndef IVSHM_V2
    ivshm_info->revision = 1;
    rw_section_sz = pci_resource_len(pdev, 2);
    if (rw_section_sz) {
        rw_section_addr = pci_resource_start(pdev, 2);
    } else {
        rw_section_addr = get_config_qword(pdev, JAILHOUSE_CFG_SHMEM_PTR);
        rw_section_sz = get_config_qword(pdev, JAILHOUSE_CFG_SHMEM_SZ);
    }
    state_section_addr = 0;
    state_section_sz = 0;
    output_section_sz = 0;
    state_table = NULL;
#else
    ivshm_info->revision = 2;
    id = readl(regs + IVSHM_V2_REG_ID);
    if (id > 1) {
        dev_err(&pdev->dev, "invalid ID %d\n", id);
        return -EINVAL;
    }
    if (readl(regs + IVSHM_V2_REG_MAX_PEERS) > 2) {
        dev_err(&pdev->dev, "only 2 peers supported\n");
        return -EINVAL;
    }

    vendor_cap = pci_find_capability(pdev, PCI_CAP_ID_VNDR);
    if (vendor_cap < 0) {
        dev_err(&pdev->dev, "missing vendor capability\n");
        return -EINVAL;
    }

    if (pci_resource_len(pdev, 2) > 0) {
        state_section_addr = pci_resource_start(pdev, 2);
    } else {
        cap_pos = vendor_cap + IVSHM_CFG_ADDRESS;
        state_section_addr = get_config_qword(pdev, cap_pos);
    }

    /* Get sections sizes */
    cap_pos = vendor_cap + IVSHM_CFG_STATE_TAB_SZ;
    pci_read_config_dword(pdev, cap_pos, &dword);
    state_section_sz = dword;
    if (state_section_sz == 0) {
        dev_err(&pdev->dev, "States table section is missing !\n");
        return -EINVAL;
    }

    cap_pos = vendor_cap + IVSHM_CFG_RW_SECTION_SZ;
    rw_section_sz = get_config_qword(pdev, cap_pos);
    if (rw_section_sz == 0) {
        dev_err(&pdev->dev, "RW section is missing !\n");
        return -EINVAL;
    }

    cap_pos = vendor_cap + IVSHM_CFG_OUTPUT_SECTION_SZ;
    output_section_sz = get_config_qword(pdev, cap_pos);
    if (rw_section_sz != 0) {
        dev_err(&pdev->dev, "Output section is defined, "
                            "but currently not used by this version!\n");
    }

//    dev_info(&pdev->dev, ">>> trying to request state region %p, size 0x%x\n", state_section_addr, state_section_sz);
    /* state table */
    if (!devm_request_mem_region(&pdev->dev,
                            state_section_addr,
                            state_section_sz,
                            DRV_NAME))
        return -EBUSY;

    state_table = devm_memremap(&pdev->dev,
                            state_section_addr,
                            state_section_sz,
                            MEMREMAP_WB);
    if (!state_table)
        return -ENOMEM;

    rw_section_addr = state_section_addr + state_section_sz;
#endif

//    dev_info(&pdev->dev, ">>> trying to request R/W region %p, size 0x%x\n", rw_section_addr, rw_section_sz);
    /* RW section */
    if (!devm_request_mem_region(&pdev->dev,
                            rw_section_addr,
                            rw_section_sz,
                            DRV_NAME))
        return -EBUSY;

    shm = devm_memremap(&pdev->dev,
                        rw_section_addr,
                        rw_section_sz,
                        MEMREMAP_WB);
    if (!shm)
        return -ENOMEM;

    /* TODO: Output section */
    output_section_addr = rw_section_addr + rw_section_sz;

    device_name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "%s[%s]", DRV_NAME,
                     dev_name(&pdev->dev));
    if (!device_name)
        return -ENOMEM;


    ivshm_info->device_name = device_name;

    ivshm_info->resource[0] = pdev->resource[0];
    ivshm_info->resource[0].name = "register";
    ivshm_info->io = regs;

    ivshm_info->resource[1].name = "shm";
    ivshm_info->resource[1].start = rw_section_addr;
    ivshm_info->resource[1].end = rw_section_addr
                                    + rw_section_sz - 1;
    ivshm_info->resource[1].flags = IORESOURCE_MEM;

    ivshm_info->shm = shm;
    ivshm_info->shmlen = rw_section_sz;

    for (i = 0; i < ARRAY_SIZE(ivshm_info->resource); i++) {
        dev_info(&pdev->dev, "name:%s base: 0x%llx size: 0x%llx\n",
            ivshm_info->resource[i].name,
            ivshm_info->resource[i].start,
            resource_size(&ivshm_info->resource[i]));
    }

    if (1 > pci_alloc_irq_vectors(pdev, 1, 1,
                      PCI_IRQ_LEGACY | PCI_IRQ_MSIX))
        return -EINVAL;

    ivshm_info->pdev = pdev;
    ivshm_info->irq = pci_irq_vector(pdev, 0);
    ivshm_info->state_table = state_table;

#ifdef IVSHM_V2
    pci_write_config_byte(pdev, vendor_cap + IVSHM_CFG_PRIV_CNTL, 0);
#endif
    pci_set_master(pdev);
    pci_set_drvdata(pdev, ivshm_info);

#if 0
    if (!dev->msix_enabled)
        writel(0xffffffff, ivshm_info->io + IntrMask);
#endif

    if (ivshm_pipe_init(ivshm_info)) {
       dev_err(&pdev->dev, "Error while creating pipe thread\n");
       goto err_ivshm_pipe_init;
    }

//    dev_info(&pdev->dev, ">>> ivshm_pci_probe(): END\n\n");
    return 0;

err_ivshm_pipe_init:
    pci_free_irq_vectors(pdev);
    return -ENODEV;
}

static void ivshm_pci_remove(struct pci_dev *dev)
{
    struct ivshm_info *info = pci_get_drvdata(dev);

    ivshm_pipe_remove(info);

    pci_set_drvdata(dev, NULL);
    pci_free_irq_vectors(dev);
}

static struct pci_device_id ivshm_pci_ids[] = {
    {
        PCI_DEVICE(IVSHM_VID, IVSHM_PID),
        .subvendor =    PCI_ANY_ID,
        .subdevice =    PCI_ANY_ID,
    },
    { 0, }
};

static struct pci_driver ivshm_pci_driver = {
    .name = "ivshm",
    .id_table = ivshm_pci_ids,
    .probe = ivshm_pci_probe,
    .remove = ivshm_pci_remove,
};

module_pci_driver(ivshm_pci_driver);
MODULE_DEVICE_TABLE(pci, ivshm_pci_ids);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Xavier Roumegue");
