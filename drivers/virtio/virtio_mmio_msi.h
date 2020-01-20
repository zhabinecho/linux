/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H
#define _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H

#ifdef CONFIG_VIRTIO_MMIO_MSI

#include <linux/msi.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/platform_device.h>
#include "virtio_mmio_common.h"

static irq_hw_number_t mmio_msi_hwirq;
static struct irq_domain *mmio_msi_domain;

struct irq_domain *__weak arch_msi_root_irq_domain(void)
{
	return NULL;
}

void __weak irq_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
}

static void __iomem *vm_dev_base(struct msi_desc *desc)
{
	if (desc) {
		struct device *dev = desc->dev;
		struct virtio_device *vdev = dev_to_virtio(dev);
		struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

		return vm_dev->base;
	}

	return NULL;
}

static void mmio_msi_set_mask_bit(struct irq_data *data, u32 flag)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	void __iomem *base = vm_dev_base(desc);
	unsigned int offset = data->irq - desc->irq;

	if (base) {
		u32 op = flag ? VIRTIO_MMIO_MSI_CMD_MASK :
			VIRTIO_MMIO_MSI_CMD_UNMASK;
		writel(offset, base + VIRTIO_MMIO_MSI_VEC_SEL);
		writel(op, base + VIRTIO_MMIO_MSI_COMMAND);
	}
}

static void mmio_msi_mask_irq(struct irq_data *data)
{
	mmio_msi_set_mask_bit(data, 1);
}

static void mmio_msi_unmask_irq(struct irq_data *data)
{
	mmio_msi_set_mask_bit(data, 0);
}

static struct irq_chip mmio_msi_controller = {
	.name			= "VIRTIO-MMIO-MSI",
	.irq_mask		= mmio_msi_mask_irq,
	.irq_unmask		= mmio_msi_unmask_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_compose_msi_msg	= irq_msi_compose_msg,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

static int mmio_msi_prepare(struct irq_domain *domain, struct device *dev,
				int nvec, msi_alloc_info_t *arg)
{
	memset(arg, 0, sizeof(*arg));
	return 0;
}

static void mmio_msi_set_desc(msi_alloc_info_t *arg, struct msi_desc *desc)
{
	mmio_msi_hwirq = platform_msi_calc_hwirq(desc);
}

static irq_hw_number_t mmio_msi_get_hwirq(struct msi_domain_info *info,
					      msi_alloc_info_t *arg)
{
	return mmio_msi_hwirq;
}

static struct msi_domain_ops mmio_msi_domain_ops = {
	.msi_prepare	= mmio_msi_prepare,
	.set_desc	= mmio_msi_set_desc,
	.get_hwirq	= mmio_msi_get_hwirq,
};

static struct msi_domain_info mmio_msi_domain_info = {
	.flags          = MSI_FLAG_USE_DEF_DOM_OPS |
			  MSI_FLAG_USE_DEF_CHIP_OPS |
			  MSI_FLAG_ACTIVATE_EARLY,
	.ops            = &mmio_msi_domain_ops,
	.chip           = &mmio_msi_controller,
	.handler        = handle_edge_irq,
	.handler_name   = "edge",
};

static inline void mmio_msi_create_irq_domain(void)
{
	struct fwnode_handle *fn;
	struct irq_domain *parent = arch_msi_root_irq_domain();

	fn = irq_domain_alloc_named_fwnode("VIRTIO-MMIO-MSI");
	if (fn && parent) {
		mmio_msi_domain =
			platform_msi_create_irq_domain(fn,
				&mmio_msi_domain_info, parent);
		irq_domain_free_fwnode(fn);
	}
}

static void mmio_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	void __iomem *base = vm_dev_base(desc);

	if (base) {
		writel(desc->platform.msi_index, base + VIRTIO_MMIO_MSI_VEC_SEL);
		writel(msg->address_lo, base + VIRTIO_MMIO_MSI_ADDRESS_LOW);
		writel(msg->address_hi, base + VIRTIO_MMIO_MSI_ADDRESS_HIGH);
		writel(msg->data, base + VIRTIO_MMIO_MSI_DATA);
		writel(VIRTIO_MMIO_MSI_CMD_CONFIGURE,
			base + VIRTIO_MMIO_MSI_COMMAND);
	}
}

static inline int mmio_msi_domain_alloc_irqs(struct device *dev,
				unsigned int nvec)
{
	return platform_msi_domain_alloc_irqs(dev, nvec,
			mmio_write_msi_msg);
}

static inline void mmio_msi_domain_free_irqs(struct device *dev)
{
	return platform_msi_domain_free_irqs(dev);
}

static inline void mmio_get_msi_domain(struct virtio_device *vdev)
{
	if (!vdev->dev.msi_domain)
		vdev->dev.msi_domain = mmio_msi_domain;
}

static inline int mmio_msi_irq_vector(struct device *dev, unsigned int nr)
{
	struct msi_desc *entry = first_msi_entry(dev);

	return entry->irq + nr;
}

#else
static inline void mmio_msi_create_irq_domain(void) {}
static inline int mmio_msi_irq_vector(struct device *dev, unsigned int nr)
{
	return -EINVAL;
}
static inline void mmio_get_msi_domain(struct virtio_device *vdev) {}
static inline int mmio_msi_domain_alloc_irqs(struct device *dev,
				unsigned int nvec)
{
	return -EINVAL;
}
static inline void mmio_msi_domain_free_irqs(struct device *dev) {}
#endif

#endif
