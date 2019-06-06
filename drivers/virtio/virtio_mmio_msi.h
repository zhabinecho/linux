/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H
#define _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H

#include "virtio_mmio_common.h"

#ifdef CONFIG_VIRTIO_MMIO_MSI
#include <linux/msi.h>
#include <linux/irq.h>

static irq_hw_number_t mmio_msi_hwirq;
static struct irq_domain *platform_msi_mmio_domain;
static inline int vm_msi_irq_vector(struct device *dev, unsigned int nr)
{
	struct msi_desc *entry = first_msi_entry(dev);

	return entry->irq + nr;
}

static inline void vm_set_msi_domain(struct virtio_device *vdev)
{
	if (!vdev->dev.msi_domain)
		vdev->dev.msi_domain = platform_msi_mmio_domain;
}

static void __iomem *vm_dev_pos(struct msi_desc *desc)
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
	void __iomem *pos = vm_dev_pos(desc);
	unsigned int offset = data->irq - desc->irq;

	if (pos) {
		u32 op = flag ? VIRTIO_MMIO_MSI_CMD_MASK :
			VIRTIO_MMIO_MSI_CMD_UNMASK;
		writel(offset, pos + VIRTIO_MMIO_VEC_SEL);
		writel(op, pos + VIRTIO_MMIO_MSI_COMMAND);
	}
}

static void platform_msi_mask_irq(struct irq_data *data)
{
	mmio_msi_set_mask_bit(data, 1);
}

static void platform_msi_unmask_irq(struct irq_data *data)
{
	mmio_msi_set_mask_bit(data, 0);
}

static struct irq_chip platform_msi_controller = {
	.name			= "VIRTIO-MMIO-MSI",
	.irq_mask		= platform_msi_mask_irq,
	.irq_unmask		= platform_msi_unmask_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_compose_msi_msg	= irq_msi_compose_msg,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

static int platform_msi_prepare(struct irq_domain *domain, struct device *dev,
				int nvec, msi_alloc_info_t *arg)
{
	memset(arg, 0, sizeof(*arg));
	return 0;
}

static void platform_msi_set_desc(msi_alloc_info_t *arg, struct msi_desc *desc)
{
	mmio_msi_hwirq = platform_msi_calc_hwirq(desc);
}

static irq_hw_number_t platform_msi_get_hwirq(struct msi_domain_info *info,
					      msi_alloc_info_t *arg)
{
	return mmio_msi_hwirq;
}

static struct msi_domain_ops platform_msi_domain_ops = {
	.msi_prepare	= platform_msi_prepare,
	.set_desc	= platform_msi_set_desc,
	.get_hwirq	= platform_msi_get_hwirq,
};

static struct msi_domain_info platform_msi_domain_info = {
	.flags          = MSI_FLAG_USE_DEF_DOM_OPS |
			  MSI_FLAG_USE_DEF_CHIP_OPS |
			  MSI_FLAG_ACTIVATE_EARLY,
	.ops            = &platform_msi_domain_ops,
	.chip           = &platform_msi_controller,
	.handler        = handle_edge_irq,
	.handler_name   = "edge",
};

static inline void vm_create_msi_domain(void)
{
	struct fwnode_handle *fn;
	struct irq_domain *parent = arch_msi_root_irq_domain();

	fn = irq_domain_alloc_named_fwnode("VIRTIO-MMIO-MSI");
	if (fn && parent) {
		platform_msi_mmio_domain =
			platform_msi_create_irq_domain(fn,
				&platform_msi_domain_info, parent);
		irq_domain_free_fwnode(fn);
	}
}

static void mmio_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	void __iomem *pos = vm_dev_pos(desc);

	if (pos) {
		writel(desc->platform.msi_index, pos + VIRTIO_MMIO_VEC_SEL);
		writel(msg->address_lo, pos + VIRTIO_MMIO_MSI_ADDRESS_LOW);
		writel(msg->address_hi, pos + VIRTIO_MMIO_MSI_ADDRESS_HIGH);
		writel(msg->data, pos + VIRTIO_MMIO_MSI_DATA);
		writel(VIRTIO_MMIO_MSI_CMD_CONFIGURE,
				pos + VIRTIO_MMIO_MSI_COMMAND);
	}
}
static inline int vm_msi_domain_alloc_irqs(struct device *dev,
				unsigned int nvec)
{
	return platform_msi_domain_alloc_irqs(dev, nvec,
			mmio_write_msi_msg);
}
static inline void vm_msi_domain_free_irqs(struct device *dev)
{
	return platform_msi_domain_free_irqs(dev);
}
#else
static inline int vm_msi_irq_vector(struct device *dev, unsigned int nr)
{
	return -EINVAL;
}
static inline void vm_create_msi_domain(void) { }
static inline void vm_set_msi_domain(struct virtio_device *vdev) { }
static inline int vm_msi_domain_alloc_irqs(struct device *dev,
				unsigned int nvec)
{
	return -EINVAL;
}
static inline void vm_msi_domain_free_irqs(struct device *dev) { }
#endif

#endif
