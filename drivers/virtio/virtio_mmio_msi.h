/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H
#define _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H

#ifdef CONFIG_VIRTIO_MMIO_MSI

#include <linux/msi.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/platform_device.h>

static irq_hw_number_t mmio_msi_hwirq;
static struct irq_domain *mmio_msi_domain;

struct irq_domain *__weak arch_msi_root_irq_domain(void)
{
	return NULL;
}

void __weak irq_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
}

static void mmio_msi_mask_irq(struct irq_data *data)
{
}

static void mmio_msi_unmask_irq(struct irq_data *data)
{
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
#else
static inline void mmio_msi_create_irq_domain(void) {}
#endif

#endif
