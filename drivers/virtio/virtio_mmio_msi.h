/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H
#define _DRIVERS_VIRTIO_VIRTIO_MMIO_MSI_H

/*
In cloud native environment, we need a lightweight and secure system. It
should benefit from the speed of containers and the security of VM, which
is classified as secure containers. The traditional solution of cloud VM
is Qemu. In fact we don't need to pay for the legacy devices. Currently,
more userspace VMMs, e.g. Qemu, Firecracker, Cloud Hypervisor and Alibaba
Cloud VMM which is called Dragonball, began to pay attention to a
lightweight solution.

The lightweight VMM is suitable to cloud native infrastructure which is
designed for creating secure sandbox to address the requirements of
multi-tenant. Meanwhile, with faster startup time and lower memory
overhead, it makes possible to launch thousands of microVMs on the same
machine. This VMM minimizes the emulation devices and uses virtio-mmio to
get a more lightweight transport layer. The virtio-mmio devices have less
code than virtio-pci, which can decrease boot time and increase deploy
density by customizing kernel such as setting pci=off. From another point
of view, the minimal device can reduce the attack surface.

We have compared the number of files and the lines of code between
virtio-mmio and virio-pci.

				Virtio-PCI	    Virtio-MMIO	
	number of files(Linux)	    161			1
	lines of code(Linux)	    78237		538
	number of files(Qemu)	    24			1
	lines of code(Qemu)	    8952		421

But the current standard virtio-mmio spec has some limitations which is
only support legacy interrupt and will cause performance penalties.

To address such limitation, we proposed to update virtio-mmio spec with
two new feature bits to support MSI interrupt and enhancing notification
mechanism[1], which can achieve the same performance as virtio-pci devices
with only around 600 lines of code.

Here are the performance gain of MSI interrupt in virtio-mmio. Each case is
repeated three times.

        netperf -t TCP_RR -H 192.168.1.36 -l 30 -- -r 32,1024

                Virtio-PCI    Virtio-MMIO   Virtio-MMIO(MSI)
        trans/s     9536        6939            9500
        trans/s     9734        7029            9749
        trans/s     9894        7095            9318

With the virtio spec proposal[1], other VMMs (e.g. Qemu) can also make use
of the new features to get a enhancing performance.

[1] https://lkml.org/lkml/2020/1/21/31

Change Log:
v1->v2
* Change version update to feature bit
* Add mask/unmask support
* Add two MSI sharing/non-sharing modes
* Create generic irq domain for all architectures
*/

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
		writel(desc->platform.msi_index, base +
				VIRTIO_MMIO_MSI_VEC_SEL);
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
