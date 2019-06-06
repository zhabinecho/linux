/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DRIVERS_VIRTIO_VIRTIO_MMIO_COMMON_H
#define _DRIVERS_VIRTIO_VIRTIO_MMIO_COMMON_H

#include <linux/acpi.h>
#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_mmio.h>
#include <linux/virtio_ring.h>

#define to_virtio_mmio_device(_plat_dev) \
	container_of(_plat_dev, struct virtio_mmio_device, vdev)

struct virtio_mmio_device {
	struct virtio_device vdev;
	struct platform_device *pdev;

	void __iomem *base;
	unsigned long version;

	/* a list of queues so we can dispatch IRQs */
	spinlock_t lock;
	struct list_head virtqueues;

	unsigned short notify_base;
	unsigned short notify_multiplier;

	bool dyn_mapping;
	bool per_vq_vectors;
	bool msi_enabled;
	/* Name strings for interrupts. */
	char (*vm_vq_names)[256];
	/* Vectors allocateed, for msi per-vq vectors */
	unsigned int msi_used_vectors;
};

#endif
