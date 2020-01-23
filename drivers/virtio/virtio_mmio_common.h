/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DRIVERS_VIRTIO_VIRTIO_MMIO_COMMON_H
#define _DRIVERS_VIRTIO_VIRTIO_MMIO_COMMON_H
/*
 * Virtio MMIO driver - common functionality for all device versions
 *
 * This module allows virtio devices to be used over a memory-mapped device.
 */

#include <linux/platform_device.h>
#include <linux/virtio.h>

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

	/* Name strings for interrupts. This size should be enough. */
	char (*vm_vq_names)[256];

	/* used vectors */
	unsigned int msi_used_vectors;
	bool msi_share;
	bool msi_enabled;
};

#endif
