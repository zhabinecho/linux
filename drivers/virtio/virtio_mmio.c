// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Virtio memory mapped device driver
 *
 * Copyright 2011-2014, ARM Ltd.
 *
 * This module allows virtio devices to be used over a virtual, memory mapped
 * platform device.
 *
 * The guest device(s) may be instantiated in one of three equivalent ways:
 *
 * 1. Static platform device in board's code, eg.:
 *
 *	static struct platform_device v2m_virtio_device = {
 *		.name = "virtio-mmio",
 *		.id = -1,
 *		.num_resources = 2,
 *		.resource = (struct resource []) {
 *			{
 *				.start = 0x1001e000,
 *				.end = 0x1001e0ff,
 *				.flags = IORESOURCE_MEM,
 *			}, {
 *				.start = 42 + 32,
 *				.end = 42 + 32,
 *				.flags = IORESOURCE_IRQ,
 *			},
 *		}
 *	};
 *
 * 2. Device Tree node, eg.:
 *
 *		virtio_block@1e000 {
 *			compatible = "virtio,mmio";
 *			reg = <0x1e000 0x100>;
 *			interrupts = <42>;
 *		}
 *
 * 3. Kernel module (or command line) parameter. Can be used more than once -
 *    one device will be created for each one. Syntax:
 *
 *		[virtio_mmio.]device=<size>@<baseaddr>:<irq>[:<id>]
 *    where:
 *		<size>     := size (can use standard suffixes like K, M or G)
 *		<baseaddr> := physical base address
 *		<irq>      := interrupt number (as passed to request_irq())
 *		<id>       := (optional) platform device id
 *    eg.:
 *		virtio_mmio.device=0x100@0x100b0000:48 \
 *				virtio_mmio.device=1K@0x1001e000:74
 *
 * Based on Virtio PCI driver by Anthony Liguori, copyright IBM Corp. 2007
 */

#define pr_fmt(fmt) "virtio-mmio: " fmt

#include "virtio_mmio_common.h"
#include "virtio_mmio_msi.h"

/* The alignment to use between consumer and producer parts of vring.
 * Currently hardcoded to the page size. */
#define VIRTIO_MMIO_VRING_ALIGN		PAGE_SIZE


struct virtio_mmio_vq_info {
	/* the actual virtqueue */
	struct virtqueue *vq;

	/* the list node for the virtqueues list */
	struct list_head node;

	/* Notify Address*/
	unsigned int notify_addr;

	/* MSI vector (or none) */
	unsigned int msi_vector;
};

static void vm_free_msi_irqs(struct virtio_device *vdev);
static int vm_request_msi_vectors(struct virtio_device *vdev, int nirqs);

/* Configuration interface */

static u64 vm_get_features(struct virtio_device *vdev)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	u64 features;

	writel(1, vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES_SEL);
	features = readl(vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES);
	features <<= 32;

	writel(0, vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES_SEL);
	features |= readl(vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES);

	return features;
}

static void vm_transport_features(struct virtio_device *vdev, u64 features)
{
	if (features & BIT_ULL(VIRTIO_F_MMIO_NOTIFICATION))
		__virtio_set_bit(vdev, VIRTIO_F_MMIO_NOTIFICATION);
	if (features & BIT_ULL(VIRTIO_F_MMIO_MSI))
		__virtio_set_bit(vdev, VIRTIO_F_MMIO_MSI);
}

static int vm_finalize_features(struct virtio_device *vdev)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	u64 features = vdev->features;

	/* Give virtio_ring a chance to accept features. */
	vring_transport_features(vdev);

	/* Give virtio_mmio a chance to accept features. */
	vm_transport_features(vdev, features);

	/* Make sure there is are no mixed devices */
	if (vm_dev->version == 2 &&
			!__virtio_test_bit(vdev, VIRTIO_F_VERSION_1)) {
		dev_err(&vdev->dev, "New virtio-mmio devices (version 2) must provide VIRTIO_F_VERSION_1 feature!\n");
		return -EINVAL;
	}

	writel(1, vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES_SEL);
	writel((u32)(vdev->features >> 32),
			vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES);

	writel(0, vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES_SEL);
	writel((u32)vdev->features,
			vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES);

	return 0;
}

static void vm_get(struct virtio_device *vdev, unsigned offset,
		   void *buf, unsigned len)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	void __iomem *base = vm_dev->base + VIRTIO_MMIO_CONFIG;
	u8 b;
	__le16 w;
	__le32 l;

	if (vm_dev->version == 1) {
		u8 *ptr = buf;
		int i;

		for (i = 0; i < len; i++)
			ptr[i] = readb(base + offset + i);
		return;
	}

	switch (len) {
	case 1:
		b = readb(base + offset);
		memcpy(buf, &b, sizeof b);
		break;
	case 2:
		w = cpu_to_le16(readw(base + offset));
		memcpy(buf, &w, sizeof w);
		break;
	case 4:
		l = cpu_to_le32(readl(base + offset));
		memcpy(buf, &l, sizeof l);
		break;
	case 8:
		l = cpu_to_le32(readl(base + offset));
		memcpy(buf, &l, sizeof l);
		l = cpu_to_le32(ioread32(base + offset + sizeof l));
		memcpy(buf + sizeof l, &l, sizeof l);
		break;
	default:
		BUG();
	}
}

static void vm_set(struct virtio_device *vdev, unsigned offset,
		   const void *buf, unsigned len)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	void __iomem *base = vm_dev->base + VIRTIO_MMIO_CONFIG;
	u8 b;
	__le16 w;
	__le32 l;

	if (vm_dev->version == 1) {
		const u8 *ptr = buf;
		int i;

		for (i = 0; i < len; i++)
			writeb(ptr[i], base + offset + i);

		return;
	}

	switch (len) {
	case 1:
		memcpy(&b, buf, sizeof b);
		writeb(b, base + offset);
		break;
	case 2:
		memcpy(&w, buf, sizeof w);
		writew(le16_to_cpu(w), base + offset);
		break;
	case 4:
		memcpy(&l, buf, sizeof l);
		writel(le32_to_cpu(l), base + offset);
		break;
	case 8:
		memcpy(&l, buf, sizeof l);
		writel(le32_to_cpu(l), base + offset);
		memcpy(&l, buf + sizeof l, sizeof l);
		writel(le32_to_cpu(l), base + offset + sizeof l);
		break;
	default:
		BUG();
	}
}

static u32 vm_generation(struct virtio_device *vdev)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

	if (vm_dev->version == 1)
		return 0;
	else
		return readl(vm_dev->base + VIRTIO_MMIO_CONFIG_GENERATION);
}

static u8 vm_get_status(struct virtio_device *vdev)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

	return readl(vm_dev->base + VIRTIO_MMIO_STATUS) & 0xff;
}

static void vm_set_status(struct virtio_device *vdev, u8 status)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

	/* We should never be setting status to 0. */
	BUG_ON(status == 0);

	writel(status, vm_dev->base + VIRTIO_MMIO_STATUS);
}

static void vm_reset(struct virtio_device *vdev)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

	/* 0 status means a reset. */
	writel(0, vm_dev->base + VIRTIO_MMIO_STATUS);
}

static inline void mmio_msi_set_enable(struct virtio_mmio_device *vm_dev,
		int enable)
{
	u32 state;

	state = readl(vm_dev->base + VIRTIO_MMIO_MSI_STATE);
	if (enable && (state & VIRTIO_MMIO_MSI_ENABLE_MASK))
		return;

	writel(VIRTIO_MMIO_MSI_CMD_ENABLE,
			vm_dev->base + VIRTIO_MMIO_MSI_COMMAND);
}

static void mmio_msi_config_vector(struct virtio_mmio_device *vm_dev,
		u32 vector)
{
	writel(vector, vm_dev->base + VIRTIO_MMIO_VEC_SEL);
	writel(VIRTIO_MMIO_MSI_CMD_MAP_CONFIG,
			vm_dev->base + VIRTIO_MMIO_MSI_COMMAND);
}

static void mmio_msi_queue_vector(struct virtio_mmio_device *vm_dev,
		u32 vector)
{
	writel(vector, vm_dev->base + VIRTIO_MMIO_VEC_SEL);
	writel(VIRTIO_MMIO_MSI_CMD_MAP_QUEUE,
			vm_dev->base + VIRTIO_MMIO_MSI_COMMAND);
}

/* Transport interface */

/* the notify function used when creating a virt queue */
static bool vm_notify(struct virtqueue *vq)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vq->vdev);
	struct virtio_mmio_vq_info *info = vq->priv;

	/* We write the queue's selector into the Notify Address to
	 * signal the other end */
	if (info)
		writel(vq->index, vm_dev->base + info->notify_addr);

	return true;
}

/* Notify all virtqueues on an interrupt. */
static irqreturn_t vm_interrupt(int irq, void *opaque)
{
	struct virtio_mmio_device *vm_dev = opaque;
	struct virtio_mmio_vq_info *info;
	unsigned long status;
	unsigned long flags;
	irqreturn_t ret = IRQ_NONE;

	/* Read and acknowledge interrupts */
	status = readl(vm_dev->base + VIRTIO_MMIO_INTERRUPT_STATUS);
	writel(status, vm_dev->base + VIRTIO_MMIO_INTERRUPT_ACK);

	if (unlikely(status & VIRTIO_MMIO_INT_CONFIG)) {
		virtio_config_changed(&vm_dev->vdev);
		ret = IRQ_HANDLED;
	}

	if (likely(status & VIRTIO_MMIO_INT_VRING)) {
		spin_lock_irqsave(&vm_dev->lock, flags);
		list_for_each_entry(info, &vm_dev->virtqueues, node)
			ret |= vring_interrupt(irq, info->vq);
		spin_unlock_irqrestore(&vm_dev->lock, flags);
	}

	return ret;
}

static irqreturn_t vm_vring_interrupt(int irq, void *opaque)
{
	struct virtio_mmio_device *vm_dev = opaque;
	struct virtio_mmio_vq_info *info;
	irqreturn_t ret = IRQ_NONE;
	unsigned long flags;

	spin_lock_irqsave(&vm_dev->lock, flags);
	list_for_each_entry(info, &vm_dev->virtqueues, node) {
		if (vring_interrupt(irq, info->vq) == IRQ_HANDLED)
			ret = IRQ_HANDLED;
	}
	spin_unlock_irqrestore(&vm_dev->lock, flags);

	return ret;
}


/* Handle a configuration change */
static irqreturn_t vm_config_changed(int irq, void *opaque)
{
	struct virtio_mmio_device *vm_dev = opaque;

	virtio_config_changed(&vm_dev->vdev);

	return IRQ_HANDLED;
}

static void vm_del_vq(struct virtqueue *vq)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vq->vdev);
	struct virtio_mmio_vq_info *info = vq->priv;
	unsigned long flags;
	unsigned int index = vq->index;

	if (vm_dev->msi_enabled && vm_dev->per_vq_vectors) {
		if (info->msi_vector != VIRTIO_MMIO_MSI_NO_VECTOR) {
			int irq = vm_msi_irq_vector(&vq->vdev->dev,
					info->msi_vector);

			free_irq(irq, vq);
		}
	}

	spin_lock_irqsave(&vm_dev->lock, flags);
	list_del(&info->node);
	spin_unlock_irqrestore(&vm_dev->lock, flags);

	/* Select and deactivate the queue */
	writel(index, vm_dev->base + VIRTIO_MMIO_QUEUE_SEL);
	if (vm_dev->version == 1) {
		writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_PFN);
	} else {
		writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_READY);
		WARN_ON(readl(vm_dev->base + VIRTIO_MMIO_QUEUE_READY));
	}

	vring_del_virtqueue(vq);

	kfree(info);
}

static void vm_free_irqs(struct virtio_device *vdev)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

	if (vm_dev->msi_enabled)
		vm_free_msi_irqs(vdev);
	else
		free_irq(platform_get_irq(vm_dev->pdev, 0), vm_dev);
}

static void vm_del_vqs(struct virtio_device *vdev)
{
	struct virtqueue *vq, *n;

	list_for_each_entry_safe(vq, n, &vdev->vqs, list)
		vm_del_vq(vq);

	vm_free_irqs(vdev);
}

static struct virtqueue *vm_setup_vq(struct virtio_device *vdev, unsigned index,
				  void (*callback)(struct virtqueue *vq),
				  const char *name, bool ctx, u32 msi_vector)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	struct virtio_mmio_vq_info *info;
	struct virtqueue *vq;
	unsigned long flags;
	unsigned int num;
	int err;

	if (!name)
		return NULL;

	/* Select the queue we're interested in */
	writel(index, vm_dev->base + VIRTIO_MMIO_QUEUE_SEL);

	/* Queue shouldn't already be set up. */
	if (readl(vm_dev->base + (vm_dev->version == 1 ?
			VIRTIO_MMIO_QUEUE_PFN : VIRTIO_MMIO_QUEUE_READY))) {
		err = -ENOENT;
		goto error_available;
	}

	/* Allocate and fill out our active queue description */
	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		goto error_kmalloc;
	}

	num = readl(vm_dev->base + VIRTIO_MMIO_QUEUE_NUM_MAX);
	if (num == 0) {
		err = -ENOENT;
		goto error_new_virtqueue;
	}

	/* Create the vring */
	vq = vring_create_virtqueue(index, num, VIRTIO_MMIO_VRING_ALIGN, vdev,
				 true, true, ctx, vm_notify, callback, name);
	if (!vq) {
		err = -ENOMEM;
		goto error_new_virtqueue;
	}

	/* Activate the queue */
	writel(virtqueue_get_vring_size(vq), vm_dev->base + VIRTIO_MMIO_QUEUE_NUM);
	if (vm_dev->version == 1) {
		u64 q_pfn = virtqueue_get_desc_addr(vq) >> PAGE_SHIFT;

		/*
		 * virtio-mmio v1 uses a 32bit QUEUE PFN. If we have something
		 * that doesn't fit in 32bit, fail the setup rather than
		 * pretending to be successful.
		 */
		if (q_pfn >> 32) {
			dev_err(&vdev->dev,
				"platform bug: legacy virtio-mmio must not be used with RAM above 0x%llxGB\n",
				0x1ULL << (32 + PAGE_SHIFT - 30));
			err = -E2BIG;
			goto error_bad_pfn;
		}

		writel(PAGE_SIZE, vm_dev->base + VIRTIO_MMIO_QUEUE_ALIGN);
		writel(q_pfn, vm_dev->base + VIRTIO_MMIO_QUEUE_PFN);
	} else {
		u64 addr;

		addr = virtqueue_get_desc_addr(vq);
		writel((u32)addr, vm_dev->base + VIRTIO_MMIO_QUEUE_DESC_LOW);
		writel((u32)(addr >> 32),
				vm_dev->base + VIRTIO_MMIO_QUEUE_DESC_HIGH);

		addr = virtqueue_get_avail_addr(vq);
		writel((u32)addr, vm_dev->base + VIRTIO_MMIO_QUEUE_AVAIL_LOW);
		writel((u32)(addr >> 32),
				vm_dev->base + VIRTIO_MMIO_QUEUE_AVAIL_HIGH);

		addr = virtqueue_get_used_addr(vq);
		writel((u32)addr, vm_dev->base + VIRTIO_MMIO_QUEUE_USED_LOW);
		writel((u32)(addr >> 32),
				vm_dev->base + VIRTIO_MMIO_QUEUE_USED_HIGH);

		writel(1, vm_dev->base + VIRTIO_MMIO_QUEUE_READY);
	}

	vq->priv = info;
	info->vq = vq;

	if (__virtio_test_bit(vdev, VIRTIO_F_MMIO_NOTIFICATION))
		info->notify_addr = vm_dev->notify_base +
				vm_dev->notify_multiplier * vq->index;
	else
		info->notify_addr = VIRTIO_MMIO_QUEUE_NOTIFY;

	info->msi_vector = msi_vector;
	if (vm_dev->dyn_mapping && msi_vector != VIRTIO_MMIO_MSI_NO_VECTOR)
		mmio_msi_queue_vector(vm_dev, msi_vector);

	spin_lock_irqsave(&vm_dev->lock, flags);
	list_add(&info->node, &vm_dev->virtqueues);
	spin_unlock_irqrestore(&vm_dev->lock, flags);

	return vq;

error_bad_pfn:
	vring_del_virtqueue(vq);
error_new_virtqueue:
	if (vm_dev->version == 1) {
		writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_PFN);
	} else {
		writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_READY);
		WARN_ON(readl(vm_dev->base + VIRTIO_MMIO_QUEUE_READY));
	}
	kfree(info);
error_kmalloc:
error_available:
	return ERR_PTR(err);
}

static int vm_find_vqs_intx(struct virtio_device *vdev, unsigned int nvqs,
			struct virtqueue *vqs[],
			vq_callback_t *callbacks[],
			const char * const names[],
			const bool *ctx)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	int irq = platform_get_irq(vm_dev->pdev, 0);
	int i, err, queue_idx = 0;

	if (irq < 0) {
		dev_err(&vdev->dev, "Cannot get IRQ resource\n");
		return irq;
	}

	err = request_irq(irq, vm_interrupt, IRQF_SHARED,
			dev_name(&vdev->dev), vm_dev);

	for (i = 0; i < nvqs; ++i) {
		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vqs[i] = vm_setup_vq(vdev, queue_idx++, callbacks[i], names[i],
				     ctx ? ctx[i] : false,
				     VIRTIO_MMIO_MSI_NO_VECTOR);
		if (IS_ERR(vqs[i])) {
			vm_del_vqs(vdev);
			return PTR_ERR(vqs[i]);
		}
	}

	return err;
}

static int vm_find_vqs_msi(struct virtio_device *vdev, unsigned int nvqs,
			struct virtqueue *vqs[], vq_callback_t *callbacks[],
			const char * const names[], bool per_vq_vectors,
			const bool *ctx, struct irq_affinity *desc)
{
	int i, err, allocated_vectors, nvectors;
	u32 msi_vec;
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	bool dyn_mapping = !!(readl(vm_dev->base + VIRTIO_MMIO_MSI_STATE) &
		VIRTIO_MMIO_MSI_MAPPING_MASK);

	if (!dyn_mapping &&
		readl(vm_dev->base + VIRTIO_MMIO_VEC_NUM) < (nvqs + 1))
		return -EINVAL;
	vm_dev->dyn_mapping = dyn_mapping;

	vm_dev->per_vq_vectors = (!vm_dev->dyn_mapping || per_vq_vectors);
	if (vm_dev->per_vq_vectors) {
		nvectors = 1;
		for (i = 0; i < nvqs; ++i)
			if (callbacks[i])
				++nvectors;
	} else {
		nvectors = 2;
	}

	/* Allocate nvqs irqs for queues and one irq for configuration */
	err = vm_request_msi_vectors(vdev, nvectors);
	if (err != 0)
		return err;

	allocated_vectors = vm_dev->msi_used_vectors;
	for (i = 0; i < nvqs; i++) {
		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}
		if (!callbacks[i])
			msi_vec = VIRTIO_MMIO_MSI_NO_VECTOR;
		else if (vm_dev->per_vq_vectors)
			msi_vec = allocated_vectors++;
		else
			msi_vec = 1;
		vqs[i] = vm_setup_vq(vdev, i, callbacks[i], names[i],
				ctx ? ctx[i] : false, msi_vec);
		if (IS_ERR(vqs[i])) {
			err = PTR_ERR(vqs[i]);
			goto error_find;
		}

		if (!vm_dev->per_vq_vectors ||
				msi_vec == VIRTIO_MMIO_MSI_NO_VECTOR)
			continue;

		/* allocate per-vq irq if available and necessary */
		snprintf(vm_dev->vm_vq_names[msi_vec],
			sizeof(*vm_dev->vm_vq_names),
			"%s-%s",
			dev_name(&vm_dev->vdev.dev), names[i]);
		err = request_irq(vm_msi_irq_vector(&vqs[i]->vdev->dev,
					msi_vec),
				vring_interrupt, 0,
				vm_dev->vm_vq_names[msi_vec], vqs[i]);

		if (err)
			goto error_find;
	}

	return 0;

error_find:
	vm_del_vqs(vdev);
	return err;
}

static int vm_find_vqs(struct virtio_device *vdev, unsigned nvqs,
		       struct virtqueue *vqs[],
		       vq_callback_t *callbacks[],
		       const char * const names[],
		       const bool *ctx,
		       struct irq_affinity *desc)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	int err;

	if (__virtio_test_bit(vdev, VIRTIO_F_MMIO_NOTIFICATION)) {
		unsigned notify = readl(vm_dev->base + VIRTIO_MMIO_QUEUE_NOTIFY);

		vm_dev->notify_base = notify & 0xffff;
		vm_dev->notify_multiplier = (notify >> 16) & 0xffff;
	}

	if (__virtio_test_bit(vdev, VIRTIO_F_MMIO_MSI)) {
		err = vm_find_vqs_msi(vdev, nvqs, vqs, callbacks,
				names, true, ctx, desc);
		if (!err)
			return 0;

		err = vm_find_vqs_msi(vdev, nvqs, vqs, callbacks,
				names, false, ctx, desc);
		if (!err)
			return 0;
	}

	return vm_find_vqs_intx(vdev, nvqs, vqs, callbacks, names, ctx);
}

static int vm_request_msi_vectors(struct virtio_device *vdev, int nirqs)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
	unsigned int v;
	int irq, err;

	if (vm_dev->msi_enabled)
		return -EINVAL;

	vm_dev->vm_vq_names = kmalloc_array(nirqs, sizeof(*vm_dev->vm_vq_names),
			GFP_KERNEL);
	if (!vm_dev->vm_vq_names)
		return -ENOMEM;

	vm_set_msi_domain(vdev);
	err = vm_msi_domain_alloc_irqs(&vdev->dev, nirqs);
	if (err) {
		kfree(vm_dev->vm_vq_names);
		vm_dev->vm_vq_names = NULL;
		return err;
	}

	mmio_msi_set_enable(vm_dev, 1);
	vm_dev->msi_enabled = true;

	v = vm_dev->msi_used_vectors;
	/* The first MSI vector is used for configuration change events. */
	snprintf(vm_dev->vm_vq_names[v], sizeof(*vm_dev->vm_vq_names),
			"%s-config", dev_name(&vdev->dev));
	irq = vm_msi_irq_vector(&vdev->dev, v);
	err = request_irq(irq, vm_config_changed, 0, vm_dev->vm_vq_names[v],
			vm_dev);
	if (err)
		goto error_request_irq;

	if (vm_dev->dyn_mapping)
		mmio_msi_config_vector(vm_dev, v);

	++vm_dev->msi_used_vectors;

	if (!vm_dev->per_vq_vectors) {
		v = vm_dev->msi_used_vectors;
		snprintf(vm_dev->vm_vq_names[v], sizeof(*vm_dev->vm_vq_names),
			 "%s-virtqueues", dev_name(&vm_dev->vdev.dev));
		err = request_irq(vm_msi_irq_vector(&vdev->dev, v),
				  vm_vring_interrupt, 0, vm_dev->vm_vq_names[v],
				  vm_dev);
		if (err)
			goto error_request_irq;
		++vm_dev->msi_used_vectors;
	}

	return 0;

error_request_irq:
	vm_free_msi_irqs(vdev);

	return err;
}

static void vm_free_msi_irqs(struct virtio_device *vdev)
{
	int i;
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

	mmio_msi_set_enable(vm_dev, 0);
	for (i = 0; i < vm_dev->msi_used_vectors; i++)
		free_irq(vm_msi_irq_vector(&vdev->dev, i), vm_dev);
	vm_msi_domain_free_irqs(&vdev->dev);
	kfree(vm_dev->vm_vq_names);
	vm_dev->vm_vq_names = NULL;
	vm_dev->msi_enabled = false;
	vm_dev->msi_used_vectors = 0;
}

static const char *vm_bus_name(struct virtio_device *vdev)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

	return vm_dev->pdev->name;
}

static const struct virtio_config_ops virtio_mmio_config_ops = {
	.get		= vm_get,
	.set		= vm_set,
	.generation	= vm_generation,
	.get_status	= vm_get_status,
	.set_status	= vm_set_status,
	.reset		= vm_reset,
	.find_vqs	= vm_find_vqs,
	.del_vqs	= vm_del_vqs,
	.get_features	= vm_get_features,
	.finalize_features = vm_finalize_features,
	.bus_name	= vm_bus_name,
};


static void virtio_mmio_release_dev(struct device *_d)
{
	struct virtio_device *vdev =
			container_of(_d, struct virtio_device, dev);
	struct virtio_mmio_device *vm_dev =
			container_of(vdev, struct virtio_mmio_device, vdev);
	struct platform_device *pdev = vm_dev->pdev;

	devm_kfree(&pdev->dev, vm_dev);
}

/* Platform device */

static int virtio_mmio_probe(struct platform_device *pdev)
{
	struct virtio_mmio_device *vm_dev;
	struct resource *mem;
	unsigned long magic;
	int rc;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem)
		return -EINVAL;

	if (!devm_request_mem_region(&pdev->dev, mem->start,
			resource_size(mem), pdev->name))
		return -EBUSY;

	vm_dev = devm_kzalloc(&pdev->dev, sizeof(*vm_dev), GFP_KERNEL);
	if (!vm_dev)
		return -ENOMEM;

	vm_dev->vdev.dev.parent = &pdev->dev;
	vm_dev->vdev.dev.release = virtio_mmio_release_dev;
	vm_dev->vdev.config = &virtio_mmio_config_ops;
	vm_dev->pdev = pdev;
	INIT_LIST_HEAD(&vm_dev->virtqueues);
	spin_lock_init(&vm_dev->lock);

	vm_dev->base = devm_ioremap(&pdev->dev, mem->start, resource_size(mem));
	if (vm_dev->base == NULL)
		return -EFAULT;

	/* Check magic value */
	magic = readl(vm_dev->base + VIRTIO_MMIO_MAGIC_VALUE);
	if (magic != ('v' | 'i' << 8 | 'r' << 16 | 't' << 24)) {
		dev_warn(&pdev->dev, "Wrong magic value 0x%08lx!\n", magic);
		return -ENODEV;
	}

	/* Check device version */
	vm_dev->version = readl(vm_dev->base + VIRTIO_MMIO_VERSION);
	if (vm_dev->version < 1 || vm_dev->version > 2) {
		dev_err(&pdev->dev, "Version %ld not supported!\n",
				vm_dev->version);
		return -ENXIO;
	}

	vm_dev->vdev.id.device = readl(vm_dev->base + VIRTIO_MMIO_DEVICE_ID);
	if (vm_dev->vdev.id.device == 0) {
		/*
		 * virtio-mmio device with an ID 0 is a (dummy) placeholder
		 * with no function. End probing now with no error reported.
		 */
		return -ENODEV;
	}
	vm_dev->vdev.id.vendor = readl(vm_dev->base + VIRTIO_MMIO_VENDOR_ID);

	if (vm_dev->version == 1) {
		writel(PAGE_SIZE, vm_dev->base + VIRTIO_MMIO_GUEST_PAGE_SIZE);

		rc = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
		/*
		 * In the legacy case, ensure our coherently-allocated virtio
		 * ring will be at an address expressable as a 32-bit PFN.
		 */
		if (!rc)
			dma_set_coherent_mask(&pdev->dev,
					      DMA_BIT_MASK(32 + PAGE_SHIFT));
	} else {
		rc = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	}
	if (rc)
		rc = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (rc)
		dev_warn(&pdev->dev, "Failed to enable 64-bit or 32-bit DMA.  Trying to continue, but this might not work.\n");

	platform_set_drvdata(pdev, vm_dev);

	vm_create_msi_domain();

	rc = register_virtio_device(&vm_dev->vdev);
	if (rc)
		put_device(&vm_dev->vdev.dev);

	return rc;
}

static int virtio_mmio_remove(struct platform_device *pdev)
{
	struct virtio_mmio_device *vm_dev = platform_get_drvdata(pdev);
	unregister_virtio_device(&vm_dev->vdev);

	return 0;
}



/* Devices list parameter */

#if defined(CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES)

static struct device vm_cmdline_parent = {
	.init_name = "virtio-mmio-cmdline",
};

static int vm_cmdline_parent_registered;
static int vm_cmdline_id;

static int vm_cmdline_set(const char *device,
		const struct kernel_param *kp)
{
	int err;
	struct resource resources[2] = {};
	char *str;
	long long int base, size;
	unsigned int irq;
	int processed, consumed = 0;
	struct platform_device *pdev;

	/* Consume "size" part of the command line parameter */
	size = memparse(device, &str);

	/* Get "@<base>:<irq>[:<id>]" chunks */
	processed = sscanf(str, "@%lli:%u%n:%d%n",
			&base, &irq, &consumed,
			&vm_cmdline_id, &consumed);

	/*
	 * sscanf() must processes at least 2 chunks; also there
	 * must be no extra characters after the last chunk, so
	 * str[consumed] must be '\0'
	 */
	if (processed < 2 || str[consumed])
		return -EINVAL;

	resources[0].flags = IORESOURCE_MEM;
	resources[0].start = base;
	resources[0].end = base + size - 1;

	resources[1].flags = IORESOURCE_IRQ;
	resources[1].start = resources[1].end = irq;

	if (!vm_cmdline_parent_registered) {
		err = device_register(&vm_cmdline_parent);
		if (err) {
			pr_err("Failed to register parent device!\n");
			return err;
		}
		vm_cmdline_parent_registered = 1;
	}

	pr_info("Registering device virtio-mmio.%d at 0x%llx-0x%llx, IRQ %d.\n",
		       vm_cmdline_id,
		       (unsigned long long)resources[0].start,
		       (unsigned long long)resources[0].end,
		       (int)resources[1].start);

	pdev = platform_device_register_resndata(&vm_cmdline_parent,
			"virtio-mmio", vm_cmdline_id++,
			resources, ARRAY_SIZE(resources), NULL, 0);

	return PTR_ERR_OR_ZERO(pdev);
}

static int vm_cmdline_get_device(struct device *dev, void *data)
{
	char *buffer = data;
	unsigned int len = strlen(buffer);
	struct platform_device *pdev = to_platform_device(dev);

	snprintf(buffer + len, PAGE_SIZE - len, "0x%llx@0x%llx:%llu:%d\n",
			pdev->resource[0].end - pdev->resource[0].start + 1ULL,
			(unsigned long long)pdev->resource[0].start,
			(unsigned long long)pdev->resource[1].start,
			pdev->id);
	return 0;
}

static int vm_cmdline_get(char *buffer, const struct kernel_param *kp)
{
	buffer[0] = '\0';
	device_for_each_child(&vm_cmdline_parent, buffer,
			vm_cmdline_get_device);
	return strlen(buffer) + 1;
}

static const struct kernel_param_ops vm_cmdline_param_ops = {
	.set = vm_cmdline_set,
	.get = vm_cmdline_get,
};

device_param_cb(device, &vm_cmdline_param_ops, NULL, S_IRUSR);

static int vm_unregister_cmdline_device(struct device *dev,
		void *data)
{
	platform_device_unregister(to_platform_device(dev));

	return 0;
}

static void vm_unregister_cmdline_devices(void)
{
	if (vm_cmdline_parent_registered) {
		device_for_each_child(&vm_cmdline_parent, NULL,
				vm_unregister_cmdline_device);
		device_unregister(&vm_cmdline_parent);
		vm_cmdline_parent_registered = 0;
	}
}

#else

static void vm_unregister_cmdline_devices(void)
{
}

#endif

/* Platform driver */

static const struct of_device_id virtio_mmio_match[] = {
	{ .compatible = "virtio,mmio", },
	{},
};
MODULE_DEVICE_TABLE(of, virtio_mmio_match);

#ifdef CONFIG_ACPI
static const struct acpi_device_id virtio_mmio_acpi_match[] = {
	{ "LNRO0005", },
	{ }
};
MODULE_DEVICE_TABLE(acpi, virtio_mmio_acpi_match);
#endif

static struct platform_driver virtio_mmio_driver = {
	.probe		= virtio_mmio_probe,
	.remove		= virtio_mmio_remove,
	.driver		= {
		.name	= "virtio-mmio",
		.of_match_table	= virtio_mmio_match,
		.acpi_match_table = ACPI_PTR(virtio_mmio_acpi_match),
	},
};

static int __init virtio_mmio_init(void)
{
	return platform_driver_register(&virtio_mmio_driver);
}

static void __exit virtio_mmio_exit(void)
{
	platform_driver_unregister(&virtio_mmio_driver);
	vm_unregister_cmdline_devices();
}

module_init(virtio_mmio_init);
module_exit(virtio_mmio_exit);

MODULE_AUTHOR("Pawel Moll <pawel.moll@arm.com>");
MODULE_DESCRIPTION("Platform bus driver for memory mapped virtio devices");
MODULE_LICENSE("GPL");
