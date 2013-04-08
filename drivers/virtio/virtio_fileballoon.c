/* Virtio file (page cache-backed) balloon implementation, inspired by
 * Dor Loar and Marcelo Tosatti's implementations, and based on Rusty Russel's
 * implementation.
 *
 * This implementation of the virtio balloon driver re-uses the page cache to
 * allow memory consumed by inflating the balloon to be reclaimed by linux.  It
 * creates and mounts a bare-bones filesystem containing a single inode.  When
 * the host requests the balloon to inflate, it does so by "reading" pages at
 * offsets into the inode mapping's page_tree.  The host is notified when the
 * pages are added to the page_tree, allowing it (the host) to madvise(2) the
 * corresponding host memory, reducing the RSS of the virtual machine.  In this
 * implementation, the host is only notified when a page is added to the
 * balloon.  Reclaim happens under the existing TTFP logic, which flushes unused
 * pages in the page cache.  If the host used MADV_DONTNEED, then when the guest
 * uses the page, the zero page will be mapped in, allowing automatic (and fast,
 * compared to requiring a host notification via a virtio queue to get memory
 * back) reclaim.
 *
 *  Copyright 2008 Rusty Russell IBM Corporation
 *  Copyright 2011 Frank Swiderski Google Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <linux/backing-dev.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/virtio.h>
#include <linux/virtio_balloon.h>
#include <linux/writeback.h>

#define VIRTBALLOON_PFN_ARRAY_SIZE 256

struct virtio_balloon {
	struct virtio_device *vdev;
	struct virtqueue *inflate_vq;

	/* Where the ballooning thread waits for config to change. */
	wait_queue_head_t config_change;

	/* The thread servicing the balloon. */
	struct task_struct *thread;

	/* Waiting for host to ack the pages we released. */
	struct completion acked;

	/* The array of pfns we tell the Host about. */
	unsigned int num_pfns;
	u32 pfns[VIRTBALLOON_PFN_ARRAY_SIZE];

	struct virtio_balloon_stat stats[VIRTIO_BALLOON_S_NR];

	/* The last page offset read into the mapping's page_tree */
	unsigned long last_scan_page_array;

	/* The last time a page was reclaimed */
	unsigned long last_reclaim;
};

/* Magic number used for the skeleton filesystem in the call to mount_pseudo */
#define BALLOONFS_MAGIC 0x42414c4c

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_FILE_BALLOON, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

/*
 * The skeleton filesystem contains a single inode, held by the structure below.
 * Using the containing structure below allows easy access to the struct
 * virtio_balloon.
 */
static struct balloon_inode {
	struct inode inode;
	struct virtio_balloon *vb;
} the_inode;

/*
 * balloon_alloc_inode is called when the single inode for the skeleton
 * filesystem is created in init() with the call to new_inode.
 */
static struct inode *balloon_alloc_inode(struct super_block *sb)
{
	inode_init_once(&the_inode.inode);
	return &the_inode.inode;
}

/* Noop implementation of destroy_inode.  */
static void balloon_destroy_inode(struct inode *inode)
{
}

static int balloon_sync_fs(struct super_block *sb, int wait)
{
	return filemap_write_and_wait(the_inode.inode.i_mapping);
}

static const struct super_operations balloonfs_ops = {
	.alloc_inode	= balloon_alloc_inode,
	.destroy_inode	= balloon_destroy_inode,
	.sync_fs	= balloon_sync_fs,
};

static const struct dentry_operations balloonfs_dentry_operations = {
};

static struct dentry *balloonfs_mount(struct file_system_type *fs_type,
			 int flags, const char *dev_name, void *data)
{
	return mount_pseudo(fs_type, "balloon:", &balloonfs_ops,
		&balloonfs_dentry_operations, BALLOONFS_MAGIC);
}

/* The single mounted skeleton filesystem */
static struct vfsmount *balloon_mnt __read_mostly;

static struct file_system_type balloon_fs_type = {
	.name =		"balloonfs",
	.mount =	balloonfs_mount,
	.kill_sb =	kill_anon_super,
};

/*
 * balloonfs_writepage is called when linux needs to reclaim memory held using
 * the balloonfs' page cache.
 */
static int balloonfs_writepage(struct page *page, struct writeback_control *wbc)
{
	the_inode.vb->last_reclaim = jiffies;
	SetPageUptodate(page);
	ClearPageDirty(page);
	/*
	 * If the page isn't being flushed from the page allocator, go ahead and
	 * drop it from the page cache anyway.
	 */
	if (!wbc->for_reclaim)
		delete_from_page_cache(page);
	unlock_page(page);
	return 0;
}

/* Nearly no-op implementation of readpage */
static int balloonfs_readpage(struct file *file, struct page *page)
{
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}

static const struct address_space_operations balloonfs_aops = {
	.writepage = balloonfs_writepage,
	.readpage = balloonfs_readpage
};

static struct backing_dev_info balloonfs_backing_dev_info = {
	.name           = "balloonfs",
	.ra_pages       = 0,
	.capabilities   = BDI_CAP_NO_ACCT_AND_WRITEBACK
};

/* Acknowledges a message from the specified virtqueue. */
static void balloon_ack(struct virtqueue *vq)
{
	struct virtio_balloon *vb;
	unsigned int len;

	vb = virtqueue_get_buf(vq, &len);
	if (vb)
		complete(&vb->acked);
}

/*
 * Scans the page_tree for the inode's mapping, looking for an offset that is
 * currently empty, returning that index (or 0 if it could not fill the
 * request).
 */
static unsigned long find_available_inode_page(struct virtio_balloon *vb)
{
	unsigned long radix_index, index, max_scan;
	struct address_space *mapping = the_inode.inode.i_mapping;

	/*
	 * This function is a serialized call (only happens on the free-to-host
	 * thread), so no locking is necessary here.
	 */
	index = vb->last_scan_page_array;
	max_scan = totalram_pages - vb->last_scan_page_array;

	/*
	 * Scan starting at the last scanned offset, then wrap around if
	 * necessary.
	 */
	if (index == 0)
		index = 1;
	rcu_read_lock();
	radix_index = radix_tree_next_hole(&mapping->page_tree,
					   index, max_scan);
	rcu_read_unlock();
	/*
	 * If we hit the end of the tree, wrap and search up to the original
	 * index.
	 */
	if (radix_index - index >= max_scan) {
		if (index != 1) {
			rcu_read_lock();
			radix_index = radix_tree_next_hole(&mapping->page_tree,
							   1, index);
			rcu_read_unlock();
			if (radix_index - 1 >= index)
				radix_index = 0;
		} else {
			radix_index = 0;
		}
	}
	vb->last_scan_page_array = radix_index;

	return radix_index;
}

/* Notifies the host of pages in the specified virtqueue. */
static int tell_host(struct virtio_balloon *vb, struct virtqueue *vq)
{
	int err;
	struct scatterlist sg;

	sg_init_one(&sg, vb->pfns, sizeof(vb->pfns[0]) * vb->num_pfns);

	init_completion(&vb->acked);

	/* We should always be able to add one buffer to an empty queue. */
	err = virtqueue_add_buf(vq, &sg, 1, 0, vb);
	if (err  < 0)
		return err;
	virtqueue_kick(vq);

	/* When host has read buffer, this completes via balloon_ack */
	wait_for_completion(&vb->acked);
	return err;
}

static void fill_balloon(struct virtio_balloon *vb, size_t num)
{
	int err;

	/* We can only do one array worth at a time. */
	num = min(num, ARRAY_SIZE(vb->pfns));

	for (vb->num_pfns = 0; vb->num_pfns < num; vb->num_pfns++) {
		struct page *page;
		unsigned long inode_pfn = find_available_inode_page(vb);
		/* Should always be able to find a page. */
		BUG_ON(!inode_pfn);
		page = read_mapping_page(the_inode.inode.i_mapping,
					       inode_pfn, NULL);
		if (IS_ERR(page)) {
			if (printk_ratelimit())
				dev_printk(KERN_INFO, &vb->vdev->dev,
					   "Out of puff! Can't get %zu pages\n",
					   num);
			break;
		}

		/* Set the page to be dirty */
		set_page_dirty(page);

		vb->pfns[vb->num_pfns] = page_to_pfn(page);
	}

	/* Didn't get any?  Oh well. */
	if (vb->num_pfns == 0)
		return;

	/* Notify the host of the pages we just added to the page_tree. */
	err = tell_host(vb, vb->inflate_vq);

	for (; vb->num_pfns != 0; vb->num_pfns--) {
		struct page *page = pfn_to_page(vb->pfns[vb->num_pfns - 1]);
		/*
		 * Release our refcount on the page so that it can be reclaimed
		 * when necessary. */
		page_cache_release(page);
	}
	__mark_inode_dirty(&the_inode.inode, I_DIRTY_PAGES);
}

static inline void update_stat(struct virtio_balloon *vb, int idx,
			       u64 val)
{
	BUG_ON(idx >= VIRTIO_BALLOON_S_NR);
	vb->stats[idx].tag = idx;
	vb->stats[idx].val = val;
}

#define pages_to_bytes(x) ((u64)(x) << PAGE_SHIFT)

static inline u32 config_pages(struct virtio_balloon *vb);
static void update_balloon_stats(struct virtio_balloon *vb)
{
	unsigned long events[NR_VM_EVENT_ITEMS];
	struct sysinfo i;

	all_vm_events(events);
	si_meminfo(&i);

	update_stat(vb, VIRTIO_BALLOON_S_SWAP_IN,
				pages_to_bytes(events[PSWPIN]));
	update_stat(vb, VIRTIO_BALLOON_S_SWAP_OUT,
				pages_to_bytes(events[PSWPOUT]));
	update_stat(vb, VIRTIO_BALLOON_S_MAJFLT, events[PGMAJFAULT]);
	update_stat(vb, VIRTIO_BALLOON_S_MINFLT, events[PGFAULT]);

	/* Total and Free Mem */
	update_stat(vb, VIRTIO_BALLOON_S_MEMFREE, pages_to_bytes(i.freeram));
	update_stat(vb, VIRTIO_BALLOON_S_MEMTOT, pages_to_bytes(i.totalram));
}

static void virtballoon_changed(struct virtio_device *vdev)
{
	struct virtio_balloon *vb = vdev->priv;

	wake_up(&vb->config_change);
}

static inline bool config_need_stats(struct virtio_balloon *vb)
{
	u32 v = 0;

	vb->vdev->config->get(vb->vdev,
			      offsetof(struct virtio_balloon_config,
				       need_stats),
			      &v, sizeof(v));
	return (v != 0);
}

static inline u32 config_pages(struct virtio_balloon *vb)
{
	u32 v = 0;

	vb->vdev->config->get(vb->vdev,
			      offsetof(struct virtio_balloon_config, num_pages),
			      &v, sizeof(v));
	return v;
}

static inline s64 towards_target(struct virtio_balloon *vb)
{
	struct address_space *mapping = the_inode.inode.i_mapping;
	u32 v = config_pages(vb);

	return (s64)v - (mapping ? mapping->nrpages : 0);
}

static void update_balloon_size(struct virtio_balloon *vb)
{
	struct address_space *mapping = the_inode.inode.i_mapping;
	__le32 actual = cpu_to_le32((mapping ? mapping->nrpages : 0));

	vb->vdev->config->set(vb->vdev,
			      offsetof(struct virtio_balloon_config, actual),
			      &actual, sizeof(actual));
}

static void update_free_and_total(struct virtio_balloon *vb)
{
	struct sysinfo i;
	u32 value;

	si_meminfo(&i);

	update_balloon_stats(vb);
	value = i.totalram;
	vb->vdev->config->set(vb->vdev,
			      offsetof(struct virtio_balloon_config,
				       pages_total),
			      &value, sizeof(value));
	value = i.freeram;
	vb->vdev->config->set(vb->vdev,
			      offsetof(struct virtio_balloon_config,
				       pages_free),
			      &value, sizeof(value));
	value = 0;
	vb->vdev->config->set(vb->vdev,
			      offsetof(struct virtio_balloon_config,
				       need_stats),
			      &value, sizeof(value));
}

static int balloon(void *_vballoon)
{
	struct virtio_balloon *vb = _vballoon;

	set_freezable();
	while (!kthread_should_stop()) {
		s64 diff;
		try_to_freeze();
		wait_event_interruptible(vb->config_change,
					 (diff = towards_target(vb)) > 0
					 || config_need_stats(vb)
					 || kthread_should_stop()
					 || freezing(current));
		if (config_need_stats(vb))
			update_free_and_total(vb);
		if (diff > 0) {
			unsigned long reclaim_time = vb->last_reclaim + 2 * HZ;
			/*
			 * Don't fill the balloon if a page reclaim happened in
			 * the past 2 seconds.
			 */
			if (time_after_eq(reclaim_time, jiffies)) {
				/* Inflating too fast--sleep and skip. */
				msleep(500);
			} else {
				fill_balloon(vb, diff);
			}
		} else if (diff < 0 && config_pages(vb) == 0) {
			/*
			 * Here we are specifically looking to detect the case
			 * where there are pages in the page cache, but the
			 * device wants us to go to 0.  This is used in save/
			 * restore since the host device doesn't keep track of
			 * PFNs, and must flush the page cache on restore
			 * (which loses the context of the original device
			 * instance).  However, we still suggest syncing the
			 * diff so that we can get within the target range.
			 */
			s64 nr_to_write =
				(!config_pages(vb) ? LONG_MAX : -diff);
			struct writeback_control wbc = {
				.sync_mode = WB_SYNC_ALL,
				.nr_to_write = nr_to_write,
				.range_start = 0,
				.range_end = LLONG_MAX,
			};
			sync_inode(&the_inode.inode, &wbc);
		}
		update_balloon_size(vb);
	}
	return 0;
}

static ssize_t virtballoon_attr_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buf);

static DEVICE_ATTR(total_memory, 0644,
	virtballoon_attr_show, NULL);

static DEVICE_ATTR(free_memory, 0644,
	virtballoon_attr_show, NULL);

static DEVICE_ATTR(target_pages, 0644,
	virtballoon_attr_show, NULL);

static DEVICE_ATTR(actual_pages, 0644,
	virtballoon_attr_show, NULL);

static struct attribute *virtballoon_attrs[] = {
	&dev_attr_total_memory.attr,
	&dev_attr_free_memory.attr,
	&dev_attr_target_pages.attr,
	&dev_attr_actual_pages.attr,
	NULL
};
static struct attribute_group virtballoon_attr_group = {
	.name = "virtballoon",
	.attrs = virtballoon_attrs,
};

static ssize_t virtballoon_attr_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct address_space *mapping = the_inode.inode.i_mapping;
	struct virtio_device *vdev = container_of(dev, struct virtio_device,
						  dev);
	struct virtio_balloon *vb = vdev->priv;
	unsigned long long value = 0;
	if (attr == &dev_attr_total_memory)
		value = vb->stats[VIRTIO_BALLOON_S_MEMTOT].val;
	else if (attr == &dev_attr_free_memory)
		value = vb->stats[VIRTIO_BALLOON_S_MEMFREE].val;
	else if (attr == &dev_attr_target_pages)
		value = config_pages(vb);
	else if (attr == &dev_attr_actual_pages)
		value = cpu_to_le32((mapping ? mapping->nrpages : 0));
	return sprintf(buf, "%llu\n", value);
}

static int virtballoon_probe(struct virtio_device *vdev)
{
	struct virtio_balloon *vb;
	struct virtqueue *vq[1];
	vq_callback_t *callback = balloon_ack;
	const char *name = "inflate";
	int err;

	vdev->priv = vb = kmalloc(sizeof(*vb), GFP_KERNEL);
	if (!vb) {
		err = -ENOMEM;
		goto out;
	}

	init_waitqueue_head(&vb->config_change);
	vb->vdev = vdev;

	/* We use one virtqueue: inflate */
	err = vdev->config->find_vqs(vdev, 1, vq, &callback, &name);
	if (err)
		goto out_free_vb;

	vb->inflate_vq = vq[0];

	err = sysfs_create_group(&vdev->dev.kobj, &virtballoon_attr_group);
	if (err) {
		pr_err("Failed to create virtballoon sysfs node\n");
		goto out_free_vb;
	}

	vb->last_scan_page_array = 0;
	vb->last_reclaim = 0;
	the_inode.vb = vb;

	vb->thread = kthread_run(balloon, vb, "vballoon");
	if (IS_ERR(vb->thread)) {
		err = PTR_ERR(vb->thread);
		goto out_del_vqs;
	}

	return 0;

out_del_vqs:
	vdev->config->del_vqs(vdev);
out_free_vb:
	kfree(vb);
out:
	return err;
}

static void __devexit virtballoon_remove(struct virtio_device *vdev)
{
	struct virtio_balloon *vb = vdev->priv;

	kthread_stop(vb->thread);

	sysfs_remove_group(&vdev->dev.kobj, &virtballoon_attr_group);

	/* Now we reset the device so we can clean up the queues. */
	vdev->config->reset(vdev);

	vdev->config->del_vqs(vdev);
	kfree(vb);
}

static struct virtio_driver virtio_balloon_driver = {
	.feature_table = NULL,
	.feature_table_size = 0,
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtballoon_probe,
	.remove =	__devexit_p(virtballoon_remove),
	.config_changed = virtballoon_changed,
};

static int __init init(void)
{
	int err = register_filesystem(&balloon_fs_type);
	if (err)
		goto out;

	balloon_mnt = kern_mount(&balloon_fs_type);
	if (IS_ERR(balloon_mnt)) {
		err = PTR_ERR(balloon_mnt);
		goto out_filesystem;
	}

	new_inode(balloon_mnt->mnt_sb);
	the_inode.inode.i_mapping->a_ops = &balloonfs_aops;
	the_inode.inode.i_mapping->flags |=
		(GFP_HIGHUSER | __GFP_NOMEMALLOC);
	the_inode.inode.i_mapping->backing_dev_info =
		&balloonfs_backing_dev_info;

	err = register_virtio_driver(&virtio_balloon_driver);
	if (err)
		goto out_filesystem;

	goto out;

out_filesystem:
	unregister_filesystem(&balloon_fs_type);

out:
	return err;
}

static void __exit fini(void)
{
	if (balloon_mnt) {
		unregister_filesystem(&balloon_fs_type);
		balloon_mnt = NULL;
	}
	unregister_virtio_driver(&virtio_balloon_driver);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio file (page cache-backed) balloon driver");
MODULE_LICENSE("GPL");
