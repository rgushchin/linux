// SPDX-License-Identifier: GPL-2.0
#include <linux/idr.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/shrinker.h>

/* defined in vmscan.c */
extern struct rw_semaphore shrinker_rwsem;
extern struct list_head shrinker_list;

static DEFINE_IDA(shrinker_debugfs_ida);
static struct dentry *shrinker_debugfs_root;

static int shrinker_debugfs_count_show(struct seq_file *m, void *v)
{
	struct shrinker *shrinker = (struct shrinker *)m->private;
	unsigned long nr, total = 0;
	int ret, nid;

	ret = down_read_killable(&shrinker_rwsem);
	if (ret)
		return ret;

	for_each_node(nid) {
		struct shrink_control sc = {
			.gfp_mask = GFP_KERNEL,
			.nid = nid,
		};

		nr = shrinker->count_objects(shrinker, &sc);
		if (nr == SHRINK_EMPTY)
			nr = 0;
		total += nr;

		if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
			break;

		cond_resched();
	}
	up_read(&shrinker_rwsem);

	seq_printf(m, "%lu\n", total);

	return ret;
}
DEFINE_SHOW_ATTRIBUTE(shrinker_debugfs_count);

static ssize_t shrinker_debugfs_scan_write(struct file *file,
					   const char __user *buf,
					   size_t size, loff_t *pos)
{
	struct shrinker *shrinker = (struct shrinker *)file->private_data;
	unsigned long nr, total = 0, nr_to_scan;
	unsigned long *count_per_node = NULL;
	int nid;
	char kbuf[24];
	int read_len = size < (sizeof(kbuf) - 1) ? size : (sizeof(kbuf) - 1);
	ssize_t ret;

	if (copy_from_user(kbuf, buf, read_len))
		return -EFAULT;
	kbuf[read_len] = '\0';

	if (kstrtoul(kbuf, 10, &nr_to_scan))
		return -EINVAL;

	ret = down_read_killable(&shrinker_rwsem);
	if (ret)
		return ret;

	if (shrinker->flags & SHRINKER_NUMA_AWARE) {
		/*
		 * If the shrinker is numa aware, distribute nr_to_scan
		 * proportionally.
		 */
		count_per_node = kcalloc(nr_node_ids, sizeof(unsigned long),
					 GFP_KERNEL);
		if (!count_per_node) {
			ret = -ENOMEM;
			goto out;
		}

		for_each_node(nid) {
			struct shrink_control sc = {
				.gfp_mask = GFP_KERNEL,
				.nid = nid,
			};

			nr = shrinker->count_objects(shrinker, &sc);
			if (nr == SHRINK_EMPTY)
				nr = 0;
			count_per_node[nid] = nr;
			total += nr;

			cond_resched();
		}
	}

	for_each_node(nid) {
		struct shrink_control sc = {
			.gfp_mask = GFP_KERNEL,
			.nid = nid,
		};

		if (shrinker->flags & SHRINKER_NUMA_AWARE) {
			sc.nr_to_scan = nr_to_scan * count_per_node[nid] /
				(total ? total : 1);
			sc.nr_scanned = sc.nr_to_scan;
		} else {
			sc.nr_to_scan = nr_to_scan;
			sc.nr_scanned = sc.nr_to_scan;
		}

		nr = shrinker->scan_objects(shrinker, &sc);
		if (nr == SHRINK_STOP)
			break;

		if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
			break;

		cond_resched();

	}
	ret = size;
out:
	up_read(&shrinker_rwsem);
	kfree(count_per_node);
	return ret;
}

static int shrinker_debugfs_scan_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return nonseekable_open(inode, file);
}

static const struct file_operations shrinker_debugfs_scan_fops = {
	.owner	 = THIS_MODULE,
	.open	 = shrinker_debugfs_scan_open,
	.write	 = shrinker_debugfs_scan_write,
};

int shrinker_debugfs_add(struct shrinker *shrinker)
{
	struct dentry *entry;
	char buf[256];
	int id;

	lockdep_assert_held(&shrinker_rwsem);

	/* debugfs isn't initialized yet, add debugfs entries later. */
	if (!shrinker_debugfs_root)
		return 0;

	id = ida_alloc(&shrinker_debugfs_ida, GFP_KERNEL);
	if (id < 0)
		return id;
	shrinker->debugfs_id = id;

	snprintf(buf, sizeof(buf), "%d", id);

	/* create debugfs entry */
	entry = debugfs_create_dir(buf, shrinker_debugfs_root);
	if (IS_ERR(entry)) {
		ida_free(&shrinker_debugfs_ida, id);
		return PTR_ERR(entry);
	}
	shrinker->debugfs_entry = entry;

	/* create generic interfaces */
	debugfs_create_file("count", 0220, entry, shrinker,
			    &shrinker_debugfs_count_fops);
	debugfs_create_file("scan", 0440, entry, shrinker,
			    &shrinker_debugfs_scan_fops);

	return 0;
}

void shrinker_debugfs_remove(struct shrinker *shrinker)
{
	lockdep_assert_held(&shrinker_rwsem);

	if (!shrinker->debugfs_entry)
		return;

	debugfs_remove_recursive(shrinker->debugfs_entry);
	ida_free(&shrinker_debugfs_ida, shrinker->debugfs_id);
}

static int __init shrinker_debugfs_init(void)
{
	struct shrinker *shrinker;
	int ret;

	if (!debugfs_initialized())
		return -ENODEV;

	shrinker_debugfs_root = debugfs_create_dir("shrinker", NULL);
	if (!shrinker_debugfs_root)
		return -ENOMEM;

	/* Create debugfs entries for shrinkers registered at boot */
	ret = down_write_killable(&shrinker_rwsem);
	if (ret)
		return ret;

	list_for_each_entry(shrinker, &shrinker_list, list)
		if (!shrinker->debugfs_entry)
			ret = shrinker_debugfs_add(shrinker);
	up_write(&shrinker_rwsem);

	return ret;
}
late_initcall(shrinker_debugfs_init);
