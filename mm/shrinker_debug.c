// SPDX-License-Identifier: GPL-2.0
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/shrinker.h>
#include <linux/memcontrol.h>

/* defined in vmscan.c */
extern struct rw_semaphore shrinker_rwsem;
extern struct list_head shrinker_list;

static DEFINE_IDA(shrinker_debugfs_ida);
static struct dentry *shrinker_debugfs_root;

static unsigned long shrinker_count_objects(struct shrinker *shrinker,
					    struct mem_cgroup *memcg,
					    unsigned long *count_per_node)
{
	unsigned long nr, total = 0;
	int nid;

	for_each_node(nid) {
		struct shrink_control sc = {
			.gfp_mask = GFP_KERNEL,
			.nid = nid,
			.memcg = memcg,
		};

		nr = shrinker->count_objects(shrinker, &sc);
		if (nr == SHRINK_EMPTY)
			nr = 0;
		if (count_per_node)
			count_per_node[nid] = nr;
		total += nr;

		if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
			break;

		cond_resched();
	}

	return total;
}

static int shrinker_scan_objects(struct shrinker *shrinker,
				 struct mem_cgroup *memcg,
				 unsigned long nr_to_scan)
{
	unsigned long *count_per_node;
	unsigned long total, nr;
	int ret, nid;

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

		total = shrinker_count_objects(shrinker, memcg, count_per_node);
	}

	for_each_node(nid) {
		struct shrink_control sc = {
			.gfp_mask = GFP_KERNEL,
			.nid = nid,
		};

		if (count_per_node) {
			sc.nr_to_scan = nr_to_scan * count_per_node[nid] /
				(total ? total : 1);
			sc.nr_scanned = sc.nr_to_scan;
		} else {
			sc.nr_to_scan = nr_to_scan;
			sc.nr_scanned = nr_to_scan;
		}

		nr = shrinker->scan_objects(shrinker, &sc);
		if (nr == SHRINK_STOP)
			break;

		if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
			break;

		cond_resched();
	}
out:
	up_read(&shrinker_rwsem);
	kfree(count_per_node);
	return ret;
}

static int shrinker_debugfs_count_show(struct seq_file *m, void *v)
{
	struct shrinker *shrinker = (struct shrinker *)m->private;
	int ret;

	ret = down_read_killable(&shrinker_rwsem);
	if (!ret) {
		unsigned long total = shrinker_count_objects(shrinker, NULL, NULL);

		up_read(&shrinker_rwsem);
		seq_printf(m, "%lu\n", total);
	}
	return ret;
}
DEFINE_SHOW_ATTRIBUTE(shrinker_debugfs_count);

static ssize_t shrinker_debugfs_scan_write(struct file *file,
					   const char __user *buf,
					   size_t size, loff_t *pos)
{
	struct shrinker *shrinker = (struct shrinker *)file->private_data;
	unsigned long nr_to_scan;
	char kbuf[24];
	int read_len = size < (sizeof(kbuf) - 1) ? size : (sizeof(kbuf) - 1);
	ssize_t ret;

	if (copy_from_user(kbuf, buf, read_len))
		return -EFAULT;
	kbuf[read_len] = '\0';

	if (kstrtoul(kbuf, 10, &nr_to_scan))
		return -EINVAL;

	ret = shrinker_scan_objects(shrinker, NULL, nr_to_scan);

	return ret ? ret : size;
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

#ifdef CONFIG_MEMCG
static int shrinker_debugfs_count_memcg_show(struct seq_file *m, void *v)
{
	struct shrinker *shrinker = (struct shrinker *)m->private;
	struct mem_cgroup *memcg;
	unsigned long total;
	int ret;

	ret = down_read_killable(&shrinker_rwsem);
	if (ret)
		return ret;
	rcu_read_lock();

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		if (!mem_cgroup_online(memcg))
			continue;

		total = shrinker_count_objects(shrinker, memcg, NULL);
		if (!total)
			continue;

		seq_printf(m, "%lu %lu\n", mem_cgroup_ino(memcg), total);
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);

	rcu_read_unlock();
	up_read(&shrinker_rwsem);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(shrinker_debugfs_count_memcg);

static ssize_t shrinker_debugfs_scan_memcg_write(struct file *file,
						 const char __user *buf,
						 size_t size, loff_t *pos)
{
	struct shrinker *shrinker = (struct shrinker *)file->private_data;
	unsigned long nr_to_scan, ino;
	struct mem_cgroup *memcg;
	char kbuf[48];
	int read_len = size < (sizeof(kbuf) - 1) ? size : (sizeof(kbuf) - 1);
	ssize_t ret;

	if (copy_from_user(kbuf, buf, read_len))
		return -EFAULT;
	kbuf[read_len] = '\0';

	if (sscanf(kbuf, "%lu %lu", &ino, &nr_to_scan) < 2)
		return -EINVAL;

	memcg = mem_cgroup_get_from_ino(ino);
	if (!memcg || IS_ERR(memcg))
		return -ENOENT;

	if (!mem_cgroup_online(memcg)) {
		mem_cgroup_put(memcg);
		return -ENOENT;
	}

	ret = shrinker_scan_objects(shrinker, memcg, nr_to_scan);
	mem_cgroup_put(memcg);

	return ret ? ret : size;
}

static const struct file_operations shrinker_debugfs_scan_memcg_fops = {
	.owner	 = THIS_MODULE,
	.open	 = shrinker_debugfs_scan_open,
	.write	 = shrinker_debugfs_scan_memcg_write,
};
#endif

#ifdef CONFIG_NUMA
static int shrinker_debugfs_count_node_show(struct seq_file *m, void *v)
{
	struct shrinker *shrinker = (struct shrinker *)m->private;
	unsigned long nr;
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

		seq_printf(m, "%s%lu", nid ? " " : "", nr);
		cond_resched();
	}
	up_read(&shrinker_rwsem);
	seq_puts(m, "\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(shrinker_debugfs_count_node);

static ssize_t shrinker_debugfs_scan_node_write(struct file *file,
						const char __user *buf,
						size_t size, loff_t *pos)
{
	struct shrinker *shrinker = (struct shrinker *)file->private_data;
	unsigned long nr_to_scan = 0;
	int nid;
	struct shrink_control sc = {
		.gfp_mask = GFP_KERNEL,
	};
	char kbuf[48];
	int read_len = size < (sizeof(kbuf) - 1) ? size : (sizeof(kbuf) - 1);
	ssize_t ret;

	if (copy_from_user(kbuf, buf, read_len))
		return -EFAULT;
	kbuf[read_len] = '\0';

	if (sscanf(kbuf, "%d %lu", &nid, &nr_to_scan) < 2)
		return -EINVAL;

	if (nid < 0 || nid >= nr_node_ids)
		return -EINVAL;

	ret = down_read_killable(&shrinker_rwsem);
	if (ret)
		return ret;

	sc.nid = nid;
	sc.nr_to_scan = nr_to_scan;
	sc.nr_scanned = nr_to_scan;

	shrinker->scan_objects(shrinker, &sc);

	up_read(&shrinker_rwsem);

	return ret ? ret : size;
}

static const struct file_operations shrinker_debugfs_scan_node_fops = {
	.owner	 = THIS_MODULE,
	.open	 = shrinker_debugfs_scan_open,
	.write	 = shrinker_debugfs_scan_node_write,
};

#ifdef CONFIG_MEMCG
static int shrinker_debugfs_count_memcg_node_show(struct seq_file *m, void *v)
{
	struct shrinker *shrinker = (struct shrinker *)m->private;
	unsigned long *count_per_node = NULL;
	struct mem_cgroup *memcg;
	unsigned long total;
	int ret, nid;

	count_per_node = kcalloc(nr_node_ids, sizeof(unsigned long), GFP_KERNEL);
	if (!count_per_node)
		return -ENOMEM;

	ret = down_read_killable(&shrinker_rwsem);
	if (ret) {
		kfree(count_per_node);
		return ret;
	}
	rcu_read_lock();

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		if (!mem_cgroup_online(memcg))
			continue;

		total = shrinker_count_objects(shrinker, memcg, count_per_node);
		if (!total)
			continue;

		seq_printf(m, "%lu", mem_cgroup_ino(memcg));
		for_each_node(nid)
			seq_printf(m, " %lu", count_per_node[nid]);
		seq_puts(m, "\n");
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);

	rcu_read_unlock();
	up_read(&shrinker_rwsem);

	kfree(count_per_node);
	return ret;
}
DEFINE_SHOW_ATTRIBUTE(shrinker_debugfs_count_memcg_node);

static ssize_t shrinker_debugfs_scan_memcg_node_write(struct file *file,
						      const char __user *buf,
						      size_t size, loff_t *pos)
{
	struct shrinker *shrinker = (struct shrinker *)file->private_data;
	unsigned long nr_to_scan = 0, ino;
	struct shrink_control sc = {
		.gfp_mask = GFP_KERNEL,
	};
	struct mem_cgroup *memcg;
	int nid;
	char kbuf[72];
	int read_len = size < (sizeof(kbuf) - 1) ? size : (sizeof(kbuf) - 1);
	ssize_t ret;

	if (copy_from_user(kbuf, buf, read_len))
		return -EFAULT;
	kbuf[read_len] = '\0';

	if (sscanf(kbuf, "%lu %d %lu", &ino, &nid, &nr_to_scan) < 2)
		return -EINVAL;

	if (nid < 0 || nid >= nr_node_ids)
		return -EINVAL;

	memcg = mem_cgroup_get_from_ino(ino);
	if (!memcg || IS_ERR(memcg))
		return -ENOENT;

	if (!mem_cgroup_online(memcg)) {
		mem_cgroup_put(memcg);
		return -ENOENT;
	}

	ret = down_read_killable(&shrinker_rwsem);
	if (ret) {
		mem_cgroup_put(memcg);
		return ret;
	}

	sc.nid = nid;
	sc.memcg = memcg;
	sc.nr_to_scan = nr_to_scan;
	sc.nr_scanned = nr_to_scan;

	shrinker->scan_objects(shrinker, &sc);

	up_read(&shrinker_rwsem);
	mem_cgroup_put(memcg);

	return ret ? ret : size;
}

static const struct file_operations shrinker_debugfs_scan_memcg_node_fops = {
	.owner	 = THIS_MODULE,
	.open	 = shrinker_debugfs_scan_open,
	.write	 = shrinker_debugfs_scan_memcg_node_write,
};
#endif /* CONFIG_MEMCG */
#endif /* CONFIG_NUMA */

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

	snprintf(buf, sizeof(buf), "%s-%d", shrinker->name, id);

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

#ifdef CONFIG_MEMCG
	/* create memcg interfaces */
	if (shrinker->flags & SHRINKER_MEMCG_AWARE) {
		debugfs_create_file("count_memcg", 0220, entry, shrinker,
				    &shrinker_debugfs_count_memcg_fops);
		debugfs_create_file("scan_memcg", 0440, entry, shrinker,
				    &shrinker_debugfs_scan_memcg_fops);
	}
#endif

#ifdef CONFIG_NUMA
	/* create numa and memcg/numa interfaces */
	if ((shrinker->flags & SHRINKER_NUMA_AWARE) && nr_node_ids > 1) {
		debugfs_create_file("count_node", 0220, entry, shrinker,
				    &shrinker_debugfs_count_node_fops);
		debugfs_create_file("scan_node", 0440, entry, shrinker,
				    &shrinker_debugfs_scan_node_fops);

#ifdef CONFIG_MEMCG
		if (shrinker->flags & SHRINKER_MEMCG_AWARE) {
			debugfs_create_file("count_memcg_node", 0220, entry,
					    shrinker,
					    &shrinker_debugfs_count_memcg_node_fops);
			debugfs_create_file("scan_memcg_node", 0440, entry,
					    shrinker,
					    &shrinker_debugfs_scan_memcg_node_fops);
		}
#endif /* CONFIG_MEMCG */
	}
#endif /* CONFIG_NUMA */

	/* shrinker->name is not needed anymore, free it */
	kfree(shrinker->name);
	shrinker->name = NULL;

	return 0;
}

void shrinker_debugfs_remove(struct shrinker *shrinker)
{
	lockdep_assert_held(&shrinker_rwsem);

	if (!shrinker->debugfs_entry)
		return;

	debugfs_remove_recursive(shrinker->debugfs_entry);
	ida_free(&shrinker_debugfs_ida, shrinker->debugfs_id);
	WARN_ON_ONCE(shrinker->name);
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
