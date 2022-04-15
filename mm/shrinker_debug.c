// SPDX-License-Identifier: GPL-2.0
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/shrinker.h>
#include <linux/memcontrol.h>

/* defined in vmscan.c */
extern struct rw_semaphore shrinker_rwsem;
extern struct list_head shrinker_list;

static DEFINE_IDA(shrinker_sysfs_ida);

struct shrinker_kobj {
	struct kobject kobj;
	struct shrinker *shrinker;
	int id;
};

struct shrinker_attribute {
	struct attribute attr;
	ssize_t (*show)(struct shrinker_kobj *skobj,
			struct shrinker_attribute *attr, char *buf);
	ssize_t (*store)(struct shrinker_kobj *skobj,
			 struct shrinker_attribute *attr, const char *buf,
			 size_t count);
	unsigned long private;
};

#define to_shrinker_kobj(x) container_of(x, struct shrinker_kobj, kobj)
#define to_shrinker_attr(x) container_of(x, struct shrinker_attribute, attr)

static ssize_t shrinker_attr_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct shrinker_attribute *attribute = to_shrinker_attr(attr);
	struct shrinker_kobj *skobj = to_shrinker_kobj(kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(skobj, attribute, buf);
}

static ssize_t shrinker_attr_store(struct kobject *kobj, struct attribute *attr,
				   const char *buf, size_t len)
{
	struct shrinker_attribute *attribute = to_shrinker_attr(attr);
	struct shrinker_kobj *skobj = to_shrinker_kobj(kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(skobj, attribute, buf, len);
}

static const struct sysfs_ops shrinker_sysfs_ops = {
	.show = shrinker_attr_show,
	.store = shrinker_attr_store,
};

static void shrinker_kobj_release(struct kobject *kobj)
{
	struct shrinker_kobj *skobj = to_shrinker_kobj(kobj);

	WARN_ON(skobj->shrinker);
	kfree(skobj);
}

static ssize_t count_show(struct shrinker_kobj *skobj,
			  struct shrinker_attribute *attr, char *buf)
{
	unsigned long nr, total = 0;
	struct shrinker *shrinker;
	int nid;

	down_read(&shrinker_rwsem);

	shrinker = skobj->shrinker;
	if (!shrinker) {
		up_read(&shrinker_rwsem);
		return -EBUSY;
	}

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
	return sprintf(buf, "%lu\n", total);
}

static struct shrinker_attribute count_attribute = __ATTR_RO(count);

static ssize_t scan_show(struct shrinker_kobj *skobj,
			 struct shrinker_attribute *attr, char *buf)
{
	/*
	 * Display the number of objects freed on the last scan.
	 */
	return sprintf(buf, "%lu\n", attr->private);
}

static ssize_t scan_store(struct shrinker_kobj *skobj,
			  struct shrinker_attribute *attr,
			  const char *buf, size_t size)
{
	unsigned long nr, total = 0, nr_to_scan = 0, freed = 0;
	unsigned long *count_per_node = NULL;
	struct shrinker *shrinker;
	ssize_t ret = size;
	int nid;

	if (kstrtoul(buf, 10, &nr_to_scan))
		return -EINVAL;

	down_read(&shrinker_rwsem);

	shrinker = skobj->shrinker;
	if (!shrinker) {
		ret = -EBUSY;
		goto out;
	}

	if (shrinker->flags & SHRINKER_NUMA_AWARE) {
		/*
		 * If the shrinker is numa aware, distribute nr_to_scan
		 * proportionally.
		 */
		count_per_node = kzalloc(sizeof(unsigned long) * nr_node_ids,
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
		if (nr == SHRINK_STOP || nr == SHRINK_EMPTY)
			nr = 0;

		freed += nr;

		if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
			break;

		cond_resched();

	}
	attr->private = freed;
out:
	up_read(&shrinker_rwsem);
	kfree(count_per_node);
	return ret;
}

static struct shrinker_attribute scan_attribute = __ATTR_RW(scan);

static struct attribute *shrinker_default_attrs[] = {
	&count_attribute.attr,
	&scan_attribute.attr,
	NULL,
};

static const struct attribute_group shrinker_default_group = {
	.attrs = shrinker_default_attrs,
};

#ifdef CONFIG_MEMCG
static ssize_t count_memcg_show(struct shrinker_kobj *skobj,
				struct shrinker_attribute *attr, char *buf)
{
	unsigned long nr, total;
	struct shrinker *shrinker;
	struct mem_cgroup *memcg;
	ssize_t ret = 0;
	int nid;

	down_read(&shrinker_rwsem);
	rcu_read_lock();

	shrinker = skobj->shrinker;
	if (!shrinker) {
		ret = -EBUSY;
		goto out;
	}

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		if (!mem_cgroup_online(memcg))
			continue;

		/*
		 * Display a PAGE_SIZE of data, reserve last 50 characters
		 * for "...".
		 */
		if (ret > PAGE_SIZE - 50) {
			ret += sprintf(buf + ret, "...\n");
			mem_cgroup_iter_break(NULL, memcg);
			break;
		}

		total = 0;
		for_each_node(nid) {
			struct shrink_control sc = {
				.gfp_mask = GFP_KERNEL,
				.nid = nid,
				.memcg = memcg,
			};

			nr = shrinker->count_objects(shrinker, &sc);
			if (nr == SHRINK_EMPTY)
				nr = 0;
			total += nr;

			if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
				break;

			cond_resched();
		}

		if (!total || total < attr->private)
			continue;

		ret += sprintf(buf + ret, "%lu %lu\n", mem_cgroup_ino(memcg),
			       total);

		cond_resched();
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);
out:
	rcu_read_unlock();
	up_read(&shrinker_rwsem);
	return ret;
}

static ssize_t count_memcg_store(struct shrinker_kobj *skobj,
				 struct shrinker_attribute *attr,
				 const char *buf, size_t size)
{
	unsigned long min_count;

	if (kstrtoul(buf, 10, &min_count))
		return -EINVAL;

	attr->private = min_count;

	return size;
}

static struct shrinker_attribute count_memcg_attribute = __ATTR_RW(count_memcg);

static ssize_t scan_memcg_show(struct shrinker_kobj *skobj,
			       struct shrinker_attribute *attr, char *buf)
{
	/*
	 * Display the number of objects freed on the last scan.
	 */
	return sprintf(buf, "%lu\n", attr->private);
}

static ssize_t scan_memcg_store(struct shrinker_kobj *skobj,
			  struct shrinker_attribute *attr,
			  const char *buf, size_t size)
{
	unsigned long nr, nr_to_scan = 0, freed = 0, total = 0, ino;
	unsigned long *count_per_node = NULL;
	struct mem_cgroup *memcg;
	struct shrinker *shrinker;
	ssize_t ret = size;
	int nid;

	if (sscanf(buf, "%lu %lu", &ino, &nr_to_scan) < 2)
		return -EINVAL;

	memcg = mem_cgroup_get_from_ino(ino);
	if (!memcg || IS_ERR(memcg))
		return -ENOENT;

	if (!mem_cgroup_online(memcg)) {
		mem_cgroup_put(memcg);
		return -ENOENT;
	}

	down_read(&shrinker_rwsem);

	shrinker = skobj->shrinker;
	if (!shrinker) {
		ret = -EBUSY;
		goto out;
	}

	if (shrinker->flags & SHRINKER_NUMA_AWARE) {
		count_per_node = kzalloc(sizeof(unsigned long) * nr_node_ids,
					GFP_KERNEL);
		if (!count_per_node) {
			ret = -ENOMEM;
			goto out;
		}

		for_each_node(nid) {
			struct shrink_control sc = {
				.gfp_mask = GFP_KERNEL,
				.nid = nid,
				.memcg = memcg,
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
			.memcg = memcg,
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
		if (nr == SHRINK_STOP || nr == SHRINK_EMPTY)
			nr = 0;

		freed += nr;

		if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
			break;

		cond_resched();
	}
	attr->private = freed;
out:
	up_read(&shrinker_rwsem);
	mem_cgroup_put(memcg);
	kfree(count_per_node);
	return ret;
}

static struct shrinker_attribute scan_memcg_attribute = __ATTR_RW(scan_memcg);

static struct attribute *shrinker_memcg_attrs[] = {
	&count_memcg_attribute.attr,
	&scan_memcg_attribute.attr,
	NULL,
};

static umode_t memcg_attrs_visible(struct kobject *kobj, struct attribute *attr,
				   int i)
{
	struct shrinker_kobj *skobj = to_shrinker_kobj(kobj);
	struct shrinker *shrinker;
	int ret = 0;

	lockdep_assert_held(&shrinker_rwsem);

	shrinker = skobj->shrinker;
	if (shrinker && (shrinker->flags & SHRINKER_MEMCG_AWARE))
		ret = 0644;

	return ret;
}

static const struct attribute_group shrinker_memcg_group = {
	.attrs = shrinker_memcg_attrs,
	.is_visible = memcg_attrs_visible,
};
#endif /* CONFIG_MEMCG */
static const struct attribute_group *shrinker_sysfs_groups[] = {
	&shrinker_default_group,
#ifdef CONFIG_MEMCG
	&shrinker_memcg_group,
#endif
	NULL,
};

static struct kobj_type shrinker_ktype = {
	.sysfs_ops = &shrinker_sysfs_ops,
	.release = shrinker_kobj_release,
	.default_groups = shrinker_sysfs_groups,
};

static struct kset *shrinker_kset;

int shrinker_init_kobj(struct shrinker *shrinker)
{
	struct shrinker_kobj *skobj;
	int ret = 0;
	int id;

	/* Sysfs isn't initialize yet, allocate kobjects later. */
	if (!shrinker_kset)
		return 0;

	skobj = kzalloc(sizeof(struct shrinker_kobj), GFP_KERNEL);
	if (!skobj)
		return -ENOMEM;

	id = ida_alloc(&shrinker_sysfs_ida, GFP_KERNEL);
	if (id < 0) {
		kfree(skobj);
		return id;
	}

	skobj->id = id;
	skobj->kobj.kset = shrinker_kset;
	skobj->shrinker = shrinker;
	ret = kobject_init_and_add(&skobj->kobj, &shrinker_ktype, NULL, "%d",
				   id);
	if (ret) {
		ida_free(&shrinker_sysfs_ida, id);
		kobject_put(&skobj->kobj);
		return ret;
	}

	shrinker->kobj = skobj;

	kobject_uevent(&skobj->kobj, KOBJ_ADD);

	return ret;
}

void shrinker_unlink_kobj(struct shrinker *shrinker)
{
	struct shrinker_kobj *skobj;

	if (!shrinker->kobj)
		return;

	skobj = shrinker->kobj;
	skobj->shrinker = NULL;
	ida_free(&shrinker_sysfs_ida, skobj->id);
	shrinker->kobj = NULL;

	kobject_put(&skobj->kobj);
}

static int __init shrinker_sysfs_init(void)
{
	struct shrinker *shrinker;
	int ret = 0;

	shrinker_kset = kset_create_and_add("shrinker", NULL, kernel_kobj);
	if (!shrinker_kset)
		return -ENOMEM;

	/* Create sysfs entries for shrinkers registered at boot */
	down_write(&shrinker_rwsem);
	list_for_each_entry(shrinker, &shrinker_list, list)
		if (!shrinker->kobj)
			ret = shrinker_init_kobj(shrinker);
	up_write(&shrinker_rwsem);

	return ret;
}
__initcall(shrinker_sysfs_init);
