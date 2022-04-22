==========================
Shrinker Debugfs Interface
==========================

Shrinker debugfs interface provides a visibility into the kernel memory
shrinkers subsystem and allows to get statistics and interact with
individual shrinkers.

For each shrinker registered in the system a directory in <debugfs>/shrinker/
is created. The directory is named like "kfree_rcu-0". Each name is composed
from the shrinker's name and an unique id.

Each shrinker directory contains "count" and "scan" files, which allow
to trigger count_objects() and scan_objects() callbacks. For memcg-aware
and numa-aware shrinkers count_memcg, scan_memcg, count_node, scan_node,
count_memcg_node and scan_memcg_node are additionally provided. They allow
to get per-memcg and/or per-node object count and shrink only a specific
memcg/node.

Usage examples:

 1. List registered shrinkers::
      $ cd /sys/kernel/debug/shrinker/
      $ ls
      dqcache-16          sb-cgroup2-30    sb-hugetlbfs-33  sb-proc-41       sb-selinuxfs-22  sb-tmpfs-40    sb-zsmalloc-19
      kfree_rcu-0         sb-configfs-23   sb-iomem-12      sb-proc-44       sb-sockfs-8      sb-tmpfs-42    shadow-18
      sb-aio-20           sb-dax-11        sb-mqueue-21     sb-proc-45       sb-sysfs-26      sb-tmpfs-43    thp_deferred_split-10
      sb-anon_inodefs-15  sb-debugfs-7     sb-nsfs-4        sb-proc-47       sb-tmpfs-1       sb-tmpfs-46    thp_zero-9
      sb-bdev-3           sb-devpts-28     sb-pipefs-14     sb-pstore-31     sb-tmpfs-27      sb-tmpfs-49    xfs_buf-37
      sb-bpf-32           sb-devtmpfs-5    sb-proc-25       sb-rootfs-2      sb-tmpfs-29      sb-tracefs-13  xfs_inodegc-38
      sb-btrfs-24         sb-hugetlbfs-17  sb-proc-39       sb-securityfs-6  sb-tmpfs-35      sb-xfs-36      zspool-34

 2. Get information about a specific shrinker::
      $ cd sb-btrfs-24/
      $ ls
      count  count_memcg  count_memcg_node  count_node  scan  scan_memcg  scan_memcg_node  scan_node

 3. Count objects on the system/root cgroup level::
      $ cat count
      212

 4. Count objects on the system/root cgroup level per numa node (on a 2-node machine)::
      $ cat count_node
      209 3

 5. Count objects for each memcg (output format: cgroup inode, count)::
      $ cat count_memcg
      1 212
      20 96
      53 817
      2297 2
      218 13
      581 30
      911 124
      ...

 6. Same but with a per-node output::
      $ cat count_memcg_node
      1 209 3
      20 96 0
      53 810 7
      2297 2 0
      218 13 0
      581 30 0
      911 124 0
      ...

 7. Scan system/root shrinker::
      $ cat count
      212
      $ echo 100 > scan
      $ cat scan
      97
      $ cat count
      115

 8. Scan individual memcg::
      $ echo "1868 500" > scan_memcg
      $ cat scan_memcg
      193

 9. Scan individual node::
      $ echo "1 200" > scan_node
      $ cat scan_node
      2

 10. Scan individual memcg and node::
     $ echo "1868 0 500" > scan_memcg_node
     $ cat scan_memcg_node
     435
