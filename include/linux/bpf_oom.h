/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __BPF_OOM_H
#define __BPF_OOM_H

struct cgroup;
struct oom_control;

#define BPF_OOM_NAME_MAX_LEN 64

struct bpf_oom_ops {
	/**
	 * @handle_out_of_memory: Out of memory bpf handler, called before
	 * the in-kernel OOM killer.
	 * @oc: OOM control structure
	 * @cgrp: cgroup where this OOM policy is attached
	 *
	 * Should return 1 if some memory was freed up, otherwise
	 * the in-kernel OOM killer is invoked.
	 */
	int (*handle_out_of_memory)(struct oom_control *oc,
				    struct cgroup *cgrp);

	/**
	 * @name: BPF OOM policy name
	 */
	char name[BPF_OOM_NAME_MAX_LEN];
};

#ifdef CONFIG_CGROUP_BPF
/**
 * @bpf_handle_oom: handle out of memory condition using bpf
 * @oc: OOM control structure
 *
 * Returns true if some memory was freed.
 */
bool bpf_handle_oom(struct oom_control *oc);

#else /* CONFIG_CGROUP_BPF */
static inline bool bpf_handle_oom(struct oom_control *oc)
{
	return false;
}

#endif /* CONFIG_CGROUP_BPF */

#endif /* __BPF_OOM_H */
