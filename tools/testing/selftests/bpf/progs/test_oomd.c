// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define OOM_SCORE_ADJ_MIN	(-1000)

enum oomd_preference {
	OOMD_PREFERENCE_NONE,
	OOMD_PREFERENCE_AVOID,
	OOMD_PREFERENCE_OMIT,
};

struct oomd_policy {
	__u8 preference;
	__u8 recursive_kill;
	__u8 _pad[6];
	__u64 last_pgscan;
};

struct oomd_decision {
	__u64 root_cgid;
	__u64 victim_cgid;
	__u64 victim_usage;
	__u64 victim_pgscan;
	__u64 victim_pgscan_delta;
	__u64 victim_swap_usage;
	__u64 killed_pid;
	__u64 scanned_candidates;
	__u64 skipped_omit;
	__u64 skipped_unkillable;
	__s32 kill_ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u64);
	__type(value, struct oomd_policy);
} oomd_policies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct oomd_decision);
} oomd_decisions SEC(".maps");

static __u64 cgroup_id(struct cgroup *cgrp)
{
	return BPF_CORE_READ(cgrp, kn, id);
}

static bool mem_cgroup_killable(struct mem_cgroup *memcg)
{
	struct task_struct *task;

	bpf_for_each(css_task, task, &memcg->css, CSS_TASK_ITER_PROCS)
		if (task->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
			return false;

	return true;
}

static __u64 memcg_pgscan(struct mem_cgroup *memcg)
{
	return bpf_mem_cgroup_page_state(
		       memcg,
		       bpf_core_enum_value(enum node_stat_item, PGSCAN_KSWAPD)) +
	       bpf_mem_cgroup_page_state(
		       memcg,
		       bpf_core_enum_value(enum node_stat_item, PGSCAN_DIRECT)) +
	       bpf_mem_cgroup_page_state(
		       memcg,
		       bpf_core_enum_value(enum node_stat_item, PGSCAN_KHUGEPAGED)) +
	       bpf_mem_cgroup_page_state(
		       memcg,
		       bpf_core_enum_value(enum node_stat_item, PGSCAN_PROACTIVE));
}

static __u64 oomd_pgscan_delta(struct oomd_policy *policy, __u64 pgscan)
{
	__u64 last_pgscan = 0;

	if (policy) {
		last_pgscan = policy->last_pgscan;
		policy->last_pgscan = pgscan;
	}

	if (last_pgscan > pgscan)
		last_pgscan = 0;

	return pgscan - last_pgscan;
}

static bool oomd_better_candidate(__u8 preference, __u64 pgscan_delta,
				  __u64 usage, __u8 best_preference,
				  __u64 best_pgscan_delta, __u64 best_usage,
				  bool have_best)
{
	if (!have_best)
		return true;

	if (preference != best_preference) {
		if (preference == OOMD_PREFERENCE_AVOID)
			return false;
		if (best_preference == OOMD_PREFERENCE_AVOID)
			return true;
	}

	if (pgscan_delta != best_pgscan_delta)
		return pgscan_delta > best_pgscan_delta;

	return usage > best_usage;
}

static int oomd_kill_task(struct oom_control *oc, struct task_struct *task,
			  struct oomd_decision *decision)
{
	struct task_struct *t;
	int ret;

	t = bpf_task_acquire(task);
	if (!t)
		return 0;

	if (bpf_task_is_oom_victim(task)) {
		decision->killed_pid = task->pid;
		bpf_task_release(t);
		return 1;
	}

	ret = bpf_oom_kill_process(oc, task, "bpf systemd-oomd policy");
	decision->kill_ret = ret;
	if (!ret)
		decision->killed_pid = task->pid;

	bpf_task_release(t);
	return ret ? 0 : 1;
}

static int oomd_kill_memcg(struct oom_control *oc, struct mem_cgroup *victim,
			   struct oomd_decision *decision)
{
	struct task_struct *task;

	bpf_for_each(css_task, task, &victim->css, CSS_TASK_ITER_PROCS)
		if (oomd_kill_task(oc, task, decision))
			return 1;

	return 0;
}

/*
 * A systemd-oomd-style OOM policy:
 *
 * - candidates are leaf cgroups, or cgroups marked with memory.oom.group;
 * - user-space-only systemd inputs such as ManagedOOMPreference/xattrs are
 *   supplied through oomd_policies, keyed by cgroup id;
 * - "omit" cgroups are ignored and "avoid" cgroups are ranked last;
 * - the primary score is memory.stat pgscan delta, with memory.current as the
 *   tie breaker;
 * - when memory.oom.group is set, bpf_oom_kill_process() delegates recursive
 *   group kill semantics to the kernel OOM killer for the selected task;
 * - at hard OOM we still allow the memory.current tie breaker to select a
 *   victim when all pgscan deltas are zero, so the kernel can make progress.
 */
SEC("struct_ops.s/handle_out_of_memory")
int BPF_PROG(test_oomd_out_of_memory, struct oom_control *oc,
	     struct cgroup *attached_cgrp)
{
	struct mem_cgroup *root_memcg = oc->memcg;
	struct mem_cgroup *memcg, *victim = NULL;
	struct cgroup_subsys_state *css_pos, *css;
	struct oomd_decision *decision;
	__u8 preference, best_preference = OOMD_PREFERENCE_NONE;
	__u64 usage, pgscan, delta, swap_usage, cgid;
	__u64 best_usage = 0, best_delta = 0;
	struct oomd_policy *policy;
	bool have_best = false;
	__u32 zero = 0;
	int ret = 0;

	decision = bpf_map_lookup_elem(&oomd_decisions, &zero);
	if (decision)
		__builtin_memset(decision, 0, sizeof(*decision));

	if (root_memcg)
		root_memcg = bpf_get_mem_cgroup(&root_memcg->css);
	else
		root_memcg = bpf_get_root_mem_cgroup();

	if (!root_memcg)
		return 0;

	css = &root_memcg->css;
	if (css && css->cgroup == attached_cgrp)
		goto out_put_root;

	if (decision)
		decision->root_cgid = cgroup_id(css->cgroup);

	bpf_rcu_read_lock();
	bpf_for_each(css, css_pos, &root_memcg->css,
		     BPF_CGROUP_ITER_DESCENDANTS_POST) {
		struct cgroup *cgrp = css_pos->cgroup;
		bool is_leaf, is_oom_group;

		is_leaf = !(cgrp->nr_descendants + cgrp->nr_dying_descendants);

		memcg = bpf_get_mem_cgroup(css_pos);
		if (!memcg)
			continue;

		is_oom_group = BPF_CORE_READ(memcg, oom_group);
		if (!is_leaf && !is_oom_group) {
			bpf_put_mem_cgroup(memcg);
			continue;
		}

		cgid = cgroup_id(cgrp);
		policy = bpf_map_lookup_elem(&oomd_policies, &cgid);
		preference = policy ? policy->preference : OOMD_PREFERENCE_NONE;

		if (preference == OOMD_PREFERENCE_OMIT) {
			if (decision)
				decision->skipped_omit++;
			bpf_put_mem_cgroup(memcg);
			continue;
		}

		if (!mem_cgroup_killable(memcg)) {
			if (decision)
				decision->skipped_unkillable++;
			bpf_put_mem_cgroup(memcg);
			continue;
		}

		usage = bpf_mem_cgroup_usage(memcg);
		pgscan = memcg_pgscan(memcg);
		delta = oomd_pgscan_delta(policy, pgscan);
		swap_usage = bpf_mem_cgroup_page_state(
			memcg,
			bpf_core_enum_value(enum memcg_stat_item, MEMCG_SWAP));

		if (decision)
			decision->scanned_candidates++;

		if (pgscan == 0 && usage == 0) {
			bpf_put_mem_cgroup(memcg);
			continue;
		}

		if (oomd_better_candidate(preference, delta, usage,
					  best_preference, best_delta,
					  best_usage, have_best)) {
			best_preference = preference;
			best_delta = delta;
			best_usage = usage;
			have_best = true;

			if (victim)
				bpf_put_mem_cgroup(victim);
			victim = bpf_get_mem_cgroup(&memcg->css);

			if (decision) {
				decision->victim_cgid = cgid;
				decision->victim_usage = usage;
				decision->victim_pgscan = pgscan;
				decision->victim_pgscan_delta = delta;
				decision->victim_swap_usage = swap_usage;
			}
		}

		bpf_put_mem_cgroup(memcg);
	}
	bpf_rcu_read_unlock();

	if (victim) {
		ret = oomd_kill_memcg(oc, victim, decision);
		bpf_put_mem_cgroup(victim);
	}

out_put_root:
	bpf_put_mem_cgroup(root_memcg);
	return ret;
}

SEC(".struct_ops.link")
struct bpf_oom_ops test_bpf_oomd = {
	.name = "bpf_systemd_oomd_policy",
	.handle_out_of_memory = (void *)test_oomd_out_of_memory,
};
