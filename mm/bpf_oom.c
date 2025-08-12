// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BPF-driven OOM killer customization
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/bpf.h>
#include <linux/oom.h>
#include <linux/bpf_oom.h>
#include <linux/bpf-cgroup.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/uaccess.h>

static int bpf_ops_handle_oom(struct bpf_oom_ops *bpf_oom_ops,
			      struct cgroup *cgrp,
			      struct oom_control *oc)
{
	int ret;

	oc->bpf_handler_name = &bpf_oom_ops->name[0];
	oc->bpf_memory_freed = false;
	pagefault_disable();
	ret = bpf_oom_ops->handle_out_of_memory(oc, cgrp);
	pagefault_enable();
	oc->bpf_handler_name = NULL;

	return ret;
}

bool bpf_handle_oom(struct oom_control *oc)
{
	const struct bpf_prog_array_item *item;
	struct bpf_oom_ops *bpf_oom_ops;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	int ret = 0;

	if (!cgroup_bpf_enabled(CGROUP_OOM_OPS))
		return false;

	/*
	 * System-wide OOMs are handled by the struct ops attached
	 * to the root memory cgroup
	 */
	memcg = oc->memcg ? oc->memcg : root_mem_cgroup;
	cgrp = memcg->css.cgroup;

	rcu_read_lock_trace();

	bpf_cgroup_struct_ops_foreach(bpf_oom_ops, item, cgrp, CGROUP_OOM_OPS) {
		ret = bpf_ops_handle_oom(bpf_oom_ops, item->cgroup, oc);
		if (ret && oc->bpf_memory_freed)
			break;
		ret = 0;
	}

	rcu_read_unlock_trace();

	return ret && oc->bpf_memory_freed;
}

static int __handle_out_of_memory(struct oom_control *oc,
				  struct cgroup *cgrp)
{
	return 0;
}

static struct bpf_oom_ops __bpf_oom_ops = {
	.handle_out_of_memory = __handle_out_of_memory,
};

static const struct bpf_func_proto *
bpf_oom_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return tracing_prog_func_proto(func_id, prog);
}

static bool bpf_oom_ops_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_oom_verifier_ops = {
	.get_func_proto = bpf_oom_func_proto,
	.is_valid_access = bpf_oom_ops_is_valid_access,
};

static int bpf_oom_ops_check_member(const struct btf_type *t,
				    const struct btf_member *member,
				    const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_oom_ops, handle_out_of_memory):
		if (!prog)
			return -EINVAL;
		break;
	}

	return 0;
}

static int bpf_oom_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct bpf_oom_ops *uops = udata;
	struct bpf_oom_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_oom_ops, name):
		if (uops->name[0])
			strscpy_pad(ops->name, uops->name, sizeof(ops->name));
		else
			strscpy_pad(ops->name, "bpf_defined_policy");
		return 1;
	}
	return 0;
}

static int bpf_oom_ops_init(struct btf *btf)
{
	return 0;
}

static struct bpf_struct_ops bpf_oom_bpf_ops = {
	.verifier_ops = &bpf_oom_verifier_ops,
	.check_member = bpf_oom_ops_check_member,
	.init_member = bpf_oom_ops_init_member,
	.init = bpf_oom_ops_init,
	.name = "bpf_oom_ops",
	.cgroup_atype = CGROUP_OOM_OPS,
	.owner = THIS_MODULE,
	.cfi_stubs = &__bpf_oom_ops,
	.free_after_mult_rcu_gp = true,
};

static int __init bpf_oom_struct_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_oom_bpf_ops, bpf_oom_ops);
}
late_initcall(bpf_oom_struct_ops_init);
