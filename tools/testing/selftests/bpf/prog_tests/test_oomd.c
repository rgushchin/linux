// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "cgroup_helpers.h"
#include "test_oomd.skel.h"

#define MB (1024 * 1024)
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

struct oomd_cgroup_desc {
	const char *path;
	int fd;
	unsigned long long id;
	int pid;
	size_t target;
	size_t max;
	int oom_score_adj;
	enum oomd_preference preference;
	bool victim;
};

static struct oomd_cgroup_desc cgroups[] = {
	{ .path = "/oomd_test", .max = 80 * MB },
	{ .path = "/oomd_test/system.slice" },
	{ .path = "/oomd_test/system.slice/critical.service",
	  .target = 34 * MB, .preference = OOMD_PREFERENCE_OMIT },
	{ .path = "/oomd_test/workload.slice" },
	{ .path = "/oomd_test/workload.slice/batch-a.service",
	  .target = 46 * MB, .preference = OOMD_PREFERENCE_AVOID },
	{ .path = "/oomd_test/workload.slice/batch-b.service",
	  .target = 30 * MB, .victim = true },
	{ .path = "/oomd_test/workload.slice/batch-c.service",
	  .target = 22 * MB },
	{ .path = "/oomd_test/workload.slice/unkillable.service",
	  .target = 26 * MB, .oom_score_adj = OOM_SCORE_ADJ_MIN },
};

static int spawn_task(struct oomd_cgroup_desc *desc)
{
	char *ptr;
	int pid;

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid > 0) {
		desc->pid = pid;
		return 0;
	}

	if (desc->oom_score_adj) {
		char buf[64];
		int fd = open("/proc/self/oom_score_adj", O_WRONLY);

		if (fd < 0)
			exit(1);

		snprintf(buf, sizeof(buf), "%d", desc->oom_score_adj);
		if (write(fd, buf, strlen(buf)) < 0)
			exit(1);
		close(fd);
	}

	ptr = malloc(desc->target);
	if (!ptr)
		exit(1);

	memset(ptr, 'a', desc->target);

	for (;;)
		sleep(1000);
}

static int setup_environment(void)
{
	int i, err;

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		return err;

	for (i = 0; i < ARRAY_SIZE(cgroups); i++) {
		cgroups[i].fd = create_and_get_cgroup(cgroups[i].path);
		if (!ASSERT_GE(cgroups[i].fd, 0, "create_and_get_cgroup"))
			return -errno;

		cgroups[i].id = get_cgroup_id(cgroups[i].path);
		if (!ASSERT_GT(cgroups[i].id, 0, "get_cgroup_id"))
			return -EINVAL;

		if (i == 0) {
			err = write_cgroup_file(cgroups[i].path,
						"cgroup.freeze", "1");
			if (!ASSERT_OK(err, "freeze cgroup"))
				return err;
		}

		if (!cgroups[i].target) {
			err = write_cgroup_file(cgroups[i].path,
						"cgroup.subtree_control",
						"+memory");
			if (!ASSERT_OK(err, "enable memory controller"))
				return err;
		}

		if (cgroups[i].max) {
			char buf[64];

			snprintf(buf, sizeof(buf), "%zu", cgroups[i].max);
			err = write_cgroup_file(cgroups[i].path,
						"memory.max", buf);
			if (!ASSERT_OK(err, "set memory.max"))
				return err;

			err = write_cgroup_file(cgroups[i].path,
						"memory.swap.max", "0");
			if (!ASSERT_OK(err, "disable swap"))
				return err;
		}

		if (cgroups[i].target) {
			char buf[64];

			err = spawn_task(&cgroups[i]);
			if (!ASSERT_OK(err, "spawn task"))
				return err;

			snprintf(buf, sizeof(buf), "%d", cgroups[i].pid);
			err = write_cgroup_file(cgroups[i].path,
						"cgroup.procs", buf);
			if (!ASSERT_OK(err, "put child into cgroup"))
				return err;
		}
	}

	return 0;
}

static int configure_policies(struct test_oomd *skel)
{
	int i, err, fd = bpf_map__fd(skel->maps.oomd_policies);

	for (i = 0; i < ARRAY_SIZE(cgroups); i++) {
		struct oomd_policy policy = {
			.preference = cgroups[i].preference,
		};
		__u64 id = cgroups[i].id;

		err = bpf_map_update_elem(fd, &id, &policy, BPF_ANY);
		if (!ASSERT_OK(err, "configure oomd policy"))
			return err;
	}

	return 0;
}

static int run_and_wait_for_oom(struct test_oomd *skel)
{
	int ret = -1, decision_fd, i;
	struct oomd_decision decision;
	bool first = true;
	__u32 zero = 0;

	ret = write_cgroup_file(cgroups[0].path, "cgroup.freeze", "0");
	if (!ASSERT_OK(ret, "unfreeze cgroup"))
		return -1;

	for (;;) {
		int status;
		pid_t pid = wait(&status);

		if (pid == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (!first)
			continue;

		first = false;
		ret = 0;

		for (i = 0; i < ARRAY_SIZE(cgroups); i++) {
			if (!ASSERT_EQ(cgroups[i].victim,
				       pid == cgroups[i].pid,
				       "correct process was killed")) {
				ret = -1;
				break;
			}
		}

		decision_fd = bpf_map__fd(skel->maps.oomd_decisions);
		if (bpf_map_lookup_elem(decision_fd, &zero, &decision)) {
			ASSERT_OK(-errno, "lookup oomd decision");
			ret = -1;
		} else {
			if (!ASSERT_EQ(decision.victim_cgid,
				       cgroups[5].id,
				       "selected victim cgroup"))
				ret = -1;
			if (!ASSERT_EQ(decision.killed_pid,
				       (__u64)cgroups[5].pid,
				       "selected victim task"))
				ret = -1;
			if (!ASSERT_GT(decision.scanned_candidates, 0,
				       "scanned candidates"))
				ret = -1;
			if (!ASSERT_GT(decision.skipped_omit, 0,
				       "skipped omitted cgroup"))
				ret = -1;
			if (!ASSERT_GT(decision.skipped_unkillable, 0,
				       "skipped unkillable cgroup"))
				ret = -1;
			if (!ASSERT_OK(decision.kill_ret, "bpf oom kill"))
				ret = -1;
		}

		for (i = 0; i < ARRAY_SIZE(cgroups); i++)
			if (cgroups[i].pid && cgroups[i].pid != pid)
				kill(cgroups[i].pid, SIGKILL);
	}

	return ret;
}

void test_oomd(void)
{
	LIBBPF_OPTS(bpf_cgroup_opts, opts);
	struct bpf_link *link = NULL, *root_link = NULL;
	struct test_oomd *skel;
	int err, root_fd = -1;

	err = setup_environment();
	if (err)
		goto cleanup_cgroup;

	skel = test_oomd__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup_cgroup;

	err = configure_policies(skel);
	if (err)
		goto cleanup;

	link = bpf_map__attach_cgroup_opts(skel->maps.test_bpf_oomd,
					   cgroups[0].fd, &opts);
	if (!ASSERT_OK_PTR(link, "attach_oomd_cgroup")) {
		link = NULL;
		goto cleanup;
	}

	root_fd = get_root_cgroup();
	if (!ASSERT_GE(root_fd, 0, "get_root_cgroup"))
		goto cleanup;

	root_link = bpf_map__attach_cgroup_opts(skel->maps.test_bpf_oomd,
						root_fd, &opts);
	if (!ASSERT_OK_PTR(root_link, "attach_oomd_root")) {
		root_link = NULL;
		goto cleanup;
	}

	err = run_and_wait_for_oom(skel);
	CHECK_FAIL(err);

cleanup:
	bpf_link__destroy(link);
	bpf_link__destroy(root_link);
	if (root_fd >= 0)
		close(root_fd);
	test_oomd__destroy(skel);
cleanup_cgroup:
	write_cgroup_file(cgroups[0].path, "cgroup.kill", "1");
	write_cgroup_file(cgroups[0].path, "cgroup.freeze", "0");
	cleanup_cgroup_environment();
}
