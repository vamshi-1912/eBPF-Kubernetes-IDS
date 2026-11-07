// SPDX-License-Identifier: GPL-2.0
/*
 * eBPF Monitoring Module (kernel side).
 *
 * libbpf CO-RE program that hooks syscall tracepoints and streams
 * security-relevant runtime events (process, file, network and
 * sensitive syscalls) to user space through a BPF ring buffer.
 *
 * No vmlinux.h is needed: the only kernel struct we touch
 * (task_struct) is declared minimally with preserve_access_index,
 * and libbpf relocates field offsets against the running kernel's BTF.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "ids.h"

char LICENSE[] SEC("license") = "GPL";

/* ---- minimal CO-RE kernel type ------------------------------------ */
struct task_struct {
	int tgid;
	struct task_struct *real_parent;
	char comm[TASK_COMM_LEN];
} __attribute__((preserve_access_index));

/* ---- stable tracepoint layouts (syscalls:sys_enter_* / sys_exit_*) - */
struct sys_enter_ctx {
	__u64 common;          /* common_type/flags/preempt/pid */
	__s32 syscall_nr;
	__u32 pad;
	__u64 args[6];
};

struct sys_exit_ctx {
	__u64 common;
	__s32 syscall_nr;
	__u32 pad;
	__s64 ret;
};

/* ---- configuration (set by the loader before load) ----------------- */
const volatile __u32 self_pid1 = 0;
const volatile __u32 self_pid2 = 0;

/* ---- maps ------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

/* execve args are copied on sys_enter and only emitted on a successful
 * sys_exit, because the caller's memory is gone after a successful exec. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct event);
} exec_stash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} scratch SEC(".maps");

/* [0] = events emitted, [1] = events dropped (ring buffer full) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

#define AF_UNIX  1
#define AF_INET  2
#define AF_INET6 10

#define O_WRONLY 01
#define O_RDWR   02
#define O_CREAT  0100
#define O_TRUNC  01000
#define O_APPEND 02000

/* ---- helpers ------------------------------------------------------- */
static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		*v += 1;
}

static __always_inline int is_self(__u32 tgid)
{
	return (self_pid1 && tgid == self_pid1) || (self_pid2 && tgid == self_pid2);
}

static __always_inline struct event *scratch_event(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&scratch, &zero);
}

/* Fill pid/uid/comm/cgroup/parent information for the current task. */
static __always_inline void fill_task(struct event *e, __u32 type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);

	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->type = type;
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->ppid = BPF_CORE_READ(parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->argc = 0;
	e->arg_num = 0;
	e->arg_num2 = 0;
	e->family = 0;
	e->dport = 0;
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	e->path[0] = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	BPF_CORE_READ_STR_INTO(&e->pcomm, parent, comm);
}

static __always_inline void submit(struct event *e)
{
	if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
		count(1);
	else
		count(0);
}

static __always_inline int prefix(const char *s, const char *p, int n)
{
#pragma unroll
	for (int i = 0; i < n; i++)
		if (s[i] != p[i])
			return 0;
	return 1;
}
#define HAS_PREFIX(s, lit) prefix((s), (lit), sizeof(lit) - 1)

/* Kernel-side filter: only files that matter for intrusion detection
 * are forwarded, which keeps openat() overhead negligible. */
static __always_inline int sensitive_open(const char *p, __s64 flags)
{
	int write = flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND);

	if (p[0] != '/')
		return 0;
	if (HAS_PREFIX(p, "/etc/shadow") || HAS_PREFIX(p, "/etc/gshadow") ||
	    HAS_PREFIX(p, "/etc/sudoers") || HAS_PREFIX(p, "/etc/kubernetes") ||
	    HAS_PREFIX(p, "/etc/ssh/") || HAS_PREFIX(p, "/etc/crontab") ||
	    HAS_PREFIX(p, "/etc/cron.") || HAS_PREFIX(p, "/var/spool/cron") ||
	    HAS_PREFIX(p, "/etc/ld.so.preload") || HAS_PREFIX(p, "/root/") ||
	    HAS_PREFIX(p, "/var/run/secrets") || HAS_PREFIX(p, "/run/secrets") ||
	    HAS_PREFIX(p, "/proc/kcore") || HAS_PREFIX(p, "/dev/mem") ||
	    HAS_PREFIX(p, "/proc/sys/kernel/") || HAS_PREFIX(p, "/var/lib/kubelet/pki"))
		return 1;
	if (write && (HAS_PREFIX(p, "/etc/passwd") || HAS_PREFIX(p, "/etc/group") ||
		      HAS_PREFIX(p, "/dev/shm/") || HAS_PREFIX(p, "/etc/profile") ||
		      HAS_PREFIX(p, "/etc/bash.bashrc") || HAS_PREFIX(p, "/etc/systemd/")))
		return 1;
	return 0;
}

static __always_inline int sensitive_unix(const char *p)
{
	return HAS_PREFIX(p, "/var/run/docker.sock") || HAS_PREFIX(p, "/run/docker.sock") ||
	       HAS_PREFIX(p, "/run/containerd/containerd.sock") ||
	       HAS_PREFIX(p, "/var/run/containerd/containerd.sock") ||
	       HAS_PREFIX(p, "/var/run/cri-dockerd.sock") ||
	       HAS_PREFIX(p, "/run/crio/crio.sock");
}

/* ---- process: execve ------------------------------------------------ */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_enter_execve(struct sys_enter_ctx *ctx)
{
	struct event *e = scratch_event();
	const char *const *argv = (const char *const *)ctx->args[1];
	__u32 tid;

	if (!e)
		return 0;
	fill_task(e, EV_EXEC);
	if (is_self(e->pid))
		return 0;
	bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)ctx->args[0]);

	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;

		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) || !argp)
			break;
		bpf_probe_read_user_str(e->argv[i], ARG_LEN, argp);
		e->argc = i + 1;
	}
	tid = e->tid;
	bpf_map_update_elem(&exec_stash, &tid, e, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tp_exit_execve(struct sys_exit_ctx *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct event *e = bpf_map_lookup_elem(&exec_stash, &tid);

	if (!e)
		return 0;
	if (ctx->ret == 0) {
		/* comm now holds the new program name */
		bpf_get_current_comm(e->comm, sizeof(e->comm));
		submit(e);
	}
	bpf_map_delete_elem(&exec_stash, &tid);
	return 0;
}

/* ---- file: openat ----------------------------------------------------- */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct sys_enter_ctx *ctx)
{
	struct event *e = scratch_event();

	if (!e)
		return 0;
	if (bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)ctx->args[1]) <= 0)
		return 0;
	if (!sensitive_open(e->path, (__s64)ctx->args[2]))
		return 0;
	fill_task(e, EV_OPEN);
	if (is_self(e->pid))
		return 0;
	/* fill_task cleared path; read it again */
	bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)ctx->args[1]);
	e->arg_num = (__s64)ctx->args[2];
	submit(e);
	return 0;
}

/* ---- network: connect ------------------------------------------------- */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_enter_connect(struct sys_enter_ctx *ctx)
{
	struct event *e = scratch_event();
	const void *addr = (const void *)ctx->args[1];
	__u16 family = 0, port = 0;

	if (!e || !addr)
		return 0;
	bpf_probe_read_user(&family, sizeof(family), addr);
	if (family != AF_INET && family != AF_INET6 && family != AF_UNIX)
		return 0;

	fill_task(e, EV_CONNECT);
	if (is_self(e->pid))
		return 0;
	e->family = family;

	if (family == AF_UNIX) {
		bpf_probe_read_user_str(e->path, 108, addr + 2);
		if (!sensitive_unix(e->path))
			return 0;
	} else {
		bpf_probe_read_user(&port, sizeof(port), addr + 2);
		e->dport = bpf_ntohs(port);
		if (family == AF_INET)
			bpf_probe_read_user(e->daddr, 4, addr + 4);
		else
			bpf_probe_read_user(e->daddr, 16, addr + 8);
	}
	submit(e);
	return 0;
}

/* ---- sensitive syscalls -------------------------------------------- */
static __always_inline int simple_event(__u32 type, __s64 a, __s64 b, const char *upath)
{
	struct event *e = scratch_event();

	if (!e)
		return 0;
	fill_task(e, type);
	if (is_self(e->pid))
		return 0;
	e->arg_num = a;
	e->arg_num2 = b;
	if (upath)
		bpf_probe_read_user_str(e->path, sizeof(e->path), upath);
	submit(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_enter_ptrace(struct sys_enter_ctx *ctx)
{
	return simple_event(EV_PTRACE, ctx->args[0], ctx->args[1], NULL);
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int tp_enter_setuid(struct sys_enter_ctx *ctx)
{
	return simple_event(EV_SETUID, ctx->args[0], -1, NULL);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int tp_enter_setresuid(struct sys_enter_ctx *ctx)
{
	/* report the effective uid; -1 means "unchanged" */
	if ((__s32)ctx->args[1] == -1)
		return 0;
	return simple_event(EV_SETUID, (__s32)ctx->args[1], (__s32)ctx->args[0], NULL);
}

SEC("tracepoint/syscalls/sys_enter_mount")
int tp_enter_mount(struct sys_enter_ctx *ctx)
{
	struct event *e = scratch_event();

	if (!e)
		return 0;
	fill_task(e, EV_MOUNT);
	if (is_self(e->pid))
		return 0;
	bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)ctx->args[1]);
	if (ctx->args[0])
		bpf_probe_read_user_str(e->argv[0], ARG_LEN, (const char *)ctx->args[0]);
	if (ctx->args[2])
		bpf_probe_read_user_str(e->argv[1], ARG_LEN, (const char *)ctx->args[2]);
	e->argc = 2;
	e->arg_num = ctx->args[3];
	submit(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int tp_enter_unshare(struct sys_enter_ctx *ctx)
{
	return simple_event(EV_UNSHARE, ctx->args[0], 0, NULL);
}

SEC("tracepoint/syscalls/sys_enter_setns")
int tp_enter_setns(struct sys_enter_ctx *ctx)
{
	return simple_event(EV_SETNS, ctx->args[1], ctx->args[0], NULL);
}

static __always_inline int chmod_event(const char *upath, __s64 mode)
{
	/* only setuid/setgid or "make executable" changes are interesting */
	if (!(mode & 06111))
		return 0;
	return simple_event(EV_CHMOD, mode, 0, upath);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tp_enter_fchmodat(struct sys_enter_ctx *ctx)
{
	return chmod_event((const char *)ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int tp_enter_fchmodat2(struct sys_enter_ctx *ctx)
{
	return chmod_event((const char *)ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int tp_enter_chmod(struct sys_enter_ctx *ctx)
{
	return chmod_event((const char *)ctx->args[0], ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int tp_enter_init_module(struct sys_enter_ctx *ctx)
{
	return simple_event(EV_MODULE, 0, 0, NULL);
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int tp_enter_finit_module(struct sys_enter_ctx *ctx)
{
	return simple_event(EV_MODULE, ctx->args[0], 1, NULL);
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_enter_memfd_create(struct sys_enter_ctx *ctx)
{
	return simple_event(EV_MEMFD, ctx->args[1], 0, (const char *)ctx->args[0]);
}
