// SPDX-License-Identifier: GPL-2.0
/*
 * Event Collection Module (kernel -> user space).
 *
 * Loads the CO-RE eBPF program with libbpf, attaches every tracepoint,
 * consumes the ring buffer and writes one JSON object per line to stdout.
 * The Python agent reads this stream for enrichment, feature extraction
 * and detection.
 *
 *   {"kind":"ready", ...}   once after attach
 *   {"kind":"event", ...}   per kernel event
 *   {"kind":"stats", ...}   every 5 s (emitted / dropped counters)
 */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/ids.h"
#include "ids.skel.h"

static volatile sig_atomic_t exiting;

static void on_signal(int sig) { (void)sig; exiting = 1; }

static const char *type_name(__u32 t)
{
	switch (t) {
	case EV_EXEC:    return "exec";
	case EV_OPEN:    return "open";
	case EV_CONNECT: return "connect";
	case EV_PTRACE:  return "ptrace";
	case EV_SETUID:  return "setuid";
	case EV_MOUNT:   return "mount";
	case EV_UNSHARE: return "unshare";
	case EV_CHMOD:   return "chmod";
	case EV_MODULE:  return "module";
	case EV_MEMFD:   return "memfd";
	case EV_SETNS:   return "setns";
	default:         return "unknown";
	}
}

/* Write a bounded C string as a JSON string literal. */
static void json_str(FILE *f, const char *s, size_t max)
{
	fputc('"', f);
	for (size_t i = 0; i < max && s[i]; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':  fputs("\\\"", f); break;
		case '\\': fputs("\\\\", f); break;
		case '\n': fputs("\\n", f); break;
		case '\r': fputs("\\r", f); break;
		case '\t': fputs("\\t", f); break;
		default:
			if (c < 0x20 || c >= 0x7f)
				fprintf(f, "\\u%04x", c); /* keep output valid UTF-8 */
			else
				fputc(c, f);
		}
	}
	fputc('"', f);
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	char addr[INET6_ADDRSTRLEN] = "";
	(void)ctx;

	if (len < sizeof(*e))
		return 0;

	if (e->family == AF_INET)
		inet_ntop(AF_INET, e->daddr, addr, sizeof(addr));
	else if (e->family == AF_INET6)
		inet_ntop(AF_INET6, e->daddr, addr, sizeof(addr));

	printf("{\"kind\":\"event\",\"type\":\"%s\",\"ts_ns\":%llu,\"cgroup_id\":%llu,"
	       "\"pid\":%u,\"tid\":%u,\"ppid\":%u,\"uid\":%u,\"arg_num\":%lld,\"arg_num2\":%lld,"
	       "\"family\":%u,\"dport\":%u,\"daddr\":\"%s\",\"comm\":",
	       type_name(e->type), (unsigned long long)e->ts_ns,
	       (unsigned long long)e->cgroup_id, e->pid, e->tid, e->ppid, e->uid,
	       (long long)e->arg_num, (long long)e->arg_num2, e->family, e->dport, addr);
	json_str(stdout, e->comm, sizeof(e->comm));
	fputs(",\"pcomm\":", stdout);
	json_str(stdout, e->pcomm, sizeof(e->pcomm));
	fputs(",\"path\":", stdout);
	json_str(stdout, e->path, sizeof(e->path));
	fputs(",\"argv\":[", stdout);
	for (__u32 i = 0; i < e->argc && i < MAX_ARGS; i++) {
		if (i)
			fputc(',', stdout);
		json_str(stdout, e->argv[i], ARG_LEN);
	}
	fputs("]}\n", stdout);
	return 0;
}

static void print_stats(struct ids_bpf *skel)
{
	int ncpu = libbpf_num_possible_cpus();
	__u64 totals[2] = {0, 0};
	__u64 *vals;

	if (ncpu <= 0)
		return;
	vals = calloc(ncpu, sizeof(__u64));
	if (!vals)
		return;
	for (__u32 k = 0; k < 2; k++) {
		if (bpf_map__lookup_elem(skel->maps.stats, &k, sizeof(k), vals,
					 sizeof(__u64) * ncpu, 0) == 0)
			for (int c = 0; c < ncpu; c++)
				totals[k] += vals[c];
	}
	free(vals);
	printf("{\"kind\":\"stats\",\"emitted\":%llu,\"dropped\":%llu,\"loader_pid\":%d}\n",
	       (unsigned long long)totals[0], (unsigned long long)totals[1], getpid());
}

static int libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
	if (lvl == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

int main(void)
{
	struct ring_buffer *rb = NULL;
	struct bpf_program *prog;
	struct ids_bpf *skel;
	int attached = 0, failed = 0, err;
	time_t last_stats = time(NULL);
	static char outbuf[1 << 16];

	setvbuf(stdout, outbuf, _IOFBF, sizeof(outbuf));
	libbpf_set_print(libbpf_log);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, on_signal);

	skel = ids_bpf__open();
	if (!skel) {
		fprintf(stderr, "ids_loader: failed to open BPF skeleton\n");
		return 1;
	}
	/* never report the agent's own activity */
	skel->rodata->self_pid1 = getpid();
	skel->rodata->self_pid2 = getppid();

	err = ids_bpf__load(skel);
	if (err) {
		fprintf(stderr, "ids_loader: failed to load BPF object: %d\n", err);
		goto out;
	}

	/* attach one by one so a missing tracepoint (e.g. fchmodat2 on old
	 * kernels) does not disable the whole monitor */
	fprintf(stderr, "ids_loader: attaching tracepoints\n");
	bpf_object__for_each_program(prog, skel->obj) {
		struct bpf_link *link = bpf_program__attach(prog);

		if (!link) {
			fprintf(stderr, "ids_loader: warning: cannot attach %s\n",
				bpf_program__name(prog));
			failed++;
			continue;
		}
		attached++;
	}
	if (!attached) {
		fprintf(stderr, "ids_loader: no program attached\n");
		err = 1;
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ids_loader: failed to create ring buffer\n");
		err = 1;
		goto out;
	}

	printf("{\"kind\":\"ready\",\"loader_pid\":%d,\"attached\":%d,\"failed\":%d}\n",
	       getpid(), attached, failed);
	fflush(stdout);

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ids_loader: ring buffer poll error %d\n", err);
			break;
		}
		if (time(NULL) - last_stats >= 5) {
			print_stats(skel);
			last_stats = time(NULL);
		}
		if (fflush(stdout) == EOF)
			break; /* reader went away */
	}
	err = 0;
out:
	ring_buffer__free(rb);
	ids_bpf__destroy(skel); /* also detaches all links */
	return err ? 1 : 0;
}
