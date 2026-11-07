/* Shared between the eBPF kernel program and the user-space loader. */
#ifndef __IDS_H
#define __IDS_H

#define TASK_COMM_LEN 16
#define MAX_PATH      256
#define MAX_ARGS      8
#define ARG_LEN       128

enum event_type {
	EV_EXEC    = 1,  /* execve succeeded                        */
	EV_OPEN    = 2,  /* openat on a security-sensitive path     */
	EV_CONNECT = 3,  /* outbound IPv4/IPv6 connect()            */
	EV_PTRACE  = 4,  /* ptrace()                                */
	EV_SETUID  = 5,  /* setuid()                                */
	EV_MOUNT   = 6,  /* mount()                                 */
	EV_UNSHARE = 7,  /* unshare()                               */
	EV_CHMOD   = 8,  /* fchmodat() setting suid/sgid/exec bits  */
	EV_MODULE  = 9,  /* init_module()/finit_module()            */
	EV_MEMFD   = 10, /* memfd_create() (fileless execution)     */
	EV_SETNS   = 11, /* setns() (namespace switching)           */
};

struct event {
	__u64 ts_ns;      /* bpf_ktime_get_ns() == CLOCK_MONOTONIC  */
	__u64 cgroup_id;  /* cgroup v2 id == inode of cgroup dir    */
	__u32 type;
	__u32 pid;        /* tgid                                   */
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 argc;       /* number of argv slots filled (exec)     */
	__s64 arg_num;    /* flags / mode / uid / request ...       */
	__s64 arg_num2;   /* secondary numeric arg (ptrace target)  */
	__u16 family;     /* AF_INET / AF_INET6 (connect)           */
	__u16 dport;      /* host byte order                        */
	__u8  daddr[16];  /* v4 in first 4 bytes                    */
	char  comm[TASK_COMM_LEN];
	char  pcomm[TASK_COMM_LEN];
	char  path[MAX_PATH];
	char  argv[MAX_ARGS][ARG_LEN];
};

#endif /* __IDS_H */
