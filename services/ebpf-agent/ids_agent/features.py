"""Feature Extraction Module.

Converts one runtime event (plus a short behavioural window for the
workload it belongs to) into a fixed-length numeric vector.

This module is the single source of truth for features: it is imported by
``ml/train_model.py`` for training *and* by the live agent for inference,
so the model can never be trained on something the sensor does not see.

Event dict keys (all optional except ``event_type``):
    event_type   exec|open|connect|ptrace|setuid|mount|unshare|chmod|module|memfd|setns
    comm         process name (15 chars max, like the kernel)
    parent_comm  parent process name
    uid          numeric uid
    path         exec: binary path / open: file / connect: unix socket path /
                 mount: target / memfd: name / chmod: file
    cmdline      argv joined with spaces (exec), "source fstype" (mount)
    argc         number of argv entries
    flags        open flags / chmod mode / unshare flags / ptrace request / uid
    arg2         secondary numeric argument
    dport        destination port (connect)
    daddr        destination address (connect)
    namespace    Kubernetes namespace

Window dict keys (behavioural features, last WINDOW_SECONDS for the workload):
    win_exec_count, win_distinct_bins, win_connect_count, win_distinct_dst,
    win_sensitive_opens, win_shell_count, win_new_binary
"""
from __future__ import annotations

import ipaddress
import math
import os
import re
import time
from collections import deque

COMM_LEN = 15  # TASK_COMM_LEN - 1
ARG_LEN = 127  # kernel captures ARG_LEN-1 chars per argv entry
MAX_ARGS = 8
WINDOW_SECONDS = 60
WARMUP_SECONDS = 300

EVENT_TYPES = ["exec", "open", "connect", "ptrace", "setuid", "mount",
               "unshare", "chmod", "module", "memfd", "setns"]


def _c(names):
    """Normalise names to what the kernel reports in task->comm."""
    return frozenset(n[:COMM_LEN] for n in names)


SHELLS = _c({"sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish", "busybox"})
NET_TOOLS = _c({"nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "telnet",
                "curl", "wget", "nmap", "masscan", "zmap", "tftp", "ftp", "ssh", "scp",
                "sftp", "sshpass", "rsync", "hping3", "proxychains", "chisel", "frpc"})
INTERPRETERS = _c({"python", "python2", "python3", "perl", "ruby", "php", "node", "lua",
                   "irb", "pwsh", "awk", "gawk", "tclsh"})
RECON_TOOLS = _c({"whoami", "id", "uname", "hostname", "ps", "ifconfig", "netstat", "ss",
                  "env", "printenv", "getent", "lsblk", "capsh", "groups", "lscpu", "df",
                  "find", "arp", "route", "nslookup", "dig", "host", "w", "who", "last",
                  "lsof", "crontab", "linpeas.sh", "les.sh", "pspy64", "fdisk", "lsmod"})
CONTAINER_TOOLS = _c({"kubectl", "crictl", "docker", "ctr", "helm", "kubeadm", "nerdctl",
                      "podman", "kubeletctl", "amicontained", "deepce", "cdk"})
ESCAPE_TOOLS = _c({"nsenter", "chroot", "unshare", "mount", "umount", "insmod", "modprobe",
                   "debugfs", "setcap", "pivot_root", "capsh", "rmmod"})
PKG_MANAGERS = _c({"apt", "apt-get", "dpkg", "apk", "yum", "dnf", "rpm", "pip", "pip3",
                   "npm", "yarn", "gem", "cargo", "go", "composer", "bundle", "conda"})
SERVERS = _c({"nginx", "httpd", "apache2", "java", "node", "php-fpm", "php-fpm8.2",
              "gunicorn", "uwsgi", "uvicorn", "tomcat", "catalina.sh", "puma", "unicorn",
              "redis-server", "mysqld", "postgres", "mongod", "dotnet", "caddy", "envoy",
              "haproxy", "lighttpd", "jboss", "weblogic", "spring"})
DEBUGGERS = _c({"gdb", "strace", "ltrace", "lldb", "perf", "dlv", "py-spy", "rr", "valgrind"})
K8S_COMPONENTS = _c({"coredns", "kube-proxy", "kubelet", "kube-apiserver", "etcd",
                     "kube-controller-manager", "kube-scheduler", "storage-provisioner",
                     "dashboard", "metrics-sidecar", "metrics-server", "containerd",
                     "dockerd", "runc", "containerd-shim", "containerd-shim-runc-v2",
                     "pause", "cri-dockerd", "flanneld", "calico-node", "cilium-agent",
                     "local-path-provisioner", "nginx-ingress-controller", "kindnetd",
                     "aws-node", "csi-node-driver", "node-exporter", "prometheus",
                     "fluent-bit", "fluentd", "otelcol", "ids-agent", "ids_loader"})
AUTH_BINARIES = _c({"sshd", "sudo", "su", "login", "passwd", "chpasswd", "useradd",
                    "usermod", "groupadd", "unix_chkpwd", "cron", "crond", "systemd",
                    "polkitd", "pkexec", "newgrp", "chage", "vipw", "gosu", "su-exec"})
# platform namespaces: control plane, add-ons, CI/CD and GitOps controllers
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease",
                               "kubernetes-dashboard", "local-path-storage", "ingress-nginx",
                               "calico-system", "tigera-operator", "cert-manager",
                               "monitoring", "ebpf-ids", "ci", "argocd", "gitlab-runner",
                               "jenkins", "flux-system", "tekton-pipelines"})
BENIGN_MEMFD = ("runc_cloned", "shared_mem", "pulseaudio", "systemd", "wayland", "mozilla",
                "v8", "dmabuf", "java", "libffi", "xshmfence", "gdk", "pipewire", "jit-",
                "doublemapper", "chrome", "libgcrypt", "nodejs", "crun", "memfd-cache",
                "go-memfd", "jemalloc", "cuda")

COMMON_PORTS = frozenset({20, 21, 22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636,
                          993, 995, 1433, 2379, 2380, 3000, 3306, 4317, 5000, 5432, 5672,
                          6379, 6443, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9092,
                          9093, 9100, 9200, 9300, 10250, 10256, 11211, 15672, 27017})
SUSPICIOUS_PORTS = frozenset({1080, 1234, 1337, 2222, 3333, 4242, 4443, 4444, 4445, 5555,
                              5556, 6666, 6667, 6697, 7777, 8333, 9001, 9050, 9999, 12345,
                              14433, 14444, 31337, 45560, 45700, 50050, 54321})

SENSITIVE_HIGH = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/root/.ssh", "/etc/ssh/ssh_host_",
                  "/proc/kcore", "/dev/mem", "/etc/ld.so.preload", "/var/run/docker.sock",
                  "/run/docker.sock", "/run/containerd/containerd.sock",
                  "/var/run/containerd/containerd.sock", "/var/run/cri-dockerd.sock",
                  "/run/crio/crio.sock", "/proc/sys/kernel/core_pattern",
                  "/proc/sys/kernel/modprobe", "/var/lib/kubelet/pki",
                  "/etc/kubernetes/admin.conf", "/etc/kubernetes/pki")
SENSITIVE_MEDIUM = ("/var/run/secrets", "/run/secrets", "/etc/kubernetes", "/root/",
                    "/etc/crontab", "/etc/cron.", "/var/spool/cron", "/etc/passwd",
                    "/etc/group", "/dev/shm/", "/etc/ssh/", "/etc/profile", "/etc/bash.bashrc",
                    "/etc/systemd/", "/proc/sys/kernel/")
TMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/dev/mqueue/")
FILELESS_PREFIXES = ("/proc/self/fd/", "/dev/fd/", "memfd:", "/memfd:")

O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND = 0o1, 0o2, 0o100, 0o1000, 0o2000
PTRACE_ATTACH_LIKE = {4, 5, 6, 13, 16, 0x4206}  # POKETEXT/POKEDATA/POKEUSER/SETREGS/ATTACH/SEIZE
CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET = 0x20000, 0x10000000, 0x20000000, 0x40000000

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL = re.compile(r"\b(?:https?|ftp|tftp)://", re.I)
RE_DEVTCP = re.compile(r"/dev/(?:tcp|udp)/")
RE_PIPE_INTERP = re.compile(r"\|\s*(?:sudo\s+)?(?:/usr)?(?:/bin/)?(?:ba|da|z|k)?sh\b|\|\s*(?:python[0-9.]*|perl|ruby|php)\b")
RE_REVSHELL = re.compile(
    r"(?:-i\s*>&|>&\s*/dev/(?:tcp|udp)|0>&1|\b(?:nc|ncat|netcat)\b[^|;]*\s-(?:e|c)\s"
    r"|--exec\b|\bsocat\b[^|;]*exec:|pty\.spawn|socket\.socket|fsockopen|mkfifo"
    r"|TCPSocket|use\s+Socket|\bsh\s+-i\b|exec\s+\d+<>|/inet/tcp/|Net::Socket"
    r"|new\s+Socket\(|child_process|-e\s+/bin/(?:ba)?sh)", re.I)
RE_MINER = re.compile(r"(?:stratum\+(?:tcp|ssl|tls)|xmrig|minerd|cpuminer|--donate-level|"
                      r"cryptonight|randomx|nicehash|monero|xmr\.|\bpool\.|kdevtmpfsi|kinsing|"
                      r"--coin\b|-a\s+rx/0|ethminer|nbminer|t-rex)", re.I)
RE_CLEANUP = re.compile(r"(?:history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|"
                        r"rm\s+-[rf]+\s+/var/log|shred\b|>\s*\S*\.bash_history|"
                        r"truncate\s+-s\s*0\s+\S*/var/log|journalctl\s+--(?:vacuum|rotate)|"
                        r"rm\s+-[rf]*\s+\S*\.bash_history|touch\s+-r\b|ln\s+-sf\s+/dev/null)", re.I)
RE_SENSITIVE_ARGS = re.compile(r"(?:/etc/shadow|/etc/gshadow|/etc/sudoers|\.ssh/|id_rsa|id_ed25519|"
                               r"/var/run/secrets|serviceaccount|docker\.sock|containerd\.sock|"
                               r"/proc/1/(?:root|environ|mem|ns)|core_pattern|release_agent|"
                               r"/etc/kubernetes|kubeconfig|admin\.conf|169\.254\.169\.254|"
                               r"metadata\.google|\.aws/credentials|\.kube/config|/etc/ld\.so\.preload|"
                               r"/dev/sd[a-z]|/dev/nvme|/dev/xvd|/var/lib/kubelet)", re.I)
RE_RECON_ARGS = re.compile(r"(?:-perm\s+-?[/+]?[2467]000|/proc/1/cgroup|/\.dockerenv|--print\b|"
                           r"\bnmap\b|masscan|\s-sS\b|/api/v1/|kubernetes\.default|10\.96\.0\.1\b|"
                           r"\bwhoami\b|uname\s+-a|/etc/os-release|auth\s+can-i|get\s+secrets|"
                           r"/proc/self/status|CapEff|getcap\s+-r)", re.I)
RE_SUID = re.compile(r"(?:\b[ugoa]*\+[rwx]*s\b|\b[2467][0-7]{3}\b)")
RE_B64_DECODE = re.compile(r"base64\s+(?:-d|--decode|-D)\b|b64decode|frombase64|atob\(", re.I)
RE_DOWNLOAD = re.compile(r"(?:\bcurl\b|\bwget\b|\bfetch\b|\btftp\b|urllib|requests\.get|Invoke-WebRequest|"
                         r"\bscp\b|busybox\s+wget)", re.I)
RE_TMP_WRITE = re.compile(r"(?:-[oO]\s*|>\s*)(?:/tmp/|/dev/shm/|/var/tmp/)")
RE_TOKEN = re.compile(r"[\s'\"=;|&]+")

FEATURE_NAMES = (
    [f"ev_{t}" for t in EVENT_TYPES]
    + [
        "uid_root", "ns_system", "cmd_len", "n_args", "n_special", "cmd_entropy",
        "has_base64_blob", "has_b64_decode", "has_ip_literal", "has_url", "has_dev_tcp",
        "bin_is_shell", "bin_is_net_tool", "bin_is_interpreter", "bin_is_recon",
        "bin_is_container_tool", "bin_is_escape_tool", "bin_is_pkg_mgr", "bin_in_tmp",
        "bin_hidden", "bin_fileless", "proc_is_k8s_component", "proc_is_auth_binary",
        "proc_is_debugger", "parent_is_shell", "parent_is_server", "parent_is_interpreter",
        "parent_is_k8s_component", "args_sensitive_path", "args_download", "args_download_exec",
        "args_tmp_write", "args_suid", "args_reverse_shell", "args_miner", "args_cleanup",
        "args_recon", "file_sensitivity", "file_write", "net_family_unix", "net_port_common",
        "net_port_suspicious", "net_port_high", "net_dst_private", "net_dst_loopback",
        "net_dst_linklocal", "ptrace_attach", "setuid_to_root", "unshare_userns",
        "unshare_mountns", "chmod_suid", "chmod_exec", "memfd_benign_name",
        "mount_block_device", "mount_host_path",
        "win_exec_count", "win_distinct_bins", "win_connect_count", "win_distinct_dst",
        "win_sensitive_opens", "win_shell_count", "win_new_binary", "win_shell_ratio",
    ]
)


# --------------------------------------------------------------------------- helpers
def basename(p: str) -> str:
    return os.path.basename((p or "").rstrip("/")) or ""


def norm_comm(name: str) -> str:
    return (name or "")[:COMM_LEN]


def is_python(name: str) -> bool:
    return name.startswith("python")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def has_base64_blob(cmd: str) -> int:
    for tok in RE_TOKEN.split(cmd or ""):
        if len(tok) < 24 or tok.startswith("/") or "://" in tok:
            continue
        body = tok.rstrip("=")
        if not re.fullmatch(r"[A-Za-z0-9+/]+", body):
            continue
        if tok.count("/") > len(tok) / 16:
            continue
        if any(c.isdigit() for c in body) and any(c.isupper() for c in body) and any(c.islower() for c in body):
            return 1
    return 0


def file_sensitivity(path: str, write: bool) -> int:
    p = path or ""
    if p.startswith(SENSITIVE_HIGH):
        return 2
    if p.startswith(("/etc/passwd", "/etc/group", "/dev/shm/")) and not write:
        return 0
    if p.startswith(SENSITIVE_MEDIUM):
        return 1
    return 0


def parse_ip(addr: str):
    try:
        ip = ipaddress.ip_address(addr)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return ip
    except ValueError:
        return None


def truncate_cmdline(argv):
    """Apply the same truncation the kernel probe applies (8 args x 127 chars)."""
    return [a[:ARG_LEN] for a in list(argv)[:MAX_ARGS]]


def binary_name(ev: dict) -> str:
    if ev.get("event_type") == "exec":
        b = basename(ev.get("path", ""))
        return norm_comm(b) if b else norm_comm(ev.get("comm", ""))
    return norm_comm(ev.get("comm", ""))


def in_set(name: str, s) -> int:
    return int(name in s or (s is INTERPRETERS and is_python(name)))


# --------------------------------------------------------------------------- extraction
def extract(ev: dict, win: dict | None = None) -> list[float]:
    win = win or {}
    et = ev.get("event_type", "exec")
    comm = norm_comm(ev.get("comm", ""))
    parent = norm_comm(ev.get("parent_comm", ""))
    path = ev.get("path", "") or ""
    cmd = ev.get("cmdline", "") or ""
    argc = int(ev.get("argc", 0) or 0)
    flags = int(ev.get("flags", 0) or 0)
    uid = int(ev.get("uid", 0) or 0)
    dport = int(ev.get("dport", 0) or 0)
    daddr = ev.get("daddr", "") or ""
    ns = ev.get("namespace", "") or ""
    binname = binary_name(ev)
    text = cmd if et == "exec" else f"{path} {cmd}".strip()

    f = [1.0 if et == t else 0.0 for t in EVENT_TYPES]

    write = bool(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) if et == "open" else False
    ip = parse_ip(daddr) if et == "connect" and daddr else None
    unix = et == "connect" and not daddr and path.startswith("/")
    is_runtime = comm.startswith("runc") or binname.startswith("runc") or comm.startswith("containerd-shim")

    f += [
        float(uid == 0),
        float(ns in SYSTEM_NAMESPACES),
        float(min(len(text), 1024)),
        float(argc),
        float(sum(text.count(c) for c in "|><&;$`")),
        round(entropy(text), 4),
        float(has_base64_blob(text)),
        float(bool(RE_B64_DECODE.search(text))),
        float(bool(RE_IP.search(text))),
        float(bool(RE_URL.search(text))),
        float(bool(RE_DEVTCP.search(text))),
        float(in_set(binname, SHELLS)),
        float(in_set(binname, NET_TOOLS)),
        float(in_set(binname, INTERPRETERS)),
        float(in_set(binname, RECON_TOOLS)),
        float(in_set(binname, CONTAINER_TOOLS)),
        float(in_set(binname, ESCAPE_TOOLS)),
        float(in_set(binname, PKG_MANAGERS)),
        float(et == "exec" and path.startswith(TMP_DIRS)),
        float(binname.startswith(".")),
        float(et == "exec" and path.startswith(FILELESS_PREFIXES)),
        float(comm in K8S_COMPONENTS or is_runtime),
        float(comm in AUTH_BINARIES),
        float(comm in DEBUGGERS or binname in DEBUGGERS),
        float(in_set(parent, SHELLS)),
        float(parent in SERVERS),
        float(in_set(parent, INTERPRETERS)),
        float(parent in K8S_COMPONENTS or parent.startswith("runc") or parent.startswith("containerd-shim")),
        float(bool(RE_SENSITIVE_ARGS.search(text))),
        float(bool(RE_DOWNLOAD.search(text))),
        float(bool(RE_PIPE_INTERP.search(text)) and bool(RE_DOWNLOAD.search(text) or RE_URL.search(text))),
        float(bool(RE_TMP_WRITE.search(text))),
        float(binname == "chmod" and bool(RE_SUID.search(cmd))),
        float(bool(RE_REVSHELL.search(text))),
        float(bool(RE_MINER.search(text))),
        float(bool(RE_CLEANUP.search(text))),
        float(bool(RE_RECON_ARGS.search(text))),
        float(file_sensitivity(path, write) if et == "open" or unix else 0),
        float(write),
        float(unix),
        float(et == "connect" and dport in COMMON_PORTS),
        float(et == "connect" and dport in SUSPICIOUS_PORTS),
        float(et == "connect" and dport >= 30000 and dport not in SUSPICIOUS_PORTS),
        float(bool(ip and ip.is_private and not ip.is_loopback and not ip.is_link_local)),
        float(bool(ip and ip.is_loopback)),
        float(bool(ip and ip.is_link_local)),
        float(et == "ptrace" and flags in PTRACE_ATTACH_LIKE),
        float(et == "setuid" and flags == 0),
        float(et == "unshare" and bool(flags & CLONE_NEWUSER)),
        float(et == "unshare" and bool(flags & CLONE_NEWNS)),
        float(et == "chmod" and bool(flags & 0o6000)),
        float(et == "chmod" and bool(flags & 0o111)),
        float(et == "memfd" and path.startswith(BENIGN_MEMFD)),
        float(et == "mount" and bool(re.search(r"/dev/(?:sd|nvme|xvd|vd|dm-|mapper)", cmd))),
        float(et == "mount" and (path.startswith(("/host", "/mnt")) or " / " in f" {cmd} ")),
    ]

    execs = float(win.get("win_exec_count", 0))
    shells = float(win.get("win_shell_count", 0))
    f += [
        math.log1p(execs),
        math.log1p(float(win.get("win_distinct_bins", 0))),
        math.log1p(float(win.get("win_connect_count", 0))),
        math.log1p(float(win.get("win_distinct_dst", 0))),
        math.log1p(float(win.get("win_sensitive_opens", 0))),
        math.log1p(shells),
        float(win.get("win_new_binary", 0)),
        round(shells / execs, 4) if execs else 0.0,
    ]
    return f


assert len(FEATURE_NAMES) == len(extract({"event_type": "exec"}))


# --------------------------------------------------------------------------- live behaviour window
class BehaviorTracker:
    """Keeps a sliding window of activity per container and a binary baseline
    per workload, producing the ``win_*`` behavioural features at runtime."""

    def __init__(self, window=WINDOW_SECONDS, warmup=WARMUP_SECONDS, clock=time.monotonic):
        self.window = window
        self.warmup = warmup
        self.clock = clock
        self.recent: dict[str, deque] = {}
        self.baseline: dict[str, set] = {}
        self.first_seen: dict[str, float] = {}

    def observe(self, container_key: str, workload_key: str, ev: dict) -> dict:
        now = self.clock()
        dq = self.recent.setdefault(container_key, deque())
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

        et = ev.get("event_type")
        binname = binary_name(ev)
        dst = f"{ev.get('daddr', '')}:{ev.get('dport', 0)}" if et == "connect" else ""
        write = bool(int(ev.get("flags", 0) or 0) & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))
        sensitive = et == "open" and file_sensitivity(ev.get("path", ""), write) > 0
        dq.append((now, et, binname, dst, sensitive))

        new_binary = 0
        if et == "exec":
            self.first_seen.setdefault(workload_key, now)
            seen = self.baseline.setdefault(workload_key, set())
            if binname not in seen:
                if now - self.first_seen[workload_key] > self.warmup:
                    new_binary = 1
                seen.add(binname)

        execs = [x for x in dq if x[1] == "exec"]
        conns = [x for x in dq if x[1] == "connect"]
        return {
            "win_exec_count": len(execs),
            "win_distinct_bins": len({x[2] for x in execs}),
            "win_connect_count": len(conns),
            "win_distinct_dst": len({x[3] for x in conns}),
            "win_sensitive_opens": sum(1 for x in dq if x[4]),
            "win_shell_count": sum(1 for x in execs if x[2] in SHELLS),
            "win_new_binary": new_binary,
        }

    def gc(self, max_idle=600):
        now = self.clock()
        for k in [k for k, dq in self.recent.items() if not dq or now - dq[-1][0] > max_idle]:
            del self.recent[k]
