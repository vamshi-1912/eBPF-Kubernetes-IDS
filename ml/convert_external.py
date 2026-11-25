"""Convert public datasets into the agent's event schema (ml/training_data.csv columns).

Supported sources
-----------------
beth        BETH (Highnam et al. 2021, eBPF honeypot kernel logs, Kaggle "katehighnam/beth-dataset").
            Only kernel events the SecureSME sensor also captures are kept:
                execve              -> exec     (path, argv; caller's comm becomes parent_comm)
                security_file_open  -> open     (pathname, O_* flags)   [openat/open skipped: duplicates]
                connect             -> connect  (AF_INET/AF_INET6 port+addr, AF_UNIX path)
                setuid / setreuid   -> setuid   (target uid)
                chmod / fchmod      -> chmod    (mode)
                mount               -> mount
                memfd_create        -> memfd
            Label: is_malicious = evil (``sus`` kept as an extra column).
            BETH has no Kubernetes context (namespace = "") and no attack categories.

isovalent   Splunk attack_data "cisco_isovalent_k8_escape" (Tetragon process_exec JSON lines).
            One privileged-pod escape session (nsenter -t 1).  Every event is hand-labelled:
              is_malicious          attacker actions (nsenter, host shell, recon, key theft, mount)
              is_malicious_session  everything descending from nsenter (incl. shell-profile noise)

Behavioural window columns (win_*) are produced by the agent's own BehaviorTracker,
replayed on the event timestamps, keyed per host+mount-namespace (BETH) or per pod (Tetragon).

Usage:
    python ml/convert_external.py beth      datasets/labelled_*.csv     --out datasets/converted/beth.csv
    python ml/convert_external.py isovalent datasets/cisco_isovalent.txt --out datasets/converted/isovalent.csv
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import re
import shlex
import sys
from collections import Counter
from datetime import datetime

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "services", "ebpf-agent"))
from ids_agent.features import COMM_LEN, BehaviorTracker, basename, truncate_cmdline  # noqa: E402

BASE_COLUMNS = ["event_type", "comm", "parent_comm", "uid", "path", "cmdline", "argc", "flags", "arg2",
                "dport", "daddr", "namespace", "win_exec_count", "win_distinct_bins", "win_connect_count",
                "win_distinct_dst", "win_sensitive_opens", "win_shell_count", "win_new_binary",
                "is_malicious", "attack_category", "mitre_technique", "template", "is_edge_case"]

O_FLAGS = {"O_WRONLY": 0o1, "O_RDWR": 0o2, "O_CREAT": 0o100, "O_TRUNC": 0o1000, "O_APPEND": 0o2000}
RE_PORT = re.compile(r"'sin6?_port':\s*'(\d+)'")
RE_ADDR = re.compile(r"'sin6?_addr':\s*'([^']+)'")
RE_UNIX = re.compile(r"'sun_path':\s*'([^']*)'")
RE_FAMILY = re.compile(r"'sa_family':\s*'(\w+)'")


def _args(raw: str) -> dict:
    if not raw or raw == "[]":
        return {}
    try:
        return {a["name"]: a["value"] for a in ast.literal_eval(raw)}
    except (ValueError, SyntaxError):
        return {}


def _open_flags(v) -> int:
    if isinstance(v, int):
        return v
    return sum(O_FLAGS.get(p.strip(), 0) for p in str(v).split("|"))


def _int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------------------------------ BETH
class FastTracker(BehaviorTracker):
    """Same output as ids_agent.features.BehaviorTracker, but O(1) per event.

    The agent's tracker rescans the whole 60 s window on every event, which is
    quadratic on BETH's SSH-scanner bursts (~145k connects).  Here the window
    aggregates are maintained incrementally as events enter and leave.
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self.agg: dict[str, dict] = {}

    def observe(self, container_key: str, workload_key: str, ev: dict) -> dict:
        from ids_agent.features import (O_APPEND, O_CREAT, O_RDWR, O_TRUNC, O_WRONLY, SHELLS, binary_name,
                                        file_sensitivity)
        now = self.clock()
        dq = self.recent.setdefault(container_key, __import__("collections").deque())
        g = self.agg.setdefault(container_key, {"bins": Counter(), "dsts": Counter(), "execs": 0, "conns": 0,
                                                "sens": 0, "shells": 0})
        while dq and now - dq[0][0] > self.window:
            _, et0, b0, d0, s0 = dq.popleft()
            self._add(g, et0, b0, d0, s0, SHELLS, -1)

        et = ev.get("event_type")
        binname = binary_name(ev)
        dst = f"{ev.get('daddr', '')}:{ev.get('dport', 0)}" if et == "connect" else ""
        write = bool(int(ev.get("flags", 0) or 0) & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))
        sensitive = et == "open" and file_sensitivity(ev.get("path", ""), write) > 0
        dq.append((now, et, binname, dst, sensitive))
        self._add(g, et, binname, dst, sensitive, SHELLS, +1)

        new_binary = 0
        if et == "exec":
            self.first_seen.setdefault(workload_key, now)
            seen = self.baseline.setdefault(workload_key, set())
            if binname not in seen:
                if now - self.first_seen[workload_key] > self.warmup:
                    new_binary = 1
                seen.add(binname)
        return {"win_exec_count": g["execs"], "win_distinct_bins": len(g["bins"]), "win_connect_count": g["conns"],
                "win_distinct_dst": len(g["dsts"]), "win_sensitive_opens": g["sens"], "win_shell_count": g["shells"],
                "win_new_binary": new_binary}

    @staticmethod
    def _add(g, et, binname, dst, sensitive, shells, d):
        g["sens"] += d * int(bool(sensitive))
        if et == "exec":
            g["execs"] += d
            g["shells"] += d * int(binname in shells)
            g["bins"][binname] += d
            if g["bins"][binname] <= 0:
                del g["bins"][binname]
        elif et == "connect":
            g["conns"] += d
            g["dsts"][dst] += d
            if g["dsts"][dst] <= 0:
                del g["dsts"][dst]


BETH_EVENTS = {"execve", "security_file_open", "connect", "setuid", "setreuid", "chmod", "fchmod", "mount",
               "memfd_create"}


def beth_event(r: dict, name_by_pid: dict) -> dict | None:
    en = r["eventName"]
    a = _args(r["args"])
    comm = str(r["processName"])[:COMM_LEN]
    ev = dict(event_type="", comm=comm, parent_comm=name_by_pid.get(r["parentProcessId"], ""),
              uid=_int(r["userId"]), path="", cmdline="", argc=0, flags=0, arg2=0, dport=0, daddr="", namespace="")
    if en == "execve":
        argv = truncate_cmdline([str(x) for x in (a.get("argv") or [])])
        path = str(a.get("pathname", ""))
        # execve fires in the caller before the image is replaced: the caller is the parent of the new image
        ev.update(event_type="exec", parent_comm=comm, path=path,
                  comm=(basename(path) or comm)[:COMM_LEN],
                  cmdline=" ".join(argv) if argv else path, argc=len(argv) if argv else 1)
    elif en == "security_file_open":
        ev.update(event_type="open", path=str(a.get("pathname", "")), flags=_open_flags(a.get("flags", 0)))
    elif en == "connect":
        addr = str(a.get("addr", ""))
        fam = (RE_FAMILY.search(addr) or [None, ""])[1]
        if fam in ("AF_INET", "AF_INET6"):
            ev.update(event_type="connect", dport=_int((RE_PORT.search(addr) or [0, 0])[1]),
                      daddr=(RE_ADDR.search(addr) or [0, ""])[1], flags=2 if fam == "AF_INET" else 10)
        elif fam == "AF_UNIX":
            ev.update(event_type="connect", path=(RE_UNIX.search(addr) or [0, ""])[1], flags=1)
        else:
            return None
    elif en in ("setuid", "setreuid"):
        uid = a.get("uid", a.get("euid", a.get("ruid", -1)))
        if _int(uid, -1) < 0:
            return None
        ev.update(event_type="setuid", flags=_int(uid))
    elif en in ("chmod", "fchmod"):
        ev.update(event_type="chmod", path=str(a.get("pathname", "")), flags=_int(a.get("mode", 0)))
    elif en == "mount":
        src, tgt, fst = (str(a.get(k, "")) for k in ("source", "target", "filesystemtype"))
        ev.update(event_type="mount", path=tgt, cmdline=f"{src} {fst}".strip(), argc=2)
    elif en == "memfd_create":
        ev.update(event_type="memfd", path=str(a.get("name", "")))
    else:
        return None
    return ev


BETH_OUT_COLUMNS = BASE_COLUMNS + ["sus", "host", "source_file"]
BETH_USECOLS = ["timestamp", "processId", "parentProcessId", "userId", "mountNamespace", "processName", "hostName",
                "eventName", "args", "sus", "evil"]


def _load_beth(f: str) -> pd.DataFrame:
    """Chunked read; ``args`` (the bulk of the file) is blanked for event types that are dropped anyway."""
    header = pd.read_csv(f, nrows=0).columns
    cols = [c for c in BETH_USECOLS if c in header]
    parts = []
    for ch in pd.read_csv(f, usecols=cols, chunksize=200_000):
        ch.loc[~ch["eventName"].isin(BETH_EVENTS), "args"] = ""
        ch["processName"] = ch["processName"].astype(str).str.slice(0, COMM_LEN)
        parts.append(ch)
    df = pd.concat(parts, ignore_index=True)
    return df.sort_values(["hostName", "timestamp"], kind="stable")


def convert_beth_file(f: str, out_part: str) -> dict:
    """Convert one BETH CSV into ``out_part``; returns statistics.  Runs in a worker process."""
    df = _load_beth(f)
    has_mnt = "mountNamespace" in df.columns
    skipped, kept_types = Counter(), Counter()
    clock = [0.0]
    trackers: dict[str, FastTracker] = {}
    name_by_pid: dict = {}
    last_host, n_out = None, 0
    src = os.path.basename(f)
    with open(out_part, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=BETH_OUT_COLUMNS)
        w.writeheader()
        cols = list(df.columns)
        for tup in df.itertuples(index=False, name=None):
            r = dict(zip(cols, tup))
            host = r["hostName"]
            if host != last_host:
                name_by_pid, last_host = {}, host
            name_by_pid[r["processId"]] = r["processName"]
            ev = beth_event(r, name_by_pid) if r["eventName"] in BETH_EVENTS else None
            evil = int(r["evil"])
            if ev is None:
                skipped[evil] += 1
                continue
            clock[0] = float(r["timestamp"])
            tr = trackers.setdefault(host, FastTracker(clock=lambda: clock[0]))
            key = f"{host}:{r['mountNamespace']}" if has_mnt else host
            ev.update(tr.observe(key, key, ev))
            kept_types[(ev["event_type"], evil)] += 1
            ev.update(is_malicious=evil, attack_category="malicious_unlabelled" if evil else "benign",
                      mitre_technique="", template=f"{ev['event_type']}/{'evil' if evil else 'benign'}",
                      is_edge_case=0, sus=int(r["sus"]), host=host, source_file=src)
            w.writerow(ev)
            n_out += 1
    stats = {"file": src, "raw": len(df), "raw_evil": int(df["evil"].sum()), "kept": n_out,
             "dropped_benign": skipped[0], "dropped_evil": skipped[1], "kept_types": dict(kept_types)}
    print(f"  done {src}: {stats['raw']} raw -> {n_out} kept", flush=True)
    return stats


def convert_beth(files: list[str], out: str, workers: int) -> None:
    from concurrent.futures import ProcessPoolExecutor
    files = sorted((f for f in files if not f.endswith("-dns.csv")), key=os.path.getsize, reverse=True)
    part_dir = os.path.join(os.path.dirname(os.path.abspath(out)), "beth_parts")
    os.makedirs(part_dir, exist_ok=True)
    parts = [os.path.join(part_dir, os.path.basename(f)) for f in files]
    print(f"  converting {len(files)} files with {workers} worker processes", flush=True)
    with ProcessPoolExecutor(max_workers=workers, max_tasks_per_child=1) as ex:
        stats = list(ex.map(convert_beth_file, files, parts))
    with open(out, "w", newline="") as fo:  # concatenate parts (header once)
        for i, p in enumerate(parts):
            with open(p) as fi:
                header = fi.readline()
                if i == 0:
                    fo.write(header)
                for line in fi:
                    fo.write(line)
            os.remove(p)
    os.rmdir(part_dir)
    kept_types = Counter()
    for st in stats:
        kept_types.update(st["kept_types"])
        print(f"  {st['file']:<40} raw={st['raw']:>8} (evil {st['raw_evil']:>6})  kept={st['kept']:>7}")
    print(f"  kept {sum(s['kept'] for s in stats)} events; dropped {sum(s['dropped_benign'] for s in stats)} benign"
          f" + {sum(s['dropped_evil'] for s in stats)} evil events of types the sensor does not capture")
    for (t, evil), n in sorted(kept_types.items()):
        print(f"    {t:<8} {'evil' if evil else 'benign':<7} {n}")
    print(f"Wrote {sum(s['kept'] for s in stats)} rows -> {out}")


# ------------------------------------------------------------------------------------------ Tetragon
def _label_isovalent(binary: str, args: str, parent: str, chain: list[str]) -> tuple[int, int, str]:
    """(is_malicious, is_malicious_session, note)."""
    b = basename(binary)
    session = int(b == "nsenter" or "nsenter" in chain)
    if b == "nsenter" and ("--target 1" in args or "-t 1" in args):
        return 1, 1, "container escape (nsenter into PID 1 namespaces)"
    if session and b in ("sh", "bash") and basename(parent) == "nsenter":
        return 1, 1, "interactive shell on the host"
    if session and b == "mount":
        return 1, 1, "mounting host procfs"
    if session and "authorized_keys" in args:
        return 1, 1, "reading root SSH authorized_keys"
    if session and b in ("ps", "ls") and basename(parent) in ("sh", "bash"):
        return 1, 1, "host reconnaissance"
    if session:
        return 0, 1, "login-shell profile noise after escape"
    return 0, 0, "pod start / kubectl exec"


def convert_isovalent(files: list[str]) -> list[dict]:
    recs = []
    for f in files:
        for line in open(f):
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if "process_exec" not in e:
                continue
            recs.append(e["process_exec"])
    recs.sort(key=lambda x: x["process"]["start_time"])
    clock = [0.0]
    tracker = BehaviorTracker(clock=lambda: clock[0])
    rows = []
    for x in recs:
        p, par = x["process"], x.get("parent", {})
        chain = [basename(a.get("binary", "")) for a in [par] + x.get("ancestors", [])]
        args = p.get("arguments", "") or ""
        try:
            argv = [basename(p["binary"])] + shlex.split(args)
        except ValueError:
            argv = [basename(p["binary"])] + args.split()
        argv = truncate_cmdline(argv)
        pod = p.get("pod", {})
        ev = dict(event_type="exec", comm=basename(p["binary"])[:COMM_LEN],
                  parent_comm=basename(par.get("binary", ""))[:COMM_LEN], uid=_int(p.get("uid")), path=p["binary"],
                  cmdline=" ".join(argv), argc=len(argv), flags=0, arg2=0, dport=0, daddr="",
                  namespace=pod.get("namespace", ""))
        ts = datetime.fromisoformat(p["start_time"].rstrip("Z")[:26] + "+00:00")  # ns -> us precision
        clock[0] = ts.timestamp()
        key = f"{pod.get('namespace')}/{pod.get('name')}"
        ev.update(tracker.observe(key, key, ev))
        mal, sess, note = _label_isovalent(p["binary"], args, par.get("binary", ""), chain)
        ev.update(is_malicious=mal, is_malicious_session=sess,
                  attack_category="container_escape" if mal else "benign",
                  mitre_technique="T1611" if mal else "", template=note, is_edge_case=int(sess and not mal),
                  privileged=int(bool(pod.get("container", {}).get("security_context", {}).get("privileged"))))
        rows.append(ev)
    c = Counter(r["template"] for r in rows)
    print(f"  {len(rows)} exec events: {sum(r['is_malicious'] for r in rows)} malicious actions, "
          f"{sum(r['is_malicious_session'] for r in rows)} in attack session")
    for t, n in c.most_common():
        print(f"    {n:>3}  {t}")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("source", choices=["beth", "isovalent"])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1, help="BETH: parallel worker processes")
    a = ap.parse_args()
    if a.source == "beth":
        convert_beth(a.files, a.out, a.workers)
        return
    rows = convert_isovalent(a.files)
    extra = [k for k in rows[0] if k not in BASE_COLUMNS]
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=BASE_COLUMNS + extra)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {a.out}")


if __name__ == "__main__":
    main()
