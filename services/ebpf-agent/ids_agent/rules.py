"""Detection Module - deterministic rules.

High-precision signatures that complement the Random Forest.  Each rule sees
the normalised event and its named feature vector.  Platform components
(kube-system, CoreDNS, runc, ...) are exempted where the behaviour is part of
normal cluster operation, which is what eliminated the v0 "runc contains nc"
false positive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .features import SHELLS, basename

TOOLS_FOR_TOKEN_THEFT = SHELLS | {"cat", "head", "tail", "less", "more", "base64", "curl", "wget", "cp", "tar",
                                  "nc", "strings", "xxd", "od", "dd", "grep", "awk", "sed", "vi", "vim", "nano"}
MINER_PORTS = {3333, 14444, 14433, 45700, 10128, 45560}
CONTROL_PLANE_PORTS = {10250, 10255, 2379, 2380}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str  # High | Medium | Low
    category: str
    mitre: str
    test: Callable[[dict, dict], bool]


def _platform(f):
    return f["ns_system"] or f["proc_is_k8s_component"]


RULES: list[Rule] = [
    Rule("R001", "Reverse shell command line", "High", "reverse_shell", "T1059.004",
         lambda e, f: f["args_reverse_shell"] and e["event_type"] == "exec"),
    Rule("R002", "Shell/interpreter connecting to a suspicious port", "High", "reverse_shell", "T1571",
         lambda e, f: f["ev_connect"] and f["net_port_suspicious"] and not _platform(f)
         and (f["bin_is_shell"] or f["bin_is_interpreter"] or f["bin_is_net_tool"])),
    Rule("R003", "Service-account token read by a shell tool", "High", "credential_access", "T1528",
         lambda e, f: f["ev_open"] and e["path"].startswith(("/var/run/secrets", "/run/secrets"))
         and e["comm"] in TOOLS_FOR_TOKEN_THEFT and not f["ns_system"]),
    Rule("R004", "Password database read", "High", "credential_access", "T1003.008",
         lambda e, f: f["ev_open"] and e["path"].startswith(("/etc/shadow", "/etc/gshadow"))
         and not f["proc_is_auth_binary"]),
    Rule("R005", "Crypto-miner activity", "High", "crypto_miner", "T1496",
         lambda e, f: f["args_miner"] or (f["ev_connect"] and e.get("dport") in MINER_PORTS and not _platform(f))),
    Rule("R006", "Download piped into a shell", "High", "dropper", "T1105",
         lambda e, f: bool(f["args_download_exec"])),
    Rule("R007", "Binary executed from a temp / hidden location", "Medium", "dropper", "T1204.002",
         lambda e, f: f["ev_exec"] and (f["bin_in_tmp"] or f["bin_hidden"]) and "/go-build" not in e["path"]
         and not _platform(f)),
    Rule("R008", "Kernel module loaded from a pod", "High", "container_escape", "T1547.006",
         lambda e, f: f["ev_module"] and not f["ns_system"]),
    Rule("R009", "Process injection via ptrace", "Medium", "container_escape", "T1055.008",
         lambda e, f: f["ptrace_attach"] and not f["proc_is_debugger"] and not _platform(f)),
    Rule("R010", "SUID/SGID bit set on a binary", "High", "privilege_escalation", "T1548.001",
         lambda e, f: (f["ev_chmod"] and (e.get("flags", 0) & 0o4000)) or f["args_suid"]),
    Rule("R011", "Web/server process spawned a shell or recon tool", "Medium", "discovery", "T1190",
         lambda e, f: f["ev_exec"] and f["parent_is_server"] and (f["bin_is_shell"] or f["bin_is_recon"]
                                                                  or f["bin_is_net_tool"])),
    Rule("R012", "Fileless execution (memfd / fd exec)", "High", "defense_evasion", "T1620",
         lambda e, f: f["bin_fileless"] or (f["ev_memfd"] and not f["memfd_benign_name"] and not _platform(f))),
    Rule("R013", "Log or shell-history tampering", "Medium", "defense_evasion", "T1070",
         lambda e, f: bool(f["args_cleanup"])),
    Rule("R014", "Container escape technique", "High", "container_escape", "T1611",
         lambda e, f: not _platform(f) and (
             (f["ev_exec"] and basename(e["path"]) == "nsenter" and ("-t 1" in e["cmdline"] or "--target 1" in e["cmdline"]))
             or (f["ev_mount"] and (f["mount_block_device"] or "cgroup" in e["cmdline"]))
             or f["unshare_userns"]
             or (f["ev_connect"] and f["net_family_unix"])
             or (f["ev_open"] and f["file_write"] and e["path"].startswith(("/proc/sys/kernel/core_pattern",
                                                                            "/proc/sys/kernel/modprobe")))
             or (f["ev_exec"] and any(s in e["cmdline"] for s in ("release_agent", "core_pattern", "/proc/1/root",
                                                                   "docker.sock")))
             or (f["ev_open"] and e["path"].startswith(("/proc/kcore", "/dev/mem"))))),
    Rule("R015", "Cloud metadata endpoint access", "Medium", "credential_access", "T1552.005",
         lambda e, f: (f["ev_connect"] and e.get("daddr") == "169.254.169.254") or "169.254.169.254" in e["cmdline"]),
    Rule("R016", "Persistence / auth file modified", "High", "privilege_escalation", "T1098",
         lambda e, f: f["ev_open"] and f["file_write"] and not f["proc_is_auth_binary"] and e["path"].startswith(
             ("/etc/sudoers", "/etc/shadow", "/etc/ld.so.preload", "/etc/crontab", "/var/spool/cron",
              "/etc/cron.", "/root/.ssh/authorized_keys"))),
    Rule("R017", "Kubelet / etcd API accessed from a workload", "High", "lateral_movement", "T1210",
         lambda e, f: f["ev_connect"] and e.get("dport") in CONTROL_PLANE_PORTS and not _platform(f)),
    Rule("R018", "Network scanning tool", "Medium", "discovery", "T1046",
         lambda e, f: f["ev_exec"] and (basename(e["path"]) in ("nmap", "masscan", "zmap")
                                        or (" -zv " in f" {e['cmdline']} " and "-" in e["cmdline"].split()[-1]))),
    Rule("R019", "Privilege escalation to root by non-auth binary", "High", "privilege_escalation", "T1068",
         lambda e, f: f["setuid_to_root"] and int(e.get("uid", 0)) != 0 and not f["proc_is_auth_binary"]),
]


def evaluate(ev: dict, feats: dict) -> list[Rule]:
    hits = []
    for r in RULES:
        try:
            if r.test(ev, feats):
                hits.append(r)
        except Exception:  # noqa: BLE001 - a broken rule must never stop the sensor
            continue
    return hits
