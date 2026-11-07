"""Evaluation Module (online part): agent overhead and detection latency."""
from __future__ import annotations

import collections
import os
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")


def proc_usage(pid: int, proc_root: str = "/proc"):
    """(cpu_seconds, rss_bytes) for a pid, or (None, None)."""
    try:
        with open(f"{proc_root}/{pid}/stat") as fh:
            parts = fh.read().rsplit(")", 1)[1].split()
        with open(f"{proc_root}/{pid}/statm") as fh:
            rss_pages = int(fh.read().split()[1])
        return (int(parts[11]) + int(parts[12])) / CLK_TCK, rss_pages * PAGE
    except (OSError, IndexError, ValueError):
        return None, None


class Metrics:
    def __init__(self):
        self.latencies_ms: collections.deque = collections.deque(maxlen=5000)  # kernel event -> decision
        self.alert_latencies_ms: collections.deque = collections.deque(maxlen=1000)
        self.inference_ms: collections.deque = collections.deque(maxlen=1000)  # per event
        self.processed = self.scored = self.raw = self.alerts = 0
        self.by_type: collections.Counter = collections.Counter()
        self._last = {"t": time.monotonic(), "processed": 0, "cpu": {}}

    def record_batch(self, n_scored: int, infer_seconds: float):
        if n_scored:
            self.inference_ms.append(infer_seconds * 1000 / n_scored)

    def snapshot(self, pids: dict[str, int]) -> dict:
        now = time.monotonic()
        dt = max(now - self._last["t"], 1e-6)
        out = {"events_per_sec": round((self.processed - self._last["processed"]) / dt, 2)}
        total_cpu, total_rss = 0.0, 0
        for name, pid in pids.items():
            cpu_s, rss = proc_usage(pid)
            if cpu_s is None:
                continue
            prev = self._last["cpu"].get(name)
            pct = 100.0 * (cpu_s - prev) / dt if prev is not None else 0.0
            self._last["cpu"][name] = cpu_s
            out[f"{name}_cpu_percent"] = round(pct, 2)
            out[f"{name}_rss_mb"] = round(rss / 1048576, 1)
            total_cpu += pct
            total_rss += rss
        out["cpu_percent"] = round(total_cpu, 2)
        out["rss_mb"] = round(total_rss / 1048576, 1)

        def pctl(values, q):
            if not values:
                return None
            s = sorted(values)
            return round(s[min(len(s) - 1, int(q * len(s)))], 2)

        lat = list(self.latencies_ms)
        out.update(
            latency_avg_ms=round(sum(lat) / len(lat), 2) if lat else None, latency_p50_ms=pctl(lat, 0.5),
            latency_p95_ms=pctl(lat, 0.95), latency_p99_ms=pctl(lat, 0.99),
            alert_latency_avg_ms=round(sum(self.alert_latencies_ms) / len(self.alert_latencies_ms), 2)
            if self.alert_latencies_ms else None,
            inference_ms_per_event=round(sum(self.inference_ms) / len(self.inference_ms), 4) if self.inference_ms else None,
            processed_total=self.processed, scored_total=self.scored, raw_total=self.raw, alerts_total=self.alerts,
            by_type=dict(self.by_type))
        self._last["t"], self._last["processed"] = now, self.processed
        return out
