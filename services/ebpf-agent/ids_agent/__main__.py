"""eBPF IDS agent - runs the full pipeline on one node.

  eBPF monitor (C/libbpf) -> event collection -> Kubernetes enrichment
  -> valid context?  no  -> store raw event
                     yes -> feature extraction -> Random Forest + rules
  -> suspicious?     no  -> log event as normal
                     yes -> alert + risk/severity
  -> backend (FastAPI/MongoDB)          + overhead/latency metrics
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time

import numpy as np

from . import config
from .collector import Collector
from .detector import Detector, dedup_key
from .enrichment import K8sEnricher
from .features import WINDOW_SECONDS, BehaviorTracker, extract
from .metrics import Metrics
from .shipper import Shipper

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
log = logging.getLogger("ids.agent")

EVENT_FIELDS = ("event_type", "pid", "ppid", "uid", "comm", "parent_comm", "path", "cmdline", "argv",
                "flags", "arg2", "dport", "daddr")


def event_doc(ev: dict, k8s: dict, prediction: dict | None) -> dict:
    doc = {k: ev.get(k) for k in EVENT_FIELDS}
    doc.update(ts_ms=ev["wall_ns"] // 1_000_000, node=config.NODE_NAME, k8s=k8s, k8s_context=k8s.get("valid", False),
               prediction=prediction or {"scored": False})
    return doc


class Agent:
    def __init__(self):
        self.collector = Collector(config.LOADER_PATH)
        self.enricher = K8sEnricher(config.NODE_NAME, config.CGROUP_ROOT, config.PROC_ROOT, config.POD_REFRESH_INTERVAL)
        self.detector = Detector(config.MODEL_PATH, config.DETECTION_THRESHOLD)
        self.tracker = BehaviorTracker(window=WINDOW_SECONDS, warmup=config.WARMUP_SECONDS)
        self.shipper = Shipper(config.BACKEND_URL, config.AGENT_TOKEN, config.NODE_NAME)
        self.shipper.model_version = self.detector.version
        self.metrics = Metrics()
        self.running = True

    # ------------------------------------------------------------------ background tasks
    def _publish_evaluation(self):
        try:
            with open(config.EVALUATION_PATH) as fh:
                report = json.load(fh)
        except OSError:
            return
        while self.running and not self.shipper.post("/api/agent/evaluation", report):
            time.sleep(10)
        log.info("published offline evaluation report for model %s", report.get("model_version"))

    def _heartbeat(self):
        while self.running:
            time.sleep(config.HEARTBEAT_INTERVAL)
            snap = self.metrics.snapshot({"agent": os.getpid(), "loader": self.collector.loader_pid})
            snap.update(node=config.NODE_NAME, pod=config.POD_NAME, agent_version=config.AGENT_VERSION,
                        model_version=self.detector.version, loader_ready=self.collector.ready.is_set(),
                        tracepoints_attached=self.collector.attached,
                        kernel_events_emitted=self.collector.kernel_emitted,
                        kernel_events_dropped=self.collector.kernel_dropped,
                        queue_dropped=self.collector.queue_dropped, queue_depth=self.collector.q.qsize(),
                        shipped_events=self.shipper.sent_events, shipped_alerts=self.shipper.sent_alerts,
                        ship_failures=self.shipper.failures, pods_known=len(self.enricher.pods))
            self.shipper.post("/api/agent/heartbeat", snap)
            self.enricher.refresh_pods()
            self.tracker.gc()

    # ------------------------------------------------------------------ main loop
    def process(self, batch: list[dict]):
        scored, events_out, alerts_out = [], [], []
        for ev in batch:
            self.metrics.processed += 1
            self.metrics.by_type[ev["event_type"]] += 1
            k8s = self.enricher.enrich(ev)
            if k8s.get("valid") and k8s.get("pod") == config.POD_NAME and k8s.get("namespace") == config.POD_NAMESPACE:
                continue  # never analyse ourselves
            if not k8s.get("valid"):
                # "Valid Kubernetes context? -> No -> store raw event & continue"
                self.metrics.raw += 1
                if config.STORE_RAW_EVENTS:
                    events_out.append(event_doc(ev, k8s, None))
                continue
            ev["namespace"] = k8s["namespace"]
            container_key = k8s.get("container_id") or k8s["pod_uid"]
            workload_key = f"{k8s['namespace']}/{k8s['workload_kind']}/{k8s['workload']}/{k8s['container']}"
            win = self.tracker.observe(container_key, workload_key, ev)
            scored.append((ev, k8s, win, extract(ev, win)))

        if scored:
            t0 = time.perf_counter()
            X = np.asarray([s[3] for s in scored], dtype=np.float32)
            p_mal, cats = self.detector.predict(X)
            self.metrics.record_batch(len(scored), time.perf_counter() - t0)
            self.metrics.scored += len(scored)
            for (ev, k8s, win, fvec), p, cat in zip(scored, p_mal, cats):
                d = self.detector.assess(ev, k8s, fvec, float(p), cat)
                latency_ms = (time.monotonic_ns() - ev["ts_ns"]) / 1e6
                self.metrics.latencies_ms.append(latency_ms)
                pred = {"scored": True, "label": "suspicious" if d["suspicious"] else "normal",
                        "probability": d["probability"], "category": d["category"], "risk_score": d["risk_score"],
                        "severity": d["severity"], "rules": [r["id"] for r in d["rules"]],
                        "latency_ms": round(latency_ms, 2), "model_version": self.detector.version}
                if d["suspicious"] or config.STORE_NORMAL_EVENTS:
                    events_out.append(event_doc(ev, k8s, pred))
                if d["suspicious"]:
                    self.metrics.alerts += 1
                    self.metrics.alert_latencies_ms.append(latency_ms)
                    alert = {
                        "ts_ms": ev["wall_ns"] // 1_000_000, "node": config.NODE_NAME, "k8s": k8s,
                        "severity": d["severity"], "risk_score": d["risk_score"], "probability": d["probability"],
                        "ml_detected": d["ml_detected"], "ml_category": d["ml_category"], "category": d["category"],
                        "title": d["title"], "mitre": d["mitre"], "tactic": d["tactic"], "rules": d["rules"],
                        "detection_latency_ms": round(latency_ms, 2), "model_version": self.detector.version,
                        "window": win, "event": {k: ev.get(k) for k in EVENT_FIELDS},
                        "dedup_key": dedup_key(ev, k8s, d),
                    }
                    alerts_out.append(alert)
                    if config.LOG_ALERTS:
                        log.warning("ALERT %-6s %5.1f %s/%s [%s] %s: %s", d["severity"], d["risk_score"],
                                    k8s["namespace"], k8s["pod"], d["category"], d["title"],
                                    (ev.get("cmdline") or ev.get("path") or f"{ev.get('daddr')}:{ev.get('dport')}")[:120])
        if events_out or alerts_out:
            self.shipper.enqueue(events_out, alerts_out)

    def run(self):
        self.enricher.refresh_pods(force=True)
        self.collector.start()
        self.shipper.start()
        threading.Thread(target=self._heartbeat, name="heartbeat", daemon=True).start()
        threading.Thread(target=self._publish_evaluation, name="evaluation", daemon=True).start()
        log.info("agent %s on node %s, backend %s", config.AGENT_VERSION, config.NODE_NAME, config.BACKEND_URL)
        while self.running:
            batch = self.collector.drain(config.MAX_BATCH, config.BATCH_INTERVAL)
            if batch:
                try:
                    self.process(batch)
                except Exception:  # noqa: BLE001
                    log.exception("batch processing failed")

    def stop(self, *_):
        self.running = False
        self.collector.stop()


def main():
    agent = Agent()
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()


if __name__ == "__main__":
    main()
