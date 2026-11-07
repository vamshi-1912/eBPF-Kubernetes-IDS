"""Ships events, alerts and agent metrics to the FastAPI backend."""
from __future__ import annotations

import collections
import logging
import threading
import time

import requests

log = logging.getLogger("ids.shipper")


class Shipper:
    def __init__(self, base_url: str, token: str, node: str, max_events: int = 50_000):
        self.base = base_url.rstrip("/")
        self.node = node
        self.session = requests.Session()
        self.session.headers.update({"X-Agent-Token": token, "Content-Type": "application/json"})
        self.events: collections.deque = collections.deque(maxlen=max_events)  # normal/raw: lossy
        self.alerts: collections.deque = collections.deque()                  # alerts: kept until sent
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.sent_events = self.sent_alerts = self.failures = 0
        self.last_error = ""
        self.model_version = ""

    def start(self):
        threading.Thread(target=self._loop, name="shipper", daemon=True).start()

    def enqueue(self, events: list[dict], alerts: list[dict]):
        with self.lock:
            self.events.extend(events)
            self.alerts.extend(alerts)
        if alerts or len(self.events) > 1000:
            self.wake.set()

    def _loop(self):
        backoff = 1.0
        while True:
            self.wake.wait(timeout=1.0)
            self.wake.clear()
            with self.lock:
                alerts = [self.alerts.popleft() for _ in range(min(len(self.alerts), 500))]
                events = [self.events.popleft() for _ in range(min(len(self.events), 2000))]
            if not alerts and not events:
                continue
            try:
                r = self.session.post(f"{self.base}/api/ingest", json={
                    "node": self.node, "model_version": self.model_version, "events": events, "alerts": alerts},
                    timeout=15)
                r.raise_for_status()
                self.sent_events += len(events)
                self.sent_alerts += len(alerts)
                backoff = 1.0
            except requests.RequestException as e:
                self.failures += 1
                self.last_error = str(e)[:200]
                log.warning("ingest failed (%s); retrying in %.0fs", self.last_error, backoff)
                with self.lock:
                    self.alerts.extendleft(reversed(alerts))  # never lose alerts
                    self.events.extendleft(reversed(events))
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)

    def post(self, path: str, payload: dict) -> bool:
        try:
            r = self.session.post(f"{self.base}{path}", json=payload, timeout=10)
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            self.last_error = str(e)[:200]
            log.debug("POST %s failed: %s", path, e)
            return False
