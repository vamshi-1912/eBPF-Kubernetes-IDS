"""Event Collection Module (user-space side).

Runs the libbpf loader (C) as a child process, parses its JSON-lines stream
and turns each kernel event into the normalised event dict used by the rest
of the pipeline.  The loader is restarted automatically if it dies.
"""
from __future__ import annotations

import json
import logging
import queue
import subprocess
import threading
import time

log = logging.getLogger("ids.collector")


def normalise(raw: dict, boot_offset_ns: int) -> dict:
    """Kernel record -> pipeline event (field names match the training CSV)."""
    et = raw.get("type", "unknown")
    argv = raw.get("argv") or []
    path = raw.get("path", "")
    if et == "exec":
        cmdline = " ".join(argv) if argv else path
        argc = len(argv) if argv else 1
    elif et == "mount":
        cmdline = " ".join(argv[:2])
        argc = 2
    else:
        cmdline, argc = "", 0
    family = raw.get("family", 0)
    return {
        "event_type": et,
        "ts_ns": raw.get("ts_ns", 0),
        "wall_ns": raw.get("ts_ns", 0) + boot_offset_ns,
        "cgroup_id": raw.get("cgroup_id", 0),
        "pid": raw.get("pid", 0),
        "tid": raw.get("tid", 0),
        "ppid": raw.get("ppid", 0),
        "uid": raw.get("uid", 0),
        "comm": raw.get("comm", ""),
        "parent_comm": raw.get("pcomm", ""),
        "path": path,
        "argv": argv,
        "cmdline": cmdline,
        "argc": argc,
        "flags": raw.get("arg_num", 0),
        "arg2": raw.get("arg_num2", 0),
        "family": family,
        "dport": raw.get("dport", 0),
        "daddr": raw.get("daddr", "") if family in (2, 10) else "",
    }


class Collector:
    def __init__(self, loader_path: str, max_queue: int = 200_000):
        self.loader_path = loader_path
        self.q: queue.Queue = queue.Queue(maxsize=max_queue)
        self.proc: subprocess.Popen | None = None
        self.loader_pid = 0
        self.kernel_emitted = 0
        self.kernel_dropped = 0
        self.queue_dropped = 0
        self.received = 0
        self.ready = threading.Event()
        self.attached = 0
        self._stop = threading.Event()
        # bpf_ktime_get_ns() is CLOCK_MONOTONIC -> convert to wall clock
        self.boot_offset_ns = time.time_ns() - time.monotonic_ns()

    def start(self):
        threading.Thread(target=self._run, name="loader-reader", daemon=True).start()

    def stop(self):
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def _run(self):
        backoff = 1.0
        while not self._stop.is_set():
            log.info("starting eBPF loader %s", self.loader_path)
            try:
                self.proc = subprocess.Popen([self.loader_path], stdout=subprocess.PIPE, bufsize=1 << 16)
            except OSError as e:
                log.error("cannot start loader: %s", e)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            self.loader_pid = self.proc.pid
            for line in self.proc.stdout:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                kind = rec.get("kind")
                if kind == "event":
                    self.received += 1
                    try:
                        self.q.put_nowait(normalise(rec, self.boot_offset_ns))
                    except queue.Full:
                        self.queue_dropped += 1
                elif kind == "stats":
                    self.kernel_emitted = rec.get("emitted", 0)
                    self.kernel_dropped = rec.get("dropped", 0)
                elif kind == "ready":
                    self.attached = rec.get("attached", 0)
                    log.info("eBPF monitor ready: %s tracepoints attached, %s failed",
                             rec.get("attached"), rec.get("failed"))
                    self.ready.set()
                    backoff = 1.0
            code = self.proc.wait()
            self.ready.clear()
            if self._stop.is_set():
                break
            log.error("loader exited with code %s; restarting in %.0fs", code, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

    def drain(self, max_items: int, timeout: float) -> list[dict]:
        items = []
        deadline = time.monotonic() + timeout
        while len(items) < max_items:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                items.append(self.q.get(timeout=remaining))
            except queue.Empty:
                break
            while len(items) < max_items:  # grab everything already queued
                try:
                    items.append(self.q.get_nowait())
                except queue.Empty:
                    break
        return items
