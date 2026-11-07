"""Kubernetes Enrichment Module.

Maps every kernel event to its Pod, container, namespace and workload:

    cgroup id (from eBPF) --> cgroup path (inode scan of /sys/fs/cgroup)
                          --> pod UID + container ID (regex on the path)
                          --> Pod metadata (Kubernetes API, cached per node)

Events whose cgroup does not belong to a pod (node daemons such as kubelet,
dockerd, sshd) have no valid Kubernetes context; the pipeline stores them as
raw events without ML scoring, exactly as in the design flowchart.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time

import requests

log = logging.getLogger("ids.enrichment")

RE_POD_UID = re.compile(r"pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})")
RE_CONTAINER_ID = re.compile(r"([0-9a-f]{64})")
RE_CRONJOB_SUFFIX = re.compile(r"-\d{8,}$")

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class CgroupResolver:
    """cgroup v2 id == inode number of the cgroup directory."""

    def __init__(self, root: str, proc_root: str = "/proc", min_rescan: float = 2.0):
        self.root = root
        self.proc_root = proc_root
        self.min_rescan = min_rescan
        self.paths: dict[int, str] = {}
        self._last_scan = 0.0

    def _scan(self):
        self._last_scan = time.monotonic()
        found = {}
        if not os.path.isdir(self.root):
            return
        for dirpath, dirnames, _ in os.walk(self.root):
            try:
                found[os.stat(dirpath).st_ino] = dirpath[len(self.root):] or "/"
            except OSError:
                pass
            # pods never live below a container scope; prune for speed
            dirnames[:] = [d for d in dirnames if not d.endswith(".mount")]
        self.paths = found

    def resolve(self, cgroup_id: int, pid: int = 0) -> str:
        path = self.paths.get(cgroup_id)
        if path is None and time.monotonic() - self._last_scan > self.min_rescan:
            self._scan()
            path = self.paths.get(cgroup_id)
        if path is None and pid:
            # fallback: the process may still be alive
            try:
                with open(f"{self.proc_root}/{pid}/cgroup") as fh:
                    for line in fh:
                        if line.startswith("0::"):
                            path = line[3:].strip()
                            break
            except OSError:
                pass
        return path or ""


class KubeClient:
    def __init__(self):
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.enabled = bool(host) and os.path.exists(f"{SA_DIR}/token")
        self.base = f"https://{host}:{port}" if host else ""
        self.session = requests.Session()
        if self.enabled:
            self.session.verify = f"{SA_DIR}/ca.crt"

    def list_pods(self, node: str) -> list[dict]:
        if not self.enabled:
            return []
        with open(f"{SA_DIR}/token") as fh:  # token is rotated by the kubelet
            token = fh.read().strip()
        r = self.session.get(f"{self.base}/api/v1/pods", params={"fieldSelector": f"spec.nodeName={node}"},
                             headers={"Authorization": f"Bearer {token}"}, timeout=10)
        r.raise_for_status()
        return r.json().get("items", [])


def workload_of(pod: dict) -> tuple[str, str]:
    meta = pod.get("metadata", {})
    owners = meta.get("ownerReferences") or []
    if not owners:
        return "Pod", meta.get("name", "")
    o = next((x for x in owners if x.get("controller")), owners[0])
    kind, name = o.get("kind", ""), o.get("name", "")
    if kind == "ReplicaSet":
        h = (meta.get("labels") or {}).get("pod-template-hash")
        if h and name.endswith("-" + h):
            return "Deployment", name[: -len(h) - 1]
        return "ReplicaSet", name
    if kind == "Job" and RE_CRONJOB_SUFFIX.search(name):
        return "CronJob", RE_CRONJOB_SUFFIX.sub("", name)
    if kind == "Node":
        return "StaticPod", meta.get("name", "")
    return kind, name


class K8sEnricher:
    def __init__(self, node: str, cgroup_root: str, proc_root: str = "/proc", refresh: float = 15.0):
        self.node = node
        self.cgroups = CgroupResolver(cgroup_root, proc_root)
        self.kube = KubeClient()
        self.refresh = refresh
        self.pods: dict[str, dict] = {}  # pod uid -> metadata
        self._last_refresh = 0.0
        self._last_miss_refresh = 0.0
        self._lock = threading.Lock()
        if not self.kube.enabled:
            log.warning("Kubernetes API not available - running without enrichment (all events raw)")

    # ---- pod cache -------------------------------------------------------------------
    def refresh_pods(self, force: bool = False):
        now = time.monotonic()
        if not force and now - self._last_refresh < self.refresh:
            return
        self._last_refresh = now
        try:
            items = self.kube.list_pods(self.node)
        except Exception as e:  # noqa: BLE001 - keep the sensor alive
            log.warning("pod list failed: %s", e)
            return
        pods = {}
        for p in items:
            meta, spec, status = p.get("metadata", {}), p.get("spec", {}), p.get("status", {})
            kind, wl = workload_of(p)
            containers = {}
            for key in ("containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"):
                for cs in status.get(key) or []:
                    cid = (cs.get("containerID") or "").split("://")[-1]
                    if cid:
                        containers[cid] = {"name": cs.get("name"), "image": cs.get("image")}
            labels = meta.get("labels") or {}
            pods[meta.get("uid", "")] = {
                "namespace": meta.get("namespace", ""), "pod": meta.get("name", ""),
                "workload_kind": kind, "workload": wl, "service_account": spec.get("serviceAccountName", ""),
                "app": labels.get("app.kubernetes.io/name") or labels.get("app") or labels.get("k8s-app") or "",
                "containers": containers,
            }
        with self._lock:
            self.pods = pods

    # ---- enrichment ------------------------------------------------------------------
    def enrich(self, ev: dict) -> dict:
        cg = self.cgroups.resolve(ev.get("cgroup_id", 0), ev.get("pid", 0))
        m_pod = RE_POD_UID.search(cg)
        ctx = {"valid": False, "node": self.node, "cgroup": cg}
        if not m_pod:
            return ctx
        uid = m_pod.group(1).replace("_", "-")
        m_cid = RE_CONTAINER_ID.search(cg.rsplit("/", 1)[-1]) or RE_CONTAINER_ID.search(cg)
        cid = m_cid.group(1) if m_cid else ""
        pod = self.pods.get(uid)
        if pod is None and time.monotonic() - self._last_miss_refresh > 2.0:
            self._last_miss_refresh = time.monotonic()
            self.refresh_pods(force=True)  # new pod since last refresh
            pod = self.pods.get(uid)
        if pod is None:
            ctx["pod_uid"] = uid
            return ctx
        c = pod["containers"].get(cid)
        ctx.update(valid=True, pod_uid=uid, namespace=pod["namespace"], pod=pod["pod"],
                   workload_kind=pod["workload_kind"], workload=pod["workload"], app=pod["app"],
                   service_account=pod["service_account"], container_id=cid[:12],
                   container=c["name"] if c else ("(sandbox)" if cid else "(pod)"),
                   image=c["image"] if c else "")
        return ctx
