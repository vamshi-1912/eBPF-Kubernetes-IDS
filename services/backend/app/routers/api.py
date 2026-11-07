"""Dashboard-facing REST API: events, alerts, analytics, agents, evaluation."""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Literal

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel

from .. import db
from ..security import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)], tags=["dashboard"])

SEVERITIES = ("High", "Medium", "Low")


def _since(minutes: int | None):
    return db.now() - timedelta(minutes=minutes) if minutes else None


def _search(q: str, fields: list[str]) -> dict:
    rx = {"$regex": re.escape(q), "$options": "i"}
    return {"$or": [{f: rx} for f in fields]}


# ------------------------------------------------------------------ events
@router.get("/events")
async def list_events(
    type: str | None = None, namespace: str | None = None, pod: str | None = None,
    label: Literal["suspicious", "normal", "raw"] | None = None, q: str | None = None,
    since_minutes: int | None = Query(None, ge=1, le=60 * 24 * 30),
    limit: int = Query(100, ge=1, le=1000), skip: int = Query(0, ge=0),
):
    f: dict = {}
    if type:
        f["event_type"] = type
    if namespace:
        f["k8s.namespace"] = namespace
    if pod:
        f["k8s.pod"] = pod
    if label == "raw":
        f["k8s_context"] = False
    elif label:
        f["prediction.label"] = label
    if since_minutes:
        f["ts"] = {"$gte": _since(since_minutes)}
    if q:
        f.update(_search(q, ["cmdline", "path", "comm", "parent_comm", "daddr", "k8s.pod", "k8s.workload"]))
    d = db.db()
    total = await d.events.count_documents(f, limit=10000)
    items = await d.events.find(f).sort("ts", -1).skip(skip).limit(limit).to_list(limit)
    return {"total": total, "items": db.clean(items)}


# ------------------------------------------------------------------ alerts
@router.get("/alerts")
async def list_alerts(
    severity: str | None = None, status: str | None = None, namespace: str | None = None,
    category: str | None = None, q: str | None = None,
    since_minutes: int | None = Query(None, ge=1, le=60 * 24 * 30),
    limit: int = Query(100, ge=1, le=1000), skip: int = Query(0, ge=0),
):
    f: dict = {}
    if severity:
        f["severity"] = {"$in": severity.split(",")}
    if status:
        f["status"] = {"$in": status.split(",")}
    if namespace:
        f["k8s.namespace"] = namespace
    if category:
        f["category"] = category
    if since_minutes:
        f["last_seen"] = {"$gte": _since(since_minutes)}
    if q:
        f.update(_search(q, ["title", "event.cmdline", "event.path", "event.comm", "k8s.pod", "k8s.workload",
                             "category", "mitre"]))
    d = db.db()
    total = await d.alerts.count_documents(f)
    items = await d.alerts.find(f).sort("last_seen", -1).skip(skip).limit(limit).to_list(limit)
    return {"total": total, "items": db.clean(items)}


def _oid(alert_id: str) -> ObjectId:
    try:
        return ObjectId(alert_id)
    except InvalidId:
        raise HTTPException(404, "alert not found")


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    doc = await db.db().alerts.find_one({"_id": _oid(alert_id)})
    if not doc:
        raise HTTPException(404, "alert not found")
    return db.clean(doc)


class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]
    note: str | None = None


@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id: str, body: AlertUpdate, user: dict = Depends(require_user)):
    upd = {"status": body.status, "updated_by": user["username"], "updated_at": db.now()}
    if body.note is not None:
        upd["note"] = body.note[:2000]
    res = await db.db().alerts.find_one_and_update({"_id": _oid(alert_id)}, {"$set": upd}, return_document=True)
    if not res:
        raise HTTPException(404, "alert not found")
    return db.clean(res)


# ------------------------------------------------------------------ analytics
@router.get("/stats")
async def stats(minutes: int = Query(60, ge=5, le=60 * 24 * 7)):
    d = db.db()
    since = _since(minutes)
    bucket_ms = 60_000 if minutes <= 180 else (300_000 if minutes <= 1440 else 3_600_000)

    async def agg(coll, pipeline):
        return await (await coll.aggregate(pipeline)).to_list(None)

    def bucket(field):
        return {"$toDate": {"$subtract": [{"$toLong": f"${field}"}, {"$mod": [{"$toLong": f"${field}"}, bucket_ms]}]}}

    ev_match = {"ts": {"$gte": since}}
    al_match = {"last_seen": {"$gte": since}}
    ev_facets = await agg(d.events, [{"$match": ev_match}, {"$facet": {
        "total": [{"$count": "n"}],
        "by_type": [{"$group": {"_id": "$event_type", "n": {"$sum": 1}}}],
        "by_label": [{"$group": {"_id": {"$ifNull": ["$prediction.label", "raw"]}, "n": {"$sum": 1}}}],
        "pods": [{"$match": {"k8s_context": True}}, {"$group": {"_id": {"ns": "$k8s.namespace", "pod": "$k8s.pod"}}},
                 {"$count": "n"}],
        "namespaces": [{"$match": {"k8s_context": True}}, {"$group": {"_id": "$k8s.namespace", "n": {"$sum": 1}}},
                       {"$sort": {"n": -1}}, {"$limit": 10}],
        "timeline": [{"$group": {"_id": bucket("ts"), "n": {"$sum": 1}}}],
    }}])
    al_facets = await agg(d.alerts, [{"$match": al_match}, {"$facet": {
        "total": [{"$count": "n"}],
        "occurrences": [{"$group": {"_id": None, "n": {"$sum": "$count"}}}],
        "by_severity": [{"$group": {"_id": "$severity", "n": {"$sum": 1}}}],
        "by_status": [{"$group": {"_id": "$status", "n": {"$sum": 1}}}],
        "by_category": [{"$group": {"_id": "$category", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}],
        "by_namespace": [{"$group": {"_id": "$k8s.namespace", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}, {"$limit": 10}],
        "top_pods": [{"$group": {"_id": {"ns": "$k8s.namespace", "pod": "$k8s.pod"}, "n": {"$sum": 1},
                                 "max_risk": {"$max": "$risk_score"}}}, {"$sort": {"max_risk": -1, "n": -1}}, {"$limit": 8}],
        "mitre": [{"$unwind": "$mitre"}, {"$group": {"_id": "$mitre", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}, {"$limit": 10}],
        "detection": [{"$group": {"_id": "$ml_detected", "n": {"$sum": 1}}}],
        "timeline": [{"$group": {"_id": {"t": bucket("first_seen"), "s": "$severity"}, "n": {"$sum": 1}}}],
    }}])
    ev, al = ev_facets[0], al_facets[0]

    def kv(rows):
        return {str(r["_id"]): r["n"] for r in rows}

    timeline: dict = {}
    for r in ev["timeline"]:
        timeline.setdefault(r["_id"], {"events": 0, "High": 0, "Medium": 0, "Low": 0})["events"] = r["n"]
    for r in al["timeline"]:
        t, s = r["_id"]["t"], r["_id"]["s"]
        if s in SEVERITIES:
            timeline.setdefault(t, {"events": 0, "High": 0, "Medium": 0, "Low": 0})[s] += r["n"]
    open_alerts = await d.alerts.count_documents({"status": "open"})
    return {
        "window_minutes": minutes, "bucket_seconds": bucket_ms // 1000,
        "events_total": ev["total"][0]["n"] if ev["total"] else 0,
        "events_by_type": kv(ev["by_type"]), "events_by_label": kv(ev["by_label"]),
        "pods_monitored": ev["pods"][0]["n"] if ev["pods"] else 0,
        "events_by_namespace": [{"namespace": r["_id"], "events": r["n"]} for r in ev["namespaces"]],
        "alerts_total": al["total"][0]["n"] if al["total"] else 0,
        "alert_occurrences": al["occurrences"][0]["n"] if al["occurrences"] else 0,
        "alerts_open": open_alerts,
        "alerts_by_severity": {s: kv(al["by_severity"]).get(s, 0) for s in SEVERITIES},
        "alerts_by_status": kv(al["by_status"]), "alerts_by_category": kv(al["by_category"]),
        "alerts_by_namespace": [{"namespace": r["_id"], "alerts": r["n"]} for r in al["by_namespace"]],
        "alerts_by_detector": {"ml": kv(al["detection"]).get("True", 0), "rules_only": kv(al["detection"]).get("False", 0)},
        "top_pods": [{"namespace": r["_id"].get("ns"), "pod": r["_id"].get("pod"), "alerts": r["n"],
                      "max_risk": r["max_risk"]} for r in al["top_pods"]],
        "top_mitre": [{"technique": r["_id"], "alerts": r["n"]} for r in al["mitre"]],
        "timeline": [{"t": t.isoformat(), **v} for t, v in sorted(timeline.items())],
    }


@router.get("/namespaces")
async def namespaces():
    return sorted(n for n in await db.db().events.distinct("k8s.namespace", {"k8s_context": True}) if n)


@router.get("/agents")
async def agents(history_minutes: int = Query(30, ge=1, le=1440)):
    d = db.db()
    since = _since(history_minutes)
    out = []
    for node in await d.metrics.distinct("node"):
        hist = await d.metrics.find({"node": node, "ts": {"$gte": since}}).sort("ts", -1).limit(360).to_list(360)
        if not hist:
            continue
        latest = hist[0]
        online = (db.now() - latest["ts"]).total_seconds() < 60
        out.append({"node": node, "online": online, "latest": db.clean(latest),
                    "history": db.clean([{k: h.get(k) for k in ("ts", "cpu_percent", "rss_mb", "events_per_sec",
                                                                 "latency_avg_ms", "latency_p95_ms")}
                                         for h in reversed(hist)])})
    return out


# ------------------------------------------------------------------ evaluation
@router.get("/evaluation")
async def evaluation():
    d = db.db()
    offline = await d.evaluations.find({"kind": "offline"}).sort("uploaded_at", -1).limit(1).to_list(1)
    live = await d.evaluations.find({"kind": "live"}).sort("created_at", -1).limit(5).to_list(5)
    since = _since(15)
    runtime = await (await d.metrics.aggregate([
        {"$match": {"ts": {"$gte": since}}},
        {"$group": {"_id": None, "cpu_avg": {"$avg": "$cpu_percent"}, "cpu_max": {"$max": "$cpu_percent"},
                    "rss_avg": {"$avg": "$rss_mb"}, "rss_max": {"$max": "$rss_mb"},
                    "lat_avg": {"$avg": "$latency_avg_ms"}, "lat_p95": {"$avg": "$latency_p95_ms"},
                    "alert_lat": {"$avg": "$alert_latency_avg_ms"}, "eps": {"$avg": "$events_per_sec"},
                    "infer": {"$avg": "$inference_ms_per_event"}, "drops": {"$max": "$kernel_events_dropped"},
                    "emitted": {"$max": "$kernel_events_emitted"}, "samples": {"$sum": 1}}}])).to_list(1)
    rt = runtime[0] if runtime else {}
    rt.pop("_id", None)
    return {"offline": db.clean(offline[0]["report"]) if offline else None,
            "live": db.clean(live), "runtime_15m": {k: (round(v, 3) if isinstance(v, float) else v) for k, v in rt.items()}}


@router.post("/evaluation/live")
async def save_live_evaluation(payload: dict = Body(...), user: dict = Depends(require_user)):
    doc = {"kind": "live", "created_at": db.now(), "created_by": user["username"], **payload}
    res = await db.db().evaluations.insert_one(doc)
    return {"id": str(res.inserted_id)}
