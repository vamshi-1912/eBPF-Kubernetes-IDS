"""Agent-facing endpoints: telemetry ingestion, heartbeats, model evaluation."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends
from pymongo import UpdateOne

from .. import config, db
from ..security import require_agent

router = APIRouter(prefix="/api", dependencies=[Depends(require_agent)], tags=["agent"])

MAX_BATCH = 5000


@router.post("/ingest")
async def ingest(payload: dict = Body(...)):
    node = str(payload.get("node", "unknown"))
    events = payload.get("events") or []
    alerts = payload.get("alerts") or []
    d = db.db()
    received = db.now()

    if events:
        docs = []
        for e in events[:MAX_BATCH]:
            if not isinstance(e, dict):
                continue
            e = dict(e)
            e["ts"] = db.ms_to_dt(e.pop("ts_ms", None))
            e["node"] = e.get("node") or node
            docs.append(e)
        if docs:
            await d.events.insert_many(docs, ordered=False)

    # Risk & Alert Module: identical alerts from the same workload are merged (count++)
    ops = []
    for a in alerts[:MAX_BATCH]:
        if not isinstance(a, dict) or not a.get("dedup_key"):
            continue
        ts = db.ms_to_dt(a.pop("ts_ms", None))
        key = a.pop("dedup_key")
        body = {k: v for k, v in a.items() if k not in ("risk_score",)}
        ops.append(UpdateOne(
            {"dedup_key": key, "status": {"$ne": "resolved"},
             "last_seen": {"$gte": ts - timedelta(seconds=config.DEDUP_WINDOW_SECONDS)}},
            {"$setOnInsert": {**body, "first_seen": ts, "status": "open", "received_at": received},
             "$set": {"last_seen": ts, "last_event": a.get("event")},
             "$max": {"risk_score": a.get("risk_score", 0)},
             "$inc": {"count": 1}},
            upsert=True))
    if ops:
        await d.alerts.bulk_write(ops, ordered=True)
    return {"events": len(events), "alerts": len(alerts)}


@router.post("/agent/heartbeat")
async def heartbeat(payload: dict = Body(...)):
    doc = dict(payload)
    doc["ts"] = db.now()
    await db.db().metrics.insert_one(doc)
    return {"ok": True}


@router.post("/agent/evaluation")
async def upload_evaluation(payload: dict = Body(...)):
    """The agent publishes the offline evaluation report of the model it runs."""
    await db.db().evaluations.update_one(
        {"kind": "offline", "model_version": payload.get("model_version")},
        {"$set": {"kind": "offline", "model_version": payload.get("model_version"), "report": payload,
                  "uploaded_at": db.now()}}, upsert=True)
    return {"ok": True}
