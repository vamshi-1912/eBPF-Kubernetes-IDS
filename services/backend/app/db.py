"""MongoDB access (events, alerts, metrics, evaluations, users)."""
from __future__ import annotations

from datetime import datetime, timezone

from bson import ObjectId
from pymongo import ASCENDING, DESCENDING, AsyncMongoClient

from . import config

client: AsyncMongoClient | None = None


def db():
    return client[config.MONGO_DB]


async def connect():
    global client
    client = AsyncMongoClient(config.MONGO_URI, tz_aware=True, serverSelectionTimeoutMS=5000)
    d = db()
    await d.events.create_index("ts", expireAfterSeconds=config.EVENT_TTL_HOURS * 3600)
    await d.events.create_index([("k8s.namespace", ASCENDING), ("ts", DESCENDING)])
    await d.events.create_index([("prediction.label", ASCENDING), ("ts", DESCENDING)])
    await d.events.create_index([("event_type", ASCENDING), ("ts", DESCENDING)])
    await d.alerts.create_index("last_seen", expireAfterSeconds=config.ALERT_TTL_DAYS * 86400)
    await d.alerts.create_index([("dedup_key", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    await d.alerts.create_index([("severity", ASCENDING), ("last_seen", DESCENDING)])
    await d.alerts.create_index([("k8s.namespace", ASCENDING), ("last_seen", DESCENDING)])
    await d.metrics.create_index("ts", expireAfterSeconds=24 * 3600)
    await d.metrics.create_index([("node", ASCENDING), ("ts", DESCENDING)])
    await d.users.create_index("username", unique=True)


async def close():
    if client is not None:
        await client.close()


def now() -> datetime:
    return datetime.now(timezone.utc)


def ms_to_dt(ms) -> datetime:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return now()


def clean(doc):
    """Mongo document -> JSON-friendly dict."""
    if isinstance(doc, list):
        return [clean(d) for d in doc]
    if isinstance(doc, dict):
        out = {}
        for k, v in doc.items():
            if k == "_id":
                out["id"] = str(v)
            else:
                out[k] = clean(v)
        return out
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime):
        return doc.isoformat()
    return doc
