"""Backend settings from environment variables (Kubernetes Secret / ConfigMap)."""
import os
import secrets

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.environ.get("MONGO_DB", "ebpf_ids")
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(32)
JWT_TTL_MINUTES = int(os.environ.get("JWT_TTL_MINUTES", "720"))
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
EVENT_TTL_HOURS = int(os.environ.get("EVENT_TTL_HOURS", "24"))
ALERT_TTL_DAYS = int(os.environ.get("ALERT_TTL_DAYS", "30"))
DEDUP_WINDOW_SECONDS = int(os.environ.get("DEDUP_WINDOW_SECONDS", "600"))
CORS_ORIGINS = [o for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",") if o]
