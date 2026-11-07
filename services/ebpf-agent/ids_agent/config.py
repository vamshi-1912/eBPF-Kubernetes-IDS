"""Agent configuration (environment variables, set by the DaemonSet)."""
import os


def _bool(name, default):
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


BACKEND_URL = os.environ.get("BACKEND_URL", "http://ids-backend.ebpf-ids.svc.cluster.local:8000")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
NODE_NAME = os.environ.get("NODE_NAME", os.uname().nodename)
POD_NAME = os.environ.get("POD_NAME", "")
POD_NAMESPACE = os.environ.get("POD_NAMESPACE", "")

LOADER_PATH = os.environ.get("LOADER_PATH", "/app/ids_loader")
MODEL_PATH = os.environ.get("MODEL_PATH", "/app/model/ids_model.joblib")
EVALUATION_PATH = os.environ.get("EVALUATION_PATH", "/app/model/evaluation.json")
CGROUP_ROOT = os.environ.get("CGROUP_ROOT", "/host/sys/fs/cgroup")
PROC_ROOT = os.environ.get("PROC_ROOT", "/proc")

BATCH_INTERVAL = float(os.environ.get("BATCH_INTERVAL", "0.25"))  # seconds
MAX_BATCH = int(os.environ.get("MAX_BATCH", "512"))
HEARTBEAT_INTERVAL = float(os.environ.get("HEARTBEAT_INTERVAL", "10"))
POD_REFRESH_INTERVAL = float(os.environ.get("POD_REFRESH_INTERVAL", "15"))
WARMUP_SECONDS = float(os.environ.get("WARMUP_SECONDS", "300"))
DETECTION_THRESHOLD = float(os.environ.get("DETECTION_THRESHOLD", "0"))  # 0 = use model's
STORE_NORMAL_EVENTS = _bool("STORE_NORMAL_EVENTS", True)
STORE_RAW_EVENTS = _bool("STORE_RAW_EVENTS", True)  # events without Kubernetes context
LOG_ALERTS = _bool("LOG_ALERTS", True)
AGENT_VERSION = "1.0.0"
