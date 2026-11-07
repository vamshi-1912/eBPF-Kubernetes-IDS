"""Plain demo "shop" web service used as the target workload of the attack
simulation. It does not execute anything; scenarios are run inside the pod
with `kubectl exec` by evaluation/run_live_eval.py."""
import json


def app(environ, start_response):
    if environ.get("PATH_INFO") == "/health":
        body = b"ok"
    else:
        body = json.dumps({"service": "shop-web", "items": ["book", "pen"]}).encode()
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [body]
