#!/usr/bin/env bash
# Build all images, load them into minikube and deploy the eBPF IDS.
#
#   ./scripts/deploy_minikube.sh            # build + deploy
#   SKIP_BUILD=1 ./scripts/deploy_minikube.sh   # redeploy without rebuilding
#
# Images are built with the host Docker daemon and copied into the minikube
# node with `minikube image load`, so the node itself needs no internet access.
set -euo pipefail
cd "$(dirname "$0")/.."

NS=ebpf-ids
BUILD_NETWORK=${BUILD_NETWORK:-host}   # docker build --network (host works around broken bridge egress)
PROFILE=${MINIKUBE_PROFILE:-minikube}
mk() { minikube -p "$PROFILE" "$@"; }
log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

log "Checking minikube"
if ! mk status >/dev/null 2>&1; then
  mk start --driver=docker --cpus=2 --memory=3072
fi
kubectl config use-context "$PROFILE" >/dev/null
echo "kernel: $(mk ssh -- uname -r 2>/dev/null | tr -d '\r')  (BTF: $(mk ssh -- test -e /sys/kernel/btf/vmlinux && echo yes || echo NO))"

if [[ -z "${SKIP_BUILD:-}" ]]; then
  log "Building images"
  docker build --network "$BUILD_NETWORK" -f services/ebpf-agent/Dockerfile -t ids-agent:latest .
  docker build --network "$BUILD_NETWORK" -t ids-backend:latest services/backend
  docker build --network "$BUILD_NETWORK" -t ids-frontend:latest services/frontend
  docker image inspect mongo:7.0 >/dev/null 2>&1 || docker pull -q mongo:7.0 >/dev/null

  log "Loading images into minikube"
  for img in ids-agent:latest ids-backend:latest ids-frontend:latest mongo:7.0; do
    echo "  $img"
    # `image load --overwrite` silently keeps the old image while a container uses
    # the tag, so drop the stale tag inside the node first.
    if [[ "$img" == ids-* ]]; then mk ssh -- docker rmi -f "$img" >/dev/null 2>&1 || true; fi
    mk image load --overwrite=true "$img"
  done
fi

log "Applying manifests"
kubectl apply -f infra/k8s/00-namespace.yaml
if ! kubectl -n "$NS" get secret ids-secrets >/dev/null 2>&1; then
  rnd() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "${1:-24}"; }
  MONGO_PW=$(rnd 24); ADMIN_PW=$(rnd 16)
  kubectl -n "$NS" create secret generic ids-secrets \
    --from-literal=mongo-password="$MONGO_PW" \
    --from-literal=mongo-uri="mongodb://ids:${MONGO_PW}@ids-mongodb:27017/?authSource=admin" \
    --from-literal=jwt-secret="$(rnd 48)" \
    --from-literal=agent-token="$(rnd 40)" \
    --from-literal=admin-password="$ADMIN_PW"
  echo "created Secret ids-secrets (random credentials)"
fi
kubectl apply -f infra/k8s/

log "Rolling out"
kubectl -n "$NS" rollout restart deployment/ids-backend deployment/ids-frontend daemonset/ids-agent >/dev/null
kubectl -n "$NS" rollout status deployment/ids-mongodb --timeout=300s
kubectl -n "$NS" rollout status deployment/ids-backend --timeout=300s
kubectl -n "$NS" rollout status deployment/ids-frontend --timeout=180s
kubectl -n "$NS" rollout status daemonset/ids-agent --timeout=300s
kubectl -n "$NS" get pods -o wide

ADMIN_PW=$(kubectl -n "$NS" get secret ids-secrets -o jsonpath='{.data.admin-password}' | base64 -d)
log "Done"
echo "Dashboard : http://$(mk ip):30080      (or: minikube service ids-frontend -n $NS)"
echo "Login     : admin / $ADMIN_PW"
echo "Agent log : kubectl -n $NS logs -f ds/ids-agent"
echo "Evaluate  : .venv/bin/python evaluation/run_live_eval.py"
