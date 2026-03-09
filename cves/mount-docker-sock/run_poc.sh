#!/usr/bin/env bash
set -Eeuo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$POC_DIR/scene.yaml"
NAMESPACE="${NAMESPACE:-metarget}"

if [[ "${1:-}" == "--cleanup" ]]; then
  kubectl delete -f "$MANIFEST" --ignore-not-found
  echo "[+] Cleaned resources from $MANIFEST"
  exit 0
fi

command -v kubectl >/dev/null 2>&1 || { echo "[-] Missing dependency: kubectl"; exit 1; }

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "[-] Kubernetes API unreachable."
  echo "[*] Hint: run scripts/env_labctl.sh profile k8s-kind"
  echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"
  exit 1
fi

kubectl apply -f "$MANIFEST"
kubectl wait --for=condition=Ready "pod/mount-docker-sock" -n "$NAMESPACE" --timeout=120s || true
kubectl exec -n "$NAMESPACE" "mount-docker-sock" -- sh -lc 'id; ls -l /var/run/docker.sock'

echo "[*] 可在容器内安装 docker 客户端，通过该 socket 启动挂载 / 的特权容器。"
