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

kubectl apply -f "$MANIFEST"
kubectl wait --for=condition=Ready "pod/cap-sys-module-container" -n "$NAMESPACE" --timeout=120s || true
kubectl exec -n "$NAMESPACE" "cap-sys-module-container" -- sh -lc 'id; grep CapEff /proc/1/status; (command -v insmod || true); (command -v modprobe || true)'

echo "[*] 完整利用需要自定义恶意内核模块(.ko)并在容器中加载。"
