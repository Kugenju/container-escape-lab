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
kubectl wait --for=condition=Ready "pod/cap-dac-read-search-container" -n "$NAMESPACE" --timeout=120s || true
kubectl exec -n "$NAMESPACE" "cap-dac-read-search-container" -- sh -lc 'id; grep CapEff /proc/1/status'

echo "[*] 原始 writeup 的完整逃逸需要 shocker(open_by_handle_at) PoC。"
