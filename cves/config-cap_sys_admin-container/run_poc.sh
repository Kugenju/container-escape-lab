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
kubectl wait --for=condition=Ready "pod/cap-sys-admin-container" -n "$NAMESPACE" --timeout=120s || true
kubectl exec -n "$NAMESPACE" "cap-sys-admin-container" -- sh -lc 'id; grep CapEff /proc/1/status; mkdir -p /tmp/mt_test && mount -t tmpfs tmpfs /tmp/mt_test && echo "[+] mount tmpfs success" && umount /tmp/mt_test'

echo "[*] 可继续按业务场景挂载宿主机目录并执行 chroot。"
