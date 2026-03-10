#!/usr/bin/env bash
set -Eeuo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$POC_DIR/scene.yaml"
NAMESPACE="${NAMESPACE:-metarget}"
POD_NAME="cap-sys-admin-container"
HELPER="$POC_DIR/../../scripts/probes/k8s_exec_probe.sh"

if [[ "${1:-}" == "--cleanup" ]]; then
  kubectl delete -f "$MANIFEST" --ignore-not-found
  echo "[+] Cleaned resources from $MANIFEST"
  exit 0
fi

command -v kubectl >/dev/null 2>&1 || { echo "[-] Missing dependency: kubectl"; exit 1; }
[[ -x "$HELPER" ]] || { echo "[-] Missing helper: $HELPER"; exit 1; }

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "[-] Kubernetes API unreachable."
  echo "[*] Hint: run scripts/env_labctl.sh profile k8s-kind"
  echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"
  exit 1
fi

kubectl get ns "$NAMESPACE" >/dev/null 2>&1 || kubectl create ns "$NAMESPACE" >/dev/null
kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1 || true
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  kubectl describe pod "$POD_NAME" -n "$NAMESPACE" || true
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi

"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; grep CapEff /proc/1/status; mkdir -p /tmp/mt_test && mount -t tmpfs tmpfs /tmp/mt_test && echo "[+] mount tmpfs success" && umount /tmp/mt_test'

echo "[*] 可继续按业务场景挂载宿主机目录并执行 chroot。"
