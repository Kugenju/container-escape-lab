#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <namespace> <pod> <command-string>"
  exit 2
fi

namespace="$1"
pod="$2"
shift 2
probe_cmd="$*"
exec_timeout="${EXEC_TIMEOUT_SEC:-30}"
fallback_to_logs="${K8S_EXEC_FALLBACK_TO_LOGS:-1}"
log_tail_lines="${K8S_LOG_TAIL_LINES:-200}"

set +e
probe_out="$(timeout "$exec_timeout" kubectl exec -n "$namespace" "$pod" -- sh -lc "$probe_cmd" 2>&1)"
rc=$?
set -e

printf '%s\n' "$probe_out"

if [[ "$rc" -eq 0 ]]; then
  echo "[*] Verdict: PROBE_EXECUTED"
  exit 0
fi

if [[ "$fallback_to_logs" == "1" ]]; then
  echo "[*] Exec probe failed, attempting startup-log fallback..."
  set +e
  log_out="$(kubectl logs -n "$namespace" "$pod" --tail="$log_tail_lines" 2>&1)"
  log_rc=$?
  set -e
  printf '%s\n' "$log_out"
  if [[ "$log_rc" -eq 0 ]] && echo "$log_out" | grep -q "K8S_LOG_PROBE_OK"; then
    echo "[*] Verdict: PROBE_LOG_FALLBACK_OK"
    exit 0
  fi
fi

if [[ "$rc" -eq 124 ]]; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_exec_timeout"
  exit 1
fi

if echo "$probe_out" | grep -q "error adding pid" && \
   echo "$probe_out" | grep -q "cgroup.procs: no such file or directory"; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_exec_cgroup_path_missing"
  exit 1
fi

echo "[*] Verdict: BLOCKED_STAGE=k8s_exec_failed_unknown"
exit 1
