#!/usr/bin/env bash

set -Eeuo pipefail

if [[ "${1:-}" == "" ]]; then
  echo "Usage: $0 <CVE-ID> [note]" >&2
  exit 1
fi

CVE_ID="$1"
NOTE="${2:-non-exploit evidence collection}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CVE_DIR="${REPO_ROOT}/cves/${CVE_ID}"

if [[ ! -d "${CVE_DIR}" ]]; then
  echo "CVE directory not found: ${CVE_DIR}" >&2
  exit 1
fi

TIMESTAMP_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_PARENT="${CVE_DIR}/Logs"
if [[ -d "${CVE_DIR}/logs" && ! -d "${LOG_PARENT}" ]]; then
  LOG_PARENT="${CVE_DIR}/logs"
fi

RUN_DIR="${LOG_PARENT}/${TIMESTAMP_UTC}"
mkdir -p "${RUN_DIR}"

capture_cmd() {
  local output_file="$1"
  shift
  {
    echo "# time_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# command: $*"
    echo
    "$@" 2>&1 || true
  } >"${output_file}"
}

capture_shell() {
  local output_file="$1"
  local shell_cmd="$2"
  {
    echo "# time_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# command: ${shell_cmd}"
    echo
    bash -lc "${shell_cmd}" 2>&1 || true
  } >"${output_file}"
}

{
  echo "timestamp_utc=${TIMESTAMP_UTC}"
  echo "cve_id=${CVE_ID}"
  echo "note=${NOTE}"
  echo "hostname=$(hostname 2>/dev/null || echo unknown)"
  echo "cwd=${PWD}"
} >"${RUN_DIR}/context.env"

capture_cmd "${RUN_DIR}/uname.txt" uname -a
capture_cmd "${RUN_DIR}/os-release.txt" cat /etc/os-release
capture_cmd "${RUN_DIR}/id.txt" id
capture_cmd "${RUN_DIR}/kernel-cmdline.txt" cat /proc/cmdline
capture_cmd "${RUN_DIR}/proc-self-cgroup.txt" cat /proc/self/cgroup
capture_shell "${RUN_DIR}/mount-cgroup.txt" "mount | grep -E 'cgroup|overlay' || true"
capture_cmd "${RUN_DIR}/findmnt-cgroup.txt" findmnt -t cgroup,cgroup2
capture_shell "${RUN_DIR}/lsm.txt" "cat /sys/kernel/security/lsm || true"
capture_shell "${RUN_DIR}/sysctl-security.txt" \
  "sysctl kernel.unprivileged_userns_clone user.max_user_namespaces kernel.kptr_restrict kernel.dmesg_restrict 2>/dev/null || true"

capture_shell "${RUN_DIR}/runtime-binaries.txt" \
  "for b in docker isula runc containerd ctr crictl nerdctl; do if command -v \"$b\" >/dev/null 2>&1; then echo \"$b:$(command -v \"$b\")\"; else echo \"$b:NOT_FOUND\"; fi; done"
capture_shell "${RUN_DIR}/runtime-versions.txt" \
  "docker --version 2>/dev/null || true; isula version 2>/dev/null || true; runc --version 2>/dev/null || true; containerd --version 2>/dev/null || true"

capture_shell "${RUN_DIR}/systemd-runtime-status.txt" \
  "for s in docker.service isulad.service containerd.service; do echo \"### $s\"; systemctl is-enabled \"$s\" 2>/dev/null || true; systemctl is-active \"$s\" 2>/dev/null || true; systemctl status \"$s\" --no-pager -n 50 2>/dev/null || true; echo; done"
capture_shell "${RUN_DIR}/journal-docker.txt" "journalctl -u docker.service --no-pager -n 200 2>/dev/null || true"
capture_shell "${RUN_DIR}/journal-isulad.txt" "journalctl -u isulad.service --no-pager -n 200 2>/dev/null || true"
capture_shell "${RUN_DIR}/journal-containerd.txt" "journalctl -u containerd.service --no-pager -n 200 2>/dev/null || true"
capture_shell "${RUN_DIR}/journal-kernel.txt" "journalctl -k --no-pager -n 200 2>/dev/null || true"
capture_shell "${RUN_DIR}/dmesg-tail.txt" "dmesg -T 2>/dev/null | tail -n 200 || true"

capture_shell "${RUN_DIR}/audit-recent.txt" "ausearch -ts recent 2>/dev/null || true"
capture_shell "${RUN_DIR}/audit-recent-filtered.txt" \
  "grep -Ei 'docker|isula|runc|containerd|seccomp|apparmor|selinux|avc|denied|cgroup|namespace' \"${RUN_DIR}/audit-recent.txt\" || true"

{
  echo "# Escape Evidence Bundle"
  echo
  echo "- CVE: ${CVE_ID}"
  echo "- Timestamp (UTC): ${TIMESTAMP_UTC}"
  echo "- Note: ${NOTE}"
  echo
  echo "## Files"
  echo
  echo "- context.env"
  echo "- uname.txt"
  echo "- os-release.txt"
  echo "- runtime-binaries.txt"
  echo "- runtime-versions.txt"
  echo "- systemd-runtime-status.txt"
  echo "- journal-docker.txt / journal-isulad.txt / journal-containerd.txt"
  echo "- journal-kernel.txt"
  echo "- dmesg-tail.txt"
  echo "- audit-recent.txt"
  echo "- audit-recent-filtered.txt"
} >"${RUN_DIR}/README.md"

echo "${RUN_DIR}"
