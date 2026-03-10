#!/usr/bin/env bash
set -Eeuo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$POC_DIR/run_poc.log"
RUNTIME_JOURNAL_FILE="$POC_DIR/runtime_journal.log"
START_TS="$(date -Iseconds)"

usage() {
  echo "Usage: $0 [--cleanup]"
}

version_ge() {
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]
}

if [[ "${1:-}" == "--cleanup" ]]; then
  rm -f "$LOG_FILE" "$RUNTIME_JOURNAL_FILE"
  echo "[+] Cleanup done"
  exit 0
fi

if [[ -n "${1:-}" ]]; then
  usage
  exit 1
fi

for cmd in uname sort journalctl grep head; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[-] Missing dependency: $cmd"; exit 1; }
done

rm -f "$LOG_FILE" "$RUNTIME_JOURNAL_FILE"
{
  echo "[*] kata-escape-2020 probe start: $START_TS"
  echo "[*] Kernel: $(uname -r)"
  echo "[*] Reference vulnerable ranges:"
  echo "    - CVE-2020-2024: Kata Containers < 1.11.0"
  echo "    - CVE-2020-2026: Kata 1.11 < 1.11.1 / 1.10 < 1.10.5 / 1.9 and earlier"
  echo "    - CVE-2020-28914: Kata Containers < 1.11.5"
} | tee "$LOG_FILE"

if ! command -v kata-runtime >/dev/null 2>&1; then
  echo "[-] kata-runtime not found in PATH." | tee -a "$LOG_FILE"
  echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed" | tee -a "$LOG_FILE"
  journalctl --since "$START_TS" --no-pager -u containerd.service -u docker.service >"$RUNTIME_JOURNAL_FILE" 2>/dev/null || true
  exit 1
fi

kata_version_raw="$(kata-runtime --version 2>&1 || true)"
printf '%s\n' "$kata_version_raw" >>"$LOG_FILE"
kata_version="$(printf '%s\n' "$kata_version_raw" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
echo "[*] Parsed kata-runtime version: ${kata_version:-unknown}" | tee -a "$LOG_FILE"

if [[ -z "$kata_version" ]]; then
  echo "[-] Unable to parse kata-runtime semantic version." | tee -a "$LOG_FILE"
  echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_version_parse_failed" | tee -a "$LOG_FILE"
  RESULT=1
elif version_ge "$kata_version" "1.11.5"; then
  echo "[-] kata-runtime version outside listed vulnerable ranges." | tee -a "$LOG_FILE"
  echo "[*] Verdict: BLOCKED_STAGE=runtime_version_not_vulnerable_range" | tee -a "$LOG_FILE"
  RESULT=1
else
  echo "[-] kata-runtime version may be in vulnerable range, but dedicated clh/hostPath teardown PoC chain is not present in this safe probe." | tee -a "$LOG_FILE"
  echo "[*] Verdict: BLOCKED_STAGE=runtime_in_range_but_poc_chain_not_available" | tee -a "$LOG_FILE"
  RESULT=1
fi

journalctl --since "$START_TS" --no-pager -u containerd.service -u docker.service >"$RUNTIME_JOURNAL_FILE" 2>/dev/null || true
exit "$RESULT"
