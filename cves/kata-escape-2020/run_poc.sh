#!/usr/bin/env bash
set -Eeuo pipefail

echo "[*] Kata escape 2020 quick check"
if command -v kata-runtime >/dev/null 2>&1; then
  kata-runtime --version || true
else
  echo "[!] kata-runtime not found in PATH"
fi

echo "[*] This scene requires vulnerable Kata runtime (e.g. 1.10.0 with clh) and dedicated PoC."
echo "[*] See README references to continue manual reproduction in isolated lab."
