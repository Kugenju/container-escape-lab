#!/usr/bin/env bash
set -Eeuo pipefail

RUNC_BIN="${RUNC_BIN:-/usr/bin/runc}"
STATE_DIR="${STATE_DIR:-/var/lib/runtime-version-switch}"
STATE_FILE="${STATE_DIR}/state.env"
TMP_DIR="${TMP_DIR:-/tmp/runtime-version-switch}"

log() {
  printf '[*] %s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

die() {
  printf '[-] %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root"
}

require_cmd() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "missing dependency: $c"
  done
}

load_state() {
  if [[ -f "${STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${STATE_FILE}"
    BACKUP_PATH="${BACKUP_PATH:-${backup_path:-}}"
    ORIGINAL_VERSION="${ORIGINAL_VERSION:-${original_version:-}}"
    LAST_TARGET="${LAST_TARGET:-${last_target:-}}"
    LAST_SWITCH_TIME="${LAST_SWITCH_TIME:-${last_switch_time:-}}"
  fi
}

save_state() {
  mkdir -p "${STATE_DIR}"
  cat > "${STATE_FILE}" <<EOF
BACKUP_PATH=${BACKUP_PATH}
ORIGINAL_VERSION=${ORIGINAL_VERSION}
LAST_TARGET=${LAST_TARGET}
LAST_SWITCH_TIME=${LAST_SWITCH_TIME}
EOF
}

normalize_tag() {
  local raw="$1"
  if [[ "$raw" =~ ^v ]]; then
    printf '%s' "$raw"
  else
    printf 'v%s' "$raw"
  fi
}

backup_current_runc() {
  if [[ -n "${BACKUP_PATH:-}" && -f "${BACKUP_PATH}" ]]; then
    return
  fi
  mkdir -p "${STATE_DIR}"
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP_PATH="${STATE_DIR}/runc.backup.${ts}"
  cp -f "${RUNC_BIN}" "${BACKUP_PATH}"
  chmod 0755 "${BACKUP_PATH}"
  ORIGINAL_VERSION="$("${RUNC_BIN}" --version 2>/dev/null | awk 'NR==1{print $3}')"
}

download_and_verify() {
  local tag="$1"
  local base_url="https://github.com/opencontainers/runc/releases/download/${tag}"
  local bin_url="${base_url}/runc.amd64"
  local sha_url="${base_url}/runc.sha256sum"
  local work="${TMP_DIR}/${tag}"
  local bin_file="${work}/runc.amd64"
  local sha_file="${work}/runc.sha256sum"
  local -a proxy_prefixes=(
    ""
    "https://gh-proxy.com/"
    "https://ghproxy.net/"
    "https://github.moeyy.xyz/"
  )
  mkdir -p "${work}"
  if [[ ! -s "${bin_file}" ]]; then
    local ok=0
    for prefix in "${proxy_prefixes[@]}"; do
      local candidate="${prefix}${bin_url}"
      if curl -fL --connect-timeout 8 --max-time 240 --retry 3 --retry-delay 2 --retry-all-errors -o "${bin_file}" "${candidate}"; then
        ok=1
        break
      fi
    done
    [[ "${ok}" -eq 1 ]] || die "failed to download runc binary for ${tag}"
  else
    printf '[*] %s\n' "reuse cached binary: ${bin_file}" >&2
  fi
  local sha_ok=0
  for prefix in "${proxy_prefixes[@]}"; do
    local sha_candidate="${prefix}${sha_url}"
    if curl -fL --connect-timeout 8 --max-time 120 --retry 2 --retry-delay 2 --retry-all-errors -o "${sha_file}" "${sha_candidate}"; then
      sha_ok=1
      break
    fi
  done
  if [[ "${sha_ok}" -eq 1 ]]; then
    local expected
    expected="$(awk '/[[:space:]]+runc\.amd64$/{print $1}' "${sha_file}" | head -n1)"
    [[ -n "${expected}" ]] || die "failed to parse checksum for ${tag}"
    local actual
    actual="$(sha256sum "${bin_file}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] || die "checksum mismatch for ${tag}"
  else
    warn "checksum file unavailable for ${tag}; continue without remote checksum verification"
  fi

  printf '%s' "${bin_file}"
}

cmd_status() {
  load_state
  if [[ ! -x "${RUNC_BIN}" ]]; then
    die "runc binary not found: ${RUNC_BIN}"
  fi
  echo "runc_path=${RUNC_BIN}"
  echo "runc_version=$("${RUNC_BIN}" --version 2>/dev/null | awk 'NR==1{print $3}')"
  echo "backup_path=${BACKUP_PATH:-none}"
  echo "original_version=${ORIGINAL_VERSION:-unknown}"
  echo "last_target=${LAST_TARGET:-none}"
  echo "last_switch_time=${LAST_SWITCH_TIME:-none}"
}

cmd_use() {
  local raw="${1:-}"
  [[ -n "${raw}" ]] || die "usage: $0 use <runc-tag-or-version>"
  require_root
  require_cmd curl awk sha256sum cp chmod date

  load_state
  [[ -x "${RUNC_BIN}" ]] || die "runc binary not found: ${RUNC_BIN}"
  backup_current_runc

  local tag
  tag="$(normalize_tag "${raw}")"
  log "switch runc -> ${tag}"
  local dl_bin
  dl_bin="$(download_and_verify "${tag}")"
  cp -f "${dl_bin}" "${RUNC_BIN}"
  chmod 0755 "${RUNC_BIN}"

  LAST_TARGET="${tag}"
  LAST_SWITCH_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  save_state

  log "runc switched: $("${RUNC_BIN}" --version 2>/dev/null | head -n1)"
}

cmd_restore() {
  require_root
  load_state
  [[ -n "${BACKUP_PATH:-}" ]] || die "no backup recorded in ${STATE_FILE}"
  [[ -f "${BACKUP_PATH}" ]] || die "backup file missing: ${BACKUP_PATH}"
  cp -f "${BACKUP_PATH}" "${RUNC_BIN}"
  chmod 0755 "${RUNC_BIN}"
  LAST_TARGET="restored"
  LAST_SWITCH_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  save_state
  log "runc restored: $("${RUNC_BIN}" --version 2>/dev/null | head -n1)"
}

usage() {
  cat <<EOF
Usage:
  $0 status
  $0 use <runc-tag-or-version>
  $0 restore

Examples:
  $0 status
  $0 use 1.0.0-rc94
  $0 use v1.0.0-rc5
  $0 restore
EOF
}

main() {
  case "${1:-}" in
    status)
      cmd_status
      ;;
    use)
      shift
      cmd_use "${1:-}"
      ;;
    restore)
      cmd_restore
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
