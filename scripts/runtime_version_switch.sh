#!/usr/bin/env bash
set -Eeuo pipefail

RUNC_BIN="${RUNC_BIN:-/usr/bin/runc}"
DOCKER_INSTALL_DIR="${DOCKER_INSTALL_DIR:-/usr/bin}"
STATE_DIR="${STATE_DIR:-/var/lib/runtime-version-switch}"
TMP_DIR="${TMP_DIR:-/tmp/runtime-version-switch}"

RUNC_STATE_FILE="${STATE_DIR}/runc_state.env"
DOCKER_STATE_FILE="${STATE_DIR}/docker_state.env"
LEGACY_STATE_FILE="${STATE_DIR}/state.env"

RUNC_CACHE_DIR="${TMP_DIR}/runc"
DOCKER_CACHE_DIR="${TMP_DIR}/docker"

DOCKER_BINARIES=(
  docker
  dockerd
  containerd
  containerd-shim
  containerd-shim-runc-v2
  docker-proxy
  docker-init
  ctr
)

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

validate_scope() {
  case "${1:-none}" in
    docker|isula|dual|none) ;;
    *) die "invalid scope: $1 (expected docker|isula|dual|none)" ;;
  esac
}

parse_scope_args() {
  local scope="none"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --scope)
        shift
        [[ $# -gt 0 ]] || die "missing value after --scope"
        scope="$1"
        ;;
      --scope=*)
        scope="${1#*=}"
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
    shift
  done
  validate_scope "$scope"
  printf '%s' "$scope"
}

restart_scope() {
  local scope="${1:-none}"
  validate_scope "$scope"
  [[ "$scope" == "none" ]] && return 0
  require_root
  require_cmd systemctl
  case "$scope" in
    docker)
      systemctl restart docker.service
      systemctl is-active docker.service >/dev/null
      ;;
    isula)
      systemctl restart isulad.service
      systemctl is-active isulad.service >/dev/null
      ;;
    dual)
      systemctl restart docker.service isulad.service
      systemctl is-active docker.service >/dev/null
      systemctl is-active isulad.service >/dev/null
      ;;
  esac
}

normalize_runc_tag() {
  local raw="$1"
  if [[ "$raw" =~ ^v ]]; then
    printf '%s' "$raw"
  else
    printf 'v%s' "$raw"
  fi
}

normalize_docker_version() {
  local raw="$1"
  raw="${raw#v}"
  printf '%s' "$raw"
}

load_runc_state() {
  if [[ -f "${RUNC_STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${RUNC_STATE_FILE}"
  elif [[ -f "${LEGACY_STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${LEGACY_STATE_FILE}"
  fi
  RUNC_BACKUP_PATH="${RUNC_BACKUP_PATH:-${BACKUP_PATH:-${backup_path:-}}}"
  RUNC_ORIGINAL_VERSION="${RUNC_ORIGINAL_VERSION:-${ORIGINAL_VERSION:-${original_version:-}}}"
  RUNC_LAST_TARGET="${RUNC_LAST_TARGET:-${LAST_TARGET:-${last_target:-}}}"
  RUNC_LAST_SWITCH_TIME="${RUNC_LAST_SWITCH_TIME:-${LAST_SWITCH_TIME:-${last_switch_time:-}}}"
  RUNC_LAST_SCOPE="${RUNC_LAST_SCOPE:-${LAST_SCOPE:-${last_scope:-none}}}"
}

save_runc_state() {
  mkdir -p "${STATE_DIR}"
  cat > "${RUNC_STATE_FILE}" <<STATE
RUNC_BACKUP_PATH=${RUNC_BACKUP_PATH}
RUNC_ORIGINAL_VERSION=${RUNC_ORIGINAL_VERSION}
RUNC_LAST_TARGET=${RUNC_LAST_TARGET}
RUNC_LAST_SWITCH_TIME=${RUNC_LAST_SWITCH_TIME}
RUNC_LAST_SCOPE=${RUNC_LAST_SCOPE:-none}
STATE
}

backup_current_runc() {
  if [[ -n "${RUNC_BACKUP_PATH:-}" && -f "${RUNC_BACKUP_PATH}" ]]; then
    return
  fi
  mkdir -p "${STATE_DIR}"
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  RUNC_BACKUP_PATH="${STATE_DIR}/runc.backup.${ts}"
  cp -f "${RUNC_BIN}" "${RUNC_BACKUP_PATH}"
  chmod 0755 "${RUNC_BACKUP_PATH}"
  RUNC_ORIGINAL_VERSION="$("${RUNC_BIN}" --version 2>/dev/null | awk 'NR==1{print $3}')"
}

download_runc_binary() {
  local tag="$1"
  local mode="${2:-allow_fetch}"
  local base_url="https://github.com/opencontainers/runc/releases/download/${tag}"
  local bin_url="${base_url}/runc.amd64"
  local sha_url="${base_url}/runc.sha256sum"
  local work="${RUNC_CACHE_DIR}/${tag}"
  local bin_file="${work}/runc.amd64"
  local sha_file="${work}/runc.sha256sum"
  local legacy_bin_file="${TMP_DIR}/${tag}/runc.amd64"
  local legacy_sha_file="${TMP_DIR}/${tag}/runc.sha256sum"
  local -a proxy_prefixes=(
    ""
    "https://gh-proxy.com/"
    "https://ghproxy.net/"
    "https://github.moeyy.xyz/"
  )

  mkdir -p "${work}"
  if [[ ! -s "${bin_file}" && -s "${legacy_bin_file}" ]]; then
    cp -f "${legacy_bin_file}" "${bin_file}"
    if [[ -s "${legacy_sha_file}" ]]; then
      cp -f "${legacy_sha_file}" "${sha_file}"
    fi
  fi
  if [[ -s "${bin_file}" ]]; then
    printf '[*] %s\n' "reuse cached binary: ${bin_file}" >&2
    if [[ -s "${sha_file}" ]]; then
      local expected_cached
      expected_cached="$(awk '/[[:space:]]+runc\.amd64$/{print $1}' "${sha_file}" | head -n1)"
      if [[ -n "${expected_cached}" ]]; then
        local actual_cached
        actual_cached="$(sha256sum "${bin_file}" | awk '{print $1}')"
        [[ "${actual_cached}" == "${expected_cached}" ]] || die "cached checksum mismatch for ${tag}"
      else
        warn "cached checksum file malformed for ${tag}; using cached binary anyway"
      fi
    else
      warn "checksum file not cached for ${tag}; using cached binary without remote verification"
    fi
    printf '%s' "${bin_file}"
    return 0
  fi

  [[ "${mode}" == "allow_fetch" ]] || die "cached binary not found for ${tag} (try prefetch/use first)"

  local ok=0
  for prefix in "${proxy_prefixes[@]}"; do
    local candidate="${prefix}${bin_url}"
    if curl -fL --connect-timeout 8 --max-time 240 --retry 3 --retry-delay 2 --retry-all-errors -o "${bin_file}" "${candidate}"; then
      ok=1
      break
    fi
  done
  [[ "${ok}" -eq 1 ]] || die "failed to download runc binary for ${tag}"

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

cmd_runc_status() {
  load_runc_state
  [[ -x "${RUNC_BIN}" ]] || die "runc binary not found: ${RUNC_BIN}"
  echo "tool=runc"
  echo "runc_path=${RUNC_BIN}"
  echo "runc_version=$("${RUNC_BIN}" --version 2>/dev/null | awk 'NR==1{print $3}')"
  echo "backup_path=${RUNC_BACKUP_PATH:-none}"
  echo "original_version=${RUNC_ORIGINAL_VERSION:-unknown}"
  echo "last_target=${RUNC_LAST_TARGET:-none}"
  echo "last_switch_time=${RUNC_LAST_SWITCH_TIME:-none}"
  echo "last_scope=${RUNC_LAST_SCOPE:-none}"
}

cmd_runc_list_cache() {
  mkdir -p "${RUNC_CACHE_DIR}"
  local legacy_cache_dir="${TMP_DIR}"
  local found=0
  declare -A seen_tags=()
  while IFS= read -r bin; do
    [[ -s "${bin}" ]] || continue
    local ver_dir
    ver_dir="$(dirname "$bin")"
    local tag
    tag="$(basename "$ver_dir")"
    if [[ -n "${seen_tags[$tag]:-}" ]]; then
      continue
    fi
    seen_tags["$tag"]=1
    found=1
    local sum
    sum="$(sha256sum "$bin" | awk '{print $1}')"
    local size
    size="$(stat -c '%s' "$bin" 2>/dev/null || echo unknown)"
    echo "tool=runc tag=${tag} size=${size} sha256=${sum}"
  done < <(find "${RUNC_CACHE_DIR}" "${legacy_cache_dir}" -maxdepth 2 -type f -name 'runc.amd64' 2>/dev/null | sort -u)
  [[ "${found}" -eq 1 ]] || echo "tool=runc no_cached_versions=true"
}

cmd_runc_prefetch() {
  local raw="${1:-}"
  [[ -n "${raw}" ]] || die "usage: $0 prefetch <runc-tag-or-version>"
  require_cmd curl awk sha256sum
  local tag
  tag="$(normalize_runc_tag "${raw}")"
  local dl_bin
  dl_bin="$(download_runc_binary "${tag}" "allow_fetch")"
  log "runc prefetch done: tag=${tag} path=${dl_bin}"
}

cmd_runc_use_common() {
  local raw="${1:-}"
  local mode="${2:-allow_fetch}"
  local scope="${3:-none}"
  [[ -n "${raw}" ]] || die "usage: $0 use <runc-tag-or-version> [--scope ...]"
  validate_scope "${scope}"
  require_root
  require_cmd awk sha256sum cp chmod date
  if [[ "${mode}" == "allow_fetch" ]]; then
    require_cmd curl
  fi

  load_runc_state
  [[ -x "${RUNC_BIN}" ]] || die "runc binary not found: ${RUNC_BIN}"
  backup_current_runc

  local tag
  tag="$(normalize_runc_tag "${raw}")"
  log "switch runc -> ${tag}"
  local dl_bin
  dl_bin="$(download_runc_binary "${tag}" "${mode}")"
  cp -f "${dl_bin}" "${RUNC_BIN}"
  chmod 0755 "${RUNC_BIN}"

  RUNC_LAST_TARGET="${tag}"
  RUNC_LAST_SCOPE="${scope}"
  RUNC_LAST_SWITCH_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  save_runc_state
  restart_scope "${scope}"

  log "runc switched: $("${RUNC_BIN}" --version 2>/dev/null | head -n1) (scope=${scope})"
}

cmd_runc_use() {
  local raw="${1:-}"
  shift || true
  local scope
  scope="$(parse_scope_args "$@")"
  cmd_runc_use_common "${raw}" "allow_fetch" "${scope}"
}

cmd_runc_use_local() {
  local raw="${1:-}"
  shift || true
  local scope
  scope="$(parse_scope_args "$@")"
  cmd_runc_use_common "${raw}" "cache_only" "${scope}"
}

cmd_runc_restore() {
  local scope="${1:-none}"
  validate_scope "${scope}"
  require_root
  load_runc_state
  [[ -n "${RUNC_BACKUP_PATH:-}" ]] || die "no runc backup recorded in ${RUNC_STATE_FILE}"
  [[ -f "${RUNC_BACKUP_PATH}" ]] || die "runc backup file missing: ${RUNC_BACKUP_PATH}"
  cp -f "${RUNC_BACKUP_PATH}" "${RUNC_BIN}"
  chmod 0755 "${RUNC_BIN}"
  RUNC_LAST_SCOPE="${scope}"
  RUNC_LAST_TARGET="restored"
  RUNC_LAST_SWITCH_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  save_runc_state
  restart_scope "${scope}"
  log "runc restored: $("${RUNC_BIN}" --version 2>/dev/null | head -n1) (scope=${scope})"
}

load_docker_state() {
  if [[ -f "${DOCKER_STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${DOCKER_STATE_FILE}"
  fi
  DOCKER_BACKUP_DIR="${DOCKER_BACKUP_DIR:-${docker_backup_dir:-}}"
  DOCKER_ORIGINAL_VERSION="${DOCKER_ORIGINAL_VERSION:-${docker_original_version:-}}"
  DOCKER_LAST_TARGET="${DOCKER_LAST_TARGET:-${docker_last_target:-}}"
  DOCKER_LAST_SWITCH_TIME="${DOCKER_LAST_SWITCH_TIME:-${docker_last_switch_time:-}}"
  DOCKER_LAST_SCOPE="${DOCKER_LAST_SCOPE:-${docker_last_scope:-none}}"
}

save_docker_state() {
  mkdir -p "${STATE_DIR}"
  cat > "${DOCKER_STATE_FILE}" <<STATE
DOCKER_BACKUP_DIR=${DOCKER_BACKUP_DIR}
DOCKER_ORIGINAL_VERSION=${DOCKER_ORIGINAL_VERSION}
DOCKER_LAST_TARGET=${DOCKER_LAST_TARGET}
DOCKER_LAST_SWITCH_TIME=${DOCKER_LAST_SWITCH_TIME}
DOCKER_LAST_SCOPE=${DOCKER_LAST_SCOPE:-none}
STATE
}

backup_current_docker_bins() {
  if [[ -n "${DOCKER_BACKUP_DIR:-}" && -d "${DOCKER_BACKUP_DIR}" ]]; then
    return
  fi
  mkdir -p "${STATE_DIR}"
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  DOCKER_BACKUP_DIR="${STATE_DIR}/docker.backup.${ts}"
  mkdir -p "${DOCKER_BACKUP_DIR}"

  local copied=0
  local b
  for b in "${DOCKER_BINARIES[@]}"; do
    local src="${DOCKER_INSTALL_DIR}/${b}"
    if [[ -f "${src}" ]]; then
      cp -f "${src}" "${DOCKER_BACKUP_DIR}/${b}"
      chmod 0755 "${DOCKER_BACKUP_DIR}/${b}"
      copied=1
    fi
  done
  [[ "${copied}" -eq 1 ]] || die "no docker binaries found to backup under ${DOCKER_INSTALL_DIR}"

  if command -v docker >/dev/null 2>&1; then
    DOCKER_ORIGINAL_VERSION="$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')"
  else
    DOCKER_ORIGINAL_VERSION="unknown"
  fi
}

download_docker_bundle_dir() {
  local raw="$1"
  local mode="${2:-allow_fetch}"
  local ver
  ver="$(normalize_docker_version "${raw}")"
  local work="${DOCKER_CACHE_DIR}/${ver}"
  local tgz="${work}/docker-${ver}.tgz"
  local extract_dir="${work}/docker"
  local url="https://download.docker.com/linux/static/stable/x86_64/docker-${ver}.tgz"
  local -a mirror_prefixes=(
    ""
    "https://gh-proxy.com/"
    "https://ghproxy.net/"
  )

  mkdir -p "${work}"
  if [[ ! -s "${tgz}" ]]; then
    [[ "${mode}" == "allow_fetch" ]] || die "cached docker bundle not found for ${ver} (try docker-prefetch/docker-use first)"
    local ok=0
    for prefix in "${mirror_prefixes[@]}"; do
      local candidate="${prefix}${url}"
      if curl -fL --connect-timeout 10 --max-time 420 --retry 3 --retry-delay 2 --retry-all-errors -o "${tgz}" "${candidate}"; then
        ok=1
        break
      fi
    done
    [[ "${ok}" -eq 1 ]] || die "failed to download docker static bundle for ${ver}"
  else
    printf '[*] %s\n' "reuse cached docker bundle: ${tgz}" >&2
  fi

  tar -tzf "${tgz}" >/dev/null 2>&1 || die "docker bundle is not a valid tar.gz: ${tgz}"
  if [[ ! -d "${extract_dir}" ]]; then
    tar -xzf "${tgz}" -C "${work}"
  fi
  [[ -d "${extract_dir}" ]] || die "docker bundle extract missing directory: ${extract_dir}"
  [[ -x "${extract_dir}/docker" ]] || die "docker bundle missing binary: ${extract_dir}/docker"

  printf '%s' "${extract_dir}"
}

apply_docker_bundle_bins() {
  local src_dir="$1"
  local updated=0
  local b
  for b in "${DOCKER_BINARIES[@]}"; do
    if [[ -f "${src_dir}/${b}" ]]; then
      cp -f "${src_dir}/${b}" "${DOCKER_INSTALL_DIR}/${b}"
      chmod 0755 "${DOCKER_INSTALL_DIR}/${b}"
      updated=1
    fi
  done
  [[ "${updated}" -eq 1 ]] || die "no docker binaries were applied from ${src_dir}"
}

cmd_docker_status() {
  load_docker_state
  echo "tool=docker"
  if command -v docker >/dev/null 2>&1; then
    echo "docker_version=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')"
    echo "docker_binary=$(command -v docker)"
  else
    echo "docker_version=not_found"
    echo "docker_binary=not_found"
  fi
  if command -v dockerd >/dev/null 2>&1; then
    echo "dockerd_binary=$(command -v dockerd)"
  fi
  if command -v containerd >/dev/null 2>&1; then
    echo "containerd_version=$(containerd --version 2>/dev/null | awk 'NR==1{print $3}')"
  fi
  echo "backup_dir=${DOCKER_BACKUP_DIR:-none}"
  echo "original_version=${DOCKER_ORIGINAL_VERSION:-unknown}"
  echo "last_target=${DOCKER_LAST_TARGET:-none}"
  echo "last_switch_time=${DOCKER_LAST_SWITCH_TIME:-none}"
  echo "last_scope=${DOCKER_LAST_SCOPE:-none}"
}

cmd_docker_list_cache() {
  mkdir -p "${DOCKER_CACHE_DIR}"
  local found=0
  while IFS= read -r tgz; do
    found=1
    local ver_dir
    ver_dir="$(dirname "$tgz")"
    local ver
    ver="$(basename "$ver_dir")"
    local sum
    sum="$(sha256sum "$tgz" | awk '{print $1}')"
    local size
    size="$(stat -c '%s' "$tgz" 2>/dev/null || echo unknown)"
    echo "tool=docker version=${ver} size=${size} sha256=${sum}"
  done < <(find "${DOCKER_CACHE_DIR}" -maxdepth 2 -type f -name 'docker-*.tgz' | sort)
  [[ "${found}" -eq 1 ]] || echo "tool=docker no_cached_versions=true"
}

cmd_docker_prefetch() {
  local raw="${1:-}"
  [[ -n "${raw}" ]] || die "usage: $0 docker-prefetch <docker-version>"
  require_cmd curl tar sha256sum
  local ver
  ver="$(normalize_docker_version "${raw}")"
  local extract_dir
  extract_dir="$(download_docker_bundle_dir "${ver}" "allow_fetch")"
  log "docker prefetch done: version=${ver} dir=${extract_dir}"
}

cmd_docker_use_common() {
  local raw="${1:-}"
  local mode="${2:-allow_fetch}"
  local scope="${3:-docker}"
  [[ -n "${raw}" ]] || die "usage: $0 docker-use <docker-version> [--scope ...]"
  validate_scope "${scope}"
  require_root
  require_cmd cp chmod tar date sha256sum
  if [[ "${mode}" == "allow_fetch" ]]; then
    require_cmd curl
  fi

  load_docker_state
  backup_current_docker_bins

  local ver
  ver="$(normalize_docker_version "${raw}")"
  log "switch docker binaries -> ${ver}"

  local src_dir
  src_dir="$(download_docker_bundle_dir "${ver}" "${mode}")"
  apply_docker_bundle_bins "${src_dir}"

  DOCKER_LAST_TARGET="${ver}"
  DOCKER_LAST_SCOPE="${scope}"
  DOCKER_LAST_SWITCH_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  save_docker_state
  restart_scope "${scope}"

  if command -v docker >/dev/null 2>&1; then
    log "docker switched: $(docker --version 2>/dev/null) (scope=${scope})"
  else
    warn "docker binary not found after switch"
  fi
}

cmd_docker_use() {
  local raw="${1:-}"
  shift || true
  local scope
  scope="$(parse_scope_args "$@")"
  cmd_docker_use_common "${raw}" "allow_fetch" "${scope}"
}

cmd_docker_use_local() {
  local raw="${1:-}"
  shift || true
  local scope
  scope="$(parse_scope_args "$@")"
  cmd_docker_use_common "${raw}" "cache_only" "${scope}"
}

cmd_docker_restore() {
  local scope="${1:-docker}"
  validate_scope "${scope}"
  require_root
  load_docker_state
  [[ -n "${DOCKER_BACKUP_DIR:-}" ]] || die "no docker backup recorded in ${DOCKER_STATE_FILE}"
  [[ -d "${DOCKER_BACKUP_DIR}" ]] || die "docker backup directory missing: ${DOCKER_BACKUP_DIR}"

  local restored=0
  local b
  for b in "${DOCKER_BINARIES[@]}"; do
    if [[ -f "${DOCKER_BACKUP_DIR}/${b}" ]]; then
      cp -f "${DOCKER_BACKUP_DIR}/${b}" "${DOCKER_INSTALL_DIR}/${b}"
      chmod 0755 "${DOCKER_INSTALL_DIR}/${b}"
      restored=1
    fi
  done
  [[ "${restored}" -eq 1 ]] || die "no restorable docker binaries in ${DOCKER_BACKUP_DIR}"

  DOCKER_LAST_SCOPE="${scope}"
  DOCKER_LAST_TARGET="restored"
  DOCKER_LAST_SWITCH_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  save_docker_state
  restart_scope "${scope}"

  if command -v docker >/dev/null 2>&1; then
    log "docker restored: $(docker --version 2>/dev/null) (scope=${scope})"
  else
    warn "docker binary not found after restore"
  fi
}

usage() {
  cat <<USAGE
Usage:
  # runc mode (backward compatible)
  $0 status
  $0 list-cache
  $0 prefetch <runc-tag-or-version>
  $0 use <runc-tag-or-version> [--scope docker|isula|dual|none]
  $0 use-local <runc-tag-or-version> [--scope docker|isula|dual|none]
  $0 restore [--scope docker|isula|dual|none]

  # docker static-binary mode
  $0 docker-status
  $0 docker-list-cache
  $0 docker-prefetch <docker-version>
  $0 docker-use <docker-version> [--scope docker|isula|dual|none]
  $0 docker-use-local <docker-version> [--scope docker|isula|dual|none]
  $0 docker-restore [--scope docker|isula|dual|none]

Examples:
  $0 prefetch 1.0.0-rc94
  $0 use-local 1.0.0-rc94 --scope docker
  $0 use 1.1.5 --scope dual
  $0 restore --scope isula

  $0 docker-prefetch 20.10.24
  $0 docker-use-local 20.10.24 --scope docker
  $0 docker-use 24.0.9 --scope docker
  $0 docker-restore --scope docker
USAGE
}

main() {
  case "${1:-}" in
    status)
      cmd_runc_status
      ;;
    list-cache)
      cmd_runc_list_cache
      ;;
    prefetch)
      shift
      cmd_runc_prefetch "${1:-}"
      ;;
    use)
      shift
      cmd_runc_use "${1:-}" "${@:2}"
      ;;
    use-local)
      shift
      cmd_runc_use_local "${1:-}" "${@:2}"
      ;;
    restore)
      shift
      cmd_runc_restore "$(parse_scope_args "$@")"
      ;;
    docker-status)
      cmd_docker_status
      ;;
    docker-list-cache)
      cmd_docker_list_cache
      ;;
    docker-prefetch)
      shift
      cmd_docker_prefetch "${1:-}"
      ;;
    docker-use)
      shift
      cmd_docker_use "${1:-}" "${@:2}"
      ;;
    docker-use-local)
      shift
      cmd_docker_use_local "${1:-}" "${@:2}"
      ;;
    docker-restore)
      shift
      cmd_docker_restore "$(parse_scope_args "$@")"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
