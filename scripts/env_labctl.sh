#!/usr/bin/env bash
set -Eeuo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-escape-lab}"
K8S_NAMESPACE="${K8S_NAMESPACE:-metarget}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.30.0}"

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

download_file() {
  local url="$1"
  local out="$2"
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors -o "$out" "$url"
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root"
}

svc_state() {
  local svc="$1"
  systemctl is-active "$svc" 2>/dev/null || true
}

start_svc() {
  local svc="$1"
  systemctl start "$svc"
}

stop_svc() {
  local svc="$1"
  systemctl stop "$svc" || true
}

docker_supports_cgroupns() {
  docker run --help 2>/dev/null | grep -q -- '--cgroupns'
}

kind_create_with_legacy_docker() {
  local name="$1"
  local node_image="$2"
  local wait_sec="$3"
  local wrapper_dir
  wrapper_dir="$(mktemp -d /tmp/kind_docker_compat.XXXXXX)"
  cat >"$wrapper_dir/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
real_docker="${REAL_DOCKER_PATH:-/usr/bin/docker}"
args=()
for a in "$@"; do
  if [[ "$a" == --cgroupns=* ]]; then
    continue
  fi
  args+=("$a")
done
exec "$real_docker" "${args[@]}"
EOF
  chmod +x "$wrapper_dir/docker"
  REAL_DOCKER_PATH="$(command -v docker)" PATH="$wrapper_dir:$PATH" \
    kind create cluster --name "$name" --image "$node_image" --wait "${wait_sec}s"
  local rc=$?
  rm -rf "$wrapper_dir"
  return "$rc"
}

profile_status() {
  cat <<EOF
Runtime services:
  docker.service:    $(svc_state docker.service)
  isulad.service:    $(svc_state isulad.service)
  containerd.service:$(svc_state containerd.service)
Binary checks:
  docker:  $(command -v docker >/dev/null 2>&1 && echo yes || echo no)
  isula:   $(command -v isula >/dev/null 2>&1 && echo yes || echo no)
  kubectl: $(command -v kubectl >/dev/null 2>&1 && echo yes || echo no)
  kind:    $(command -v kind >/dev/null 2>&1 && echo yes || echo no)
EOF
  if command -v kind >/dev/null 2>&1; then
    local clusters
    clusters="$(kind get clusters 2>/dev/null || true)"
    printf 'Kind clusters: %s\n' "${clusters:-none}"
  fi
  if command -v kubectl >/dev/null 2>&1; then
    kubectl get nodes >/dev/null 2>&1 && echo "kubectl cluster access: ok" || echo "kubectl cluster access: unavailable"
  fi
}

profile_docker() {
  require_root
  command -v docker >/dev/null 2>&1 || die "docker not found"
  log "switch profile -> docker"
  stop_svc isulad.service
  start_svc docker.service
  log "docker=$(svc_state docker.service), isulad=$(svc_state isulad.service)"
}

profile_isula() {
  require_root
  command -v isula >/dev/null 2>&1 || die "isula not found"
  log "switch profile -> isula"
  stop_svc docker.service
  start_svc isulad.service
  log "docker=$(svc_state docker.service), isulad=$(svc_state isulad.service)"
}

profile_dual() {
  require_root
  command -v docker >/dev/null 2>&1 || die "docker not found"
  command -v isula >/dev/null 2>&1 || die "isula not found"
  log "switch profile -> dual"
  start_svc docker.service
  start_svc isulad.service
  log "docker=$(svc_state docker.service), isulad=$(svc_state isulad.service)"
}

ensure_kubectl() {
  require_root
  if command -v kubectl >/dev/null 2>&1; then
    log "kubectl already installed: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -n1)"
    return
  fi
  command -v curl >/dev/null 2>&1 || die "curl is required to install kubectl"
  local ver
  ver="$(curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors https://dl.k8s.io/release/stable.txt)"
  [[ -n "$ver" ]] || die "failed to query kubectl stable version"
  log "install kubectl $ver -> /usr/local/bin/kubectl"
  download_file "https://dl.k8s.io/release/${ver}/bin/linux/amd64/kubectl" /usr/local/bin/kubectl
  chmod +x /usr/local/bin/kubectl
  kubectl version --client >/dev/null 2>&1 || die "kubectl install verification failed"
}

ensure_kind() {
  require_root
  if command -v kind >/dev/null 2>&1; then
    log "kind already installed: $(kind version 2>/dev/null || true)"
    return
  fi
  command -v curl >/dev/null 2>&1 || die "curl is required to install kind"
  local kind_ver arch
  kind_ver="${KIND_VERSION:-}"
  if [[ -z "$kind_ver" ]]; then
    kind_ver="$(curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors https://api.github.com/repos/kubernetes-sigs/kind/releases/latest | sed -n 's/.*"tag_name": *"\\([^"]*\\)".*/\\1/p' | head -n1)"
  fi
  [[ -n "$kind_ver" ]] || kind_ver="v0.23.0"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "unsupported arch for kind: $arch" ;;
  esac
  log "install kind $kind_ver -> /usr/local/bin/kind"
  download_file "https://kind.sigs.k8s.io/dl/${kind_ver}/kind-linux-${arch}" /usr/local/bin/kind
  chmod +x /usr/local/bin/kind
  kind version >/dev/null 2>&1 || die "kind install verification failed"
}

kind_up() {
  require_root
  profile_docker
  ensure_kubectl
  ensure_kind
  local node_image="$KIND_NODE_IMAGE"
  log "pre-pull kind node image: $node_image"
  if ! timeout 420 docker pull "$node_image"; then
    warn "pull failed for $node_image"
    if [[ "$node_image" == kindest/node:* ]]; then
      local mirror_image="docker.m.daocloud.io/${node_image}"
      warn "trying mirror image: $mirror_image"
      timeout 420 docker pull "$mirror_image" || die "failed to pull kind node image (network/mirror issue)"
      node_image="$mirror_image"
    else
      die "failed to pull kind node image (network/mirror issue)"
    fi
  fi
  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "kind cluster already exists: $CLUSTER_NAME"
  else
    log "create kind cluster: $CLUSTER_NAME"
    if docker_supports_cgroupns; then
      kind create cluster --name "$CLUSTER_NAME" --image "$node_image" --wait 180s
    else
      warn "docker does not support --cgroupns (legacy Docker detected); applying kind compatibility wrapper"
      kind_create_with_legacy_docker "$CLUSTER_NAME" "$node_image" 180 || \
        die "kind cluster create failed with legacy Docker compatibility mode"
    fi
  fi
  kubectl get nodes >/dev/null 2>&1 || die "kubectl cannot reach kind cluster"
  kubectl get ns "$K8S_NAMESPACE" >/dev/null 2>&1 || kubectl create ns "$K8S_NAMESPACE" >/dev/null
  log "kind cluster ready, namespace=$K8S_NAMESPACE"
}

kind_down() {
  require_root
  if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "delete kind cluster: $CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
  else
    log "kind cluster not found: $CLUSTER_NAME"
  fi
}

sync_image() {
  require_root
  local img="${1:-}"
  local direction="${2:-docker-to-isula}"
  [[ -n "$img" ]] || die "usage: $0 sync-image <image[:tag]> [docker-to-isula|isula-to-docker]"
  command -v docker >/dev/null 2>&1 || die "docker not found"
  command -v isula >/dev/null 2>&1 || die "isula not found"
  local tmp_tar
  tmp_tar="$(mktemp /tmp/env_labctl_image.XXXXXX.tar)"
  case "$direction" in
    docker-to-isula)
      docker save -o "$tmp_tar" "$img"
      isula load -i "$tmp_tar"
      ;;
    isula-to-docker)
      isula save -o "$tmp_tar" "$img"
      docker load -i "$tmp_tar"
      ;;
    *)
      rm -f "$tmp_tar"
      die "unknown direction: $direction"
      ;;
  esac
  rm -f "$tmp_tar"
  log "sync image done: $img ($direction)"
}

usage() {
  cat <<EOF
Usage:
  $0 status
  $0 profile <docker|isula|dual|k8s-kind>
  $0 kind-down
  $0 ensure <kubectl|kind|all>
  $0 sync-image <image[:tag]> [docker-to-isula|isula-to-docker]

Examples:
  $0 profile docker
  $0 profile isula
  $0 profile k8s-kind
  $0 sync-image ubuntu:20.04 docker-to-isula
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    status)
      profile_status
      ;;
    profile)
      local p="${2:-}"
      case "$p" in
        docker) profile_docker ;;
        isula) profile_isula ;;
        dual) profile_dual ;;
        k8s-kind) kind_up ;;
        *) usage; exit 1 ;;
      esac
      ;;
    kind-down)
      kind_down
      ;;
    ensure)
      case "${2:-}" in
        kubectl) ensure_kubectl ;;
        kind) ensure_kind ;;
        all) ensure_kubectl; ensure_kind ;;
        *) usage; exit 1 ;;
      esac
      ;;
    sync-image)
      sync_image "${2:-}" "${3:-docker-to-isula}"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
