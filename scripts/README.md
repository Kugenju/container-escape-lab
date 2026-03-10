# Environment Switch Tool

`env_labctl.sh` provides profile switching for this lab host.
`runtime_version_switch.sh` provides `runc` and Docker static-binary version switching for vulnerable-range validation.

## Quick Start

```bash
bash scripts/env_labctl.sh status
bash scripts/env_labctl.sh profile docker
bash scripts/env_labctl.sh profile isula
bash scripts/env_labctl.sh profile k8s-kind
bash scripts/runtime_version_switch.sh status
bash scripts/runtime_version_switch.sh prefetch 1.0.0-rc94
bash scripts/runtime_version_switch.sh use-local 1.0.0-rc94 --scope docker
bash scripts/runtime_version_switch.sh use 1.1.5 --scope dual
bash scripts/runtime_version_switch.sh restore --scope dual
bash scripts/runtime_version_switch.sh docker-status
bash scripts/runtime_version_switch.sh docker-prefetch 20.10.24
bash scripts/runtime_version_switch.sh docker-use-local 20.10.24 --scope docker
bash scripts/runtime_version_switch.sh docker-restore --scope docker
```

## Supported Actions

- `status`: show current services/binaries and k8s reachability.
- `profile docker`: start Docker and stop iSulad.
- `profile isula`: start iSulad and stop Docker.
- `profile dual`: start both Docker and iSulad.
- `profile k8s-kind`: switch to Docker, install `kubectl`/`kind` if missing, create `kind` cluster (`escape-lab`) and namespace (`metarget`).
- `kind-down`: delete `kind` cluster `escape-lab`.
- `ensure kubectl|kind|all`: install missing tools.
- `sync-image <image> [docker-to-isula|isula-to-docker]`: move image between runtimes.

## Runtime Version Switching

- `status`: show current `runc` version and switch metadata.
- `list-cache`: list locally cached `runc` binaries.
- `prefetch <tag-or-version>`: download and cache `runc` binary/checksum for quick later switches.
- `use <tag-or-version> [--scope docker|isula|dual|none]`: switch `/usr/bin/runc`; if `--scope` is set, auto-restart the selected runtime service(s).
- `use-local <tag-or-version> [--scope ...]`: switch only from local cache (no network).
- `restore [--scope docker|isula|dual|none]`: restore original `runc` backup and optionally restart selected runtime service(s).
- `docker-status`: show current Docker/static toolchain version and switch metadata.
- `docker-list-cache`: list locally cached Docker static bundles.
- `docker-prefetch <version>`: download and cache Docker static bundle.
- `docker-use <version> [--scope ...]`: switch Docker static binaries from remote/cache.
- `docker-use-local <version> [--scope ...]`: switch Docker static binaries using local cache only.
- `docker-restore [--scope ...]`: restore Docker binaries from first backup snapshot.

## Notes

- Run as `root` for service switching and tool installation.
- Run as `root` to switch `/usr/bin/runc`.
- Run as `root` to switch Docker static binaries in `/usr/bin`.
- `use-local` is the fastest path for repeatedly switching between already cached versions.
- `docker-use-local` is the fastest path for repeatedly switching between already cached Docker versions.
- Default cluster name: `escape-lab`.
- Default namespace: `metarget`.
