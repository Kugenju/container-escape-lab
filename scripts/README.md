# Environment Switch Tool

`env_labctl.sh` provides profile switching for this lab host.
`runtime_version_switch.sh` provides `runc` version switching for vulnerable-range validation.

## Quick Start

```bash
bash scripts/env_labctl.sh status
bash scripts/env_labctl.sh profile docker
bash scripts/env_labctl.sh profile isula
bash scripts/env_labctl.sh profile k8s-kind
bash scripts/runtime_version_switch.sh status
bash scripts/runtime_version_switch.sh use 1.0.0-rc94
bash scripts/runtime_version_switch.sh restore
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
- `use <tag-or-version>`: download `runc.amd64` from `opencontainers/runc` release, verify `sha256`, and switch `/usr/bin/runc`.
- `restore`: restore original `runc` from local backup.

## Notes

- Run as `root` for service switching and tool installation.
- Run as `root` to switch `/usr/bin/runc`.
- Default cluster name: `escape-lab`.
- Default namespace: `metarget`.
