# Environment Switch Tool

`env_labctl.sh` provides profile switching for this lab host.

## Quick Start

```bash
bash scripts/env_labctl.sh status
bash scripts/env_labctl.sh profile docker
bash scripts/env_labctl.sh profile isula
bash scripts/env_labctl.sh profile k8s-kind
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

## Notes

- Run as `root` for service switching and tool installation.
- Default cluster name: `escape-lab`.
- Default namespace: `metarget`.
