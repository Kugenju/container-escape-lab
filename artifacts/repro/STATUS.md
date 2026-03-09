# Reproduction Status

Baseline:

- Date: 2026-03-09
- Host: openEuler 24.03 (LTS-SP3), kernel `6.6.0-132.0.0.111.oe2403sp3.x86_64`
- Docker: `18.09.0` (`EulerVersion 18.09.0.346`)
- iSulad: `2.1.6` (installed, will be validated after Docker phase)

| CVE | Docker | iSulad | Evidence |
| --- | --- | --- | --- |
| CVE-2019-13139 | blocked at remote git refspec parse (`invalid refspec`) | pending | `artifacts/repro/docker/CVE-2019-13139/` |
| CVE-2019-14271 | attempted: first blocked by Docker Hub reset, then reached `docker cp` trigger with local image and path fix, but `/host_fs` not created | pending | `artifacts/repro/docker/CVE-2019-14271/` |
| CVE-2019-5736 | attempted with host-build Dockerfile rewrite and `docker exec` trigger; exploit stuck at `Waiting for runc to exec`, no host proof file | pending | `artifacts/repro/docker/CVE-2019-5736/` |
| CVE-2024-21626 | attempted: simplified PoC no host marker; fd probe (`/proc/self/fd/N`) blocked at runc init with `mkdir ... not a directory` | pending | `artifacts/repro/docker/CVE-2024-21626/` |
