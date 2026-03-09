# Reproduction Status

Baseline:

- Date: 2026-03-09
- Host: openEuler 24.03 (LTS-SP3), kernel `6.6.0-132.0.0.111.oe2403sp3.x86_64`
- Docker: `18.09.0` (`EulerVersion 18.09.0.346`)
- iSulad: `2.1.6` (installed, will be validated after Docker phase)

| CVE | Docker | iSulad | Evidence |
| --- | --- | --- | --- |
| CVE-2019-13139 | `run_poc.sh` multi-payload run completed; `BLOCKED_STAGE=parse_remote_refspec` (`invalid refspec` before host command exec) | not applicable / blocked at input stage: `isula-build` treats crafted URL as local path and rejects before any git exec | `artifacts/repro/docker/CVE-2019-13139/`, `artifacts/repro/isula/CVE-2019-13139/` |
| CVE-2019-14271 | `run_poc.sh` reached `docker cp` trigger and malicious NSS replacement, but `/host_fs` absent; `BLOCKED_STAGE=post_trigger_no_escape_artifact` | mapped with `isula run/cp/exec/cp`: malicious `libnss_files.so.2` replacement succeeded, but `/host_fs` absent | `artifacts/repro/docker/CVE-2019-14271/`, `artifacts/repro/isula/CVE-2019-14271/` |
| CVE-2019-5736 | enhanced trigger loop completed; exploit observed `runc pid`, but every trigger failed with `/proc/self/exe ... libseccomp.so.2`; `BLOCKED_STAGE=trap_reexec_loader_dependency` | `isula-build` path incompatible for local base image; volume-injection fallback still stuck at `Waiting for runc to exec`, no proof file | `artifacts/repro/docker/CVE-2019-5736/`, `artifacts/repro/isula/CVE-2019-5736/` |
| CVE-2024-21626 | Attack-1/Attack-2 probes completed; no host marker exposure; `BLOCKED_STAGE=workdir_fd_path_validation` with `chdir ... not a directory` | `apparmor=unconfined` unsupported by isula CLI; fd probe likewise blocked at runc init (`mkdir /proc/self/fd/N`) | `artifacts/repro/docker/CVE-2024-21626/`, `artifacts/repro/isula/CVE-2024-21626/` |
