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
| CVE-2016-9962 | rewritten non-interactive `release_agent` probe finished; host marker absent; `BLOCKED_STAGE=no_host_marker` | privileged run reached cgroup mount, but writing `release_agent` was denied; no host marker | `artifacts/repro/docker/CVE-2016-9962/`, `artifacts/repro/isula/CVE-2016-9962/` |
| CVE-2017-7308 | rebuilt script and image to remove apt dependency; probe completed and returned `BLOCKED_STAGE=no_success_marker` | privileged probe reached early exploit stages but no `got r00t` marker | `artifacts/repro/docker/CVE-2017-7308/`, `artifacts/repro/isula/CVE-2017-7308/` |
| CVE-2021-30465 | rewritten non-interactive race probe completed; with `runc 1.1.8` no host artifact, `BLOCKED_STAGE=runtime_version_not_vulnerable_range` | race process started, no host artifact in target dir (`BLOCKED_STAGE=runtime_version_not_vulnerable_range_or_race_miss`) | `artifacts/repro/docker/CVE-2021-30465/`, `artifacts/repro/isula/CVE-2021-30465/` |

Additional batch summaries:

- Docker remaining scripts: `artifacts/repro/docker/REMAINING_SUMMARY_20260309.md`
- iSulad remaining scripts: `artifacts/repro/isula/REMAINING_SUMMARY_20260309.md`
