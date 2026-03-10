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
| CVE-2019-5736 | enhanced trigger loop completed on `runc 1.1.8` (`BLOCKED_STAGE=trap_reexec_loader_dependency`); rerun on vulnerable `runc 1.0.0-rc5` reached re-exec trigger (`No help topic for '/bin/sh'`) but still no host proof (`BLOCKED_STAGE=post_trigger_no_host_proof`) | `isula-build` path incompatible for local base image; volume-injection fallback still stuck at `Waiting for runc to exec`, no proof file | `artifacts/repro/docker/CVE-2019-5736/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`, `artifacts/repro/isula/CVE-2019-5736/` |
| CVE-2024-21626 | Docker Attack-1/2 在 `runc 1.1.8` 下仍为 `BLOCKED_STAGE=workdir_fd_path_validation`；新增 `runc-direct` 链路：`runc 1.1.8` 无命中（`BLOCKED_STAGE=direct_runc_fd_probe_no_hit`），切到 `runc 1.1.7` 后命中 `fd=7`（`VULNERABLE_OR_PARTIALLY_VULNERABLE`） | `apparmor=unconfined` unsupported by isula CLI; fd probe likewise blocked at runc init (`mkdir /proc/self/fd/N`) | `artifacts/repro/docker/CVE-2024-21626/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/`, `artifacts/repro/isula/CVE-2024-21626/` |
| CVE-2016-5195 | upgraded to non-interactive safe Dirty-COW probe; read-only test file remained unchanged (`BLOCKED_STAGE=kernel_not_vulnerable_or_patched`) | not started | `artifacts/repro/docker/CVE-2016-5195/auto-run-20260310/` |
| CVE-2016-8655 | upgraded to non-interactive safe AF_PACKET probe; unprivileged run lacked `CAP_NET_RAW` (`BLOCKED_STAGE=cap_net_raw_unavailable`) | not started | `artifacts/repro/docker/CVE-2016-8655/auto-run-20260310/` |
| CVE-2016-9962 | rewritten non-interactive `release_agent` probe finished; host marker absent; `BLOCKED_STAGE=no_host_marker` | privileged run reached cgroup mount, but writing `release_agent` was denied; no host marker | `artifacts/repro/docker/CVE-2016-9962/`, `artifacts/repro/isula/CVE-2016-9962/` |
| CVE-2017-16995 | upgraded to non-interactive safe eBPF probe; unprivileged `BPF_MAP_CREATE` reachable but no exploit chain (`BLOCKED_STAGE=trigger_only_no_priv_esc_chain`) | not started | `artifacts/repro/docker/CVE-2017-16995/auto-run-20260310/` |
| CVE-2017-6074 | upgraded to non-interactive safe DCCP probe; DCCP protocol unavailable (`BLOCKED_STAGE=dccp_module_unavailable`) | not started | `artifacts/repro/docker/CVE-2017-6074/auto-run-20260310/` |
| CVE-2017-7308 | rebuilt script and image to remove apt dependency; probe completed and returned `BLOCKED_STAGE=no_success_marker` | privileged probe reached early exploit stages but no `got r00t` marker | `artifacts/repro/docker/CVE-2017-7308/`, `artifacts/repro/isula/CVE-2017-7308/` |
| CVE-2020-14386 | upgraded to non-interactive safe AF_PACKET vnet probe; unprivileged run lacked `CAP_NET_RAW` (`BLOCKED_STAGE=cap_net_raw_unavailable`) | not started | `artifacts/repro/docker/CVE-2020-14386/auto-run-20260310/` |
| CVE-2021-30465 | rewritten non-interactive race probe completed; with `runc 1.1.8` no host artifact (`BLOCKED_STAGE=runtime_version_not_vulnerable_range`); rerun on `runc 1.0.0-rc94` and `runc 1.0.0-rc5` still未命中竞态（`BLOCKED_STAGE=race_not_hit_or_env_incompatible`） | race process started, no host artifact in target dir (`BLOCKED_STAGE=runtime_version_not_vulnerable_range_or_race_miss`) | `artifacts/repro/docker/CVE-2021-30465/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/`, `artifacts/repro/isula/CVE-2021-30465/` |
| CVE-2022-0995 | upgraded to non-interactive local PoC run; `nobody` execution failed to enter exploit path (`BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`) | not started | `artifacts/repro/docker/CVE-2022-0995/auto-run-20260310/` |
| CVE-2017-1000112 | upgraded to non-interactive containerized PoC run; exploit entered KASLR phase but aborted on SMAP check (`BLOCKED_STAGE=smap_mitigation_detected`) | not started | `artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/` |
| kata-escape-2020 | upgraded to non-interactive runtime/version probe; `kata-runtime` absent in PATH (`BLOCKED_STAGE=kata_runtime_not_installed`) | not started | `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/` |

Additional batch summaries:

- Docker remaining scripts: `artifacts/repro/docker/REMAINING_SUMMARY_20260309.md`
- iSulad remaining scripts: `artifacts/repro/isula/REMAINING_SUMMARY_20260309.md`

Environment switching note (2026-03-09):

- Added `scripts/env_labctl.sh` to switch `docker/isula/k8s-kind` profiles.
- `k8s-kind` profile currently blocked by unstable pull of `kindest/node:v1.30.0` (network reset/timeout to upstream registry), so kubectl scene scripts now consistently return `BLOCKED_STAGE=k8s_api_unreachable` with explicit hint.

Runtime version switching note (2026-03-10):

- Added `scripts/runtime_version_switch.sh` to switch/restore host `runc` with local backup.
- `runc 1.0.0-rc94` switch succeeded and was used to rerun CVE-2021-30465.
- `runc 1.0.0-rc5` switch succeeded via proxy fallback (`gh-proxy.com`), used to rerun CVE-2019-5736 and CVE-2021-30465.
- `runc 1.1.7` switch succeeded and was used by `CVE-2024-21626` direct-runc probe (hit `fd=7`).
