# Reproduction Status

## 1. Baseline

- Host: openEuler 24.03 (LTS-SP3), kernel `6.6.0-132.0.0.111.oe2403sp3.x86_64`
- Docker: `18.09.0` (`EulerVersion 18.09.0.346`)
- iSulad: `2.1.6`
- Default `runc`: `1.1.8`

说明：
- 本状态表已合并多轮复测结论（含后续的 `runc` 版本切换对照），不再拆分“基线记录/增量记录”。

## 2. Snapshot

- Docker：主线 CVE 脚本已覆盖，结论分为 `pass` 或 `BLOCKED_STAGE=*` 两类。
- iSulad：全部 `cves/CVE-*/run_poc.sh` 条目已完成同步验证（含 runtime 无关本地探针）；非 CVE 场景仍在增补中。
- K8s：`k8s-kind` 已可达并可批跑；9 个场景统一阻断在 `BLOCKED_STAGE=k8s_exec_cgroup_path_missing`。

## 3. CVE Matrix

| CVE | Docker | iSulad | Evidence |
| --- | --- | --- | --- |
| CVE-2019-13139 | `run_poc.sh` completed; `BLOCKED_STAGE=parse_remote_refspec` (`invalid refspec` before host command exec) | blocked at input stage: `isula-build` treats crafted URL as local path and rejects before git exec | `artifacts/repro/docker/CVE-2019-13139/`, `artifacts/repro/isula/CVE-2019-13139/` |
| CVE-2019-14271 | reached `docker cp` trigger and malicious NSS replacement, but `/host_fs` absent; `BLOCKED_STAGE=post_trigger_no_escape_artifact` | mapped with `isula run/cp/exec/cp`; malicious NSS replacement succeeded, but `/host_fs` absent | `artifacts/repro/docker/CVE-2019-14271/`, `artifacts/repro/isula/CVE-2019-14271/` |
| CVE-2019-5736 | default `runc 1.1.8` still blocked (`BLOCKED_STAGE=trap_reexec_loader_dependency`); on vulnerable `runc 1.0.0-rc5` high-trigger rerun hit host proof `/tmp/CVE-2019-5736-PWNED` (`VULNERABLE_OR_PARTIALLY_VULNERABLE`) | `isula-build` path incompatible for local base image; volume-injection fallback still stuck at `Waiting for runc to exec`, no proof | `artifacts/repro/docker/CVE-2019-5736/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt3/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt4/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt5/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt6-bash-trigger/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt8-high-trigger/`, `artifacts/repro/isula/CVE-2019-5736/` |
| CVE-2024-21626 | Docker Attack-1/2 on `runc 1.1.8`: `BLOCKED_STAGE=workdir_fd_path_validation`; direct-runc probe: `1.1.8` blocked (`direct_runc_fd_probe_no_hit`), `1.1.7` hit `fd=7` (`VULNERABLE_OR_PARTIALLY_VULNERABLE`) | `apparmor=unconfined` unsupported by isula CLI; fd probe likewise blocked at runc init (`mkdir /proc/self/fd/N`) | `artifacts/repro/docker/CVE-2024-21626/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/`, `artifacts/repro/isula/CVE-2024-21626/` |
| CVE-2016-5195 | non-interactive safe Dirty-COW probe; read-only test file unchanged (`BLOCKED_STAGE=kernel_not_vulnerable_or_patched`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=kernel_not_vulnerable_or_patched`) | `artifacts/repro/docker/CVE-2016-5195/auto-run-20260310/`, `artifacts/repro/isula/CVE-2016-5195/` |
| CVE-2016-8655 | non-interactive safe AF_PACKET probe; unprivileged run lacked `CAP_NET_RAW` (`BLOCKED_STAGE=cap_net_raw_unavailable`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=cap_net_raw_unavailable`) | `artifacts/repro/docker/CVE-2016-8655/auto-run-20260310/`, `artifacts/repro/isula/CVE-2016-8655/` |
| CVE-2016-9962 | non-interactive `release_agent` probe finished; host marker absent (`BLOCKED_STAGE=no_host_marker`) | privileged run reached cgroup mount, but writing `release_agent` was denied; no host marker | `artifacts/repro/docker/CVE-2016-9962/`, `artifacts/repro/isula/CVE-2016-9962/` |
| CVE-2017-1000112 | non-interactive containerized PoC run; entered KASLR phase but aborted on SMAP (`BLOCKED_STAGE=smap_mitigation_detected`) | iSulad-mapped `run/cp/exec` chain completed; blocked at same mitigation (`BLOCKED_STAGE=smap_mitigation_detected`) | `artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/`, `artifacts/repro/isula/CVE-2017-1000112/` |
| CVE-2017-16995 | non-interactive safe eBPF probe; `BPF_MAP_CREATE` reachable but no exploit chain (`BLOCKED_STAGE=trigger_only_no_priv_esc_chain`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=trigger_only_no_priv_esc_chain`) | `artifacts/repro/docker/CVE-2017-16995/auto-run-20260310/`, `artifacts/repro/isula/CVE-2017-16995/` |
| CVE-2017-6074 | non-interactive safe DCCP probe; DCCP unavailable (`BLOCKED_STAGE=dccp_module_unavailable`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=dccp_module_unavailable`) | `artifacts/repro/docker/CVE-2017-6074/auto-run-20260310/`, `artifacts/repro/isula/CVE-2017-6074/` |
| CVE-2017-7308 | rebuilt script/image to remove apt dependency; final `BLOCKED_STAGE=no_success_marker` | privileged probe reached early exploit stages but no `got r00t` marker | `artifacts/repro/docker/CVE-2017-7308/`, `artifacts/repro/isula/CVE-2017-7308/` |
| CVE-2018-18955 | namespace PoC produced root markers in logs (`pass`) | sync rerun under isula profile also produced root markers (`pass`) | `artifacts/repro/docker/CVE-2018-18955/`, `artifacts/repro/isula/CVE-2018-18955/` |
| CVE-2020-14386 | non-interactive safe AF_PACKET vnet probe; unprivileged run lacked `CAP_NET_RAW` (`BLOCKED_STAGE=cap_net_raw_unavailable`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=cap_net_raw_unavailable`) | `artifacts/repro/docker/CVE-2020-14386/auto-run-20260310/`, `artifacts/repro/isula/CVE-2020-14386/` |
| CVE-2021-30465 | race probe aligned to `renameat2` exchange model: on `runc 1.0.0-rc94` hit `VULNERABLE_OR_PARTIALLY_VULNERABLE`; on `runc 1.1.8` blocked (`BLOCKED_STAGE=mount_path_or_permission_validation`) | race process started, no host artifact (`BLOCKED_STAGE=runtime_version_not_vulnerable_range_or_race_miss`) | `artifacts/repro/docker/CVE-2021-30465/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310-attempt2-race-create/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.1.8-20260310-attempt2-race-create/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/`, `artifacts/repro/isula/CVE-2021-30465/` |
| CVE-2021-3493 | overlayfs PoC hit `uid=0/root` marker (`pass`) | sync rerun under isula profile also hit `uid=0/root` marker (`pass`) | `artifacts/repro/docker/CVE-2021-3493/`, `artifacts/repro/isula/CVE-2021-3493/` |
| CVE-2022-0847 | Dirty Pipe PoC hit root-shell indicators (`pass`) | sync rerun under isula profile also hit root-shell indicators (`pass`) | `artifacts/repro/docker/CVE-2022-0847/`, `artifacts/repro/isula/CVE-2022-0847/` |
| CVE-2022-0995 | non-interactive local PoC run; `nobody` execution cannot enter exploit path (`BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`) | `artifacts/repro/docker/CVE-2022-0995/auto-run-20260310/`, `artifacts/repro/isula/CVE-2022-0995/` |
| kata-escape-2020 | non-interactive runtime/version probe; `kata-runtime` absent (`BLOCKED_STAGE=kata_runtime_not_installed`) | not started | `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/` |

## 4. Batch Summaries

- Docker batch summary: `artifacts/repro/docker/REMAINING_SUMMARY.md`
- iSulad batch summary: `artifacts/repro/isula/REMAINING_SUMMARY.md`

## 5. Environment and Runtime Switching Notes

- `scripts/env_labctl.sh` supports `docker/isula/k8s-kind` profile switching.
- `scripts/env_labctl.sh profile k8s-kind` 已增加 Docker 18.09 兼容回退（移除 `--cgroupns=*` 参数）并验证可成功起集群。
- K8s 场景脚本当前主要阻断于 `kubectl exec` 进入容器阶段：`BLOCKED_STAGE=k8s_exec_cgroup_path_missing`（pod 可 Ready，但 exec 时 cgroup 路径不存在）。
- `scripts/runtime_version_switch.sh` verified switch/restore flows:
  - switched to `runc 1.0.0-rc94` for CVE-2021-30465 vulnerable-path validation.
  - switched to `runc 1.0.0-rc5` for CVE-2019-5736 and CVE-2021-30465 comparative reruns.
  - switched to `runc 1.1.7` for CVE-2024-21626 direct-runc probe (`fd=7` hit).
  - restored to `runc 1.1.8` and confirmed negative controls.
