# Reproduction Status

## 1. Baseline

- Host: openEuler 24.03 (LTS-SP3), kernel `6.6.0-132.0.0.111.oe2403sp3.x86_64`
- Docker (historical baseline): `18.09.0` (`EulerVersion 18.09.0.346`)
- Docker (latest K8s validation): `20.10.24` (static binary)
- containerd (latest K8s validation): `1.6.20`
- runc (latest K8s validation): `1.1.5`
- iSulad: `2.1.6`
- Active `runc` (current Docker20 stack): `1.1.5`
- Historical default/negative-control `runc`: `1.1.8`

说明：
- 本状态表已合并多轮复测结论（含后续的 `runc` 版本切换对照），不再拆分“基线记录/增量记录”。

## 2. Snapshot

- Docker：主线 CVE 脚本已覆盖，结论分为 `pass` 或 `BLOCKED_STAGE=*` 两类。
- iSulad：全部 `cves/CVE-*/run_poc.sh` 条目已完成同步验证（含 runtime 无关本地探针）；非 CVE 场景仍在增补中。
- K8s（Docker 18.09 基线）：`kubectl exec` 会触发 `k8s_exec_cgroup_path_missing`，9 个场景通过日志探针回退形成 `PROBE_LOG_FALLBACK_OK`。
- K8s（Docker 20.10.24 复测）：首轮复测中 `kubectl exec` 已恢复为 `PROBE_EXECUTED`，且 9 个场景批跑均 `exit_code=0`；但重复 `kind-up` 仍出现 kubelet 健康检查超时，当前稳定性未完全收敛。
- 最新 CVE 检索（runc 2025 系列）已优先完成：`CVE-2025-31133` 已复现并完成 Docker+iSulad 同步验证；`CVE-2025-52881` 与 `CVE-2025-52565` 暂未发现可直接落地的公开 runnable PoC。
- 联网新增 `CVE-2025-23266` PoC 来源（`jpts/cve-2025-23266-poc`）并完成 Docker+iSulad 实测；当前主机因缺失 `nvidia` runtime 前置条件而阻断。

## 3. CVE Matrix

| CVE | Docker | iSulad | Evidence |
| --- | --- | --- | --- |
| CVE-2019-13139 | `run_poc.sh` completed; `BLOCKED_STAGE=parse_remote_refspec` (`invalid refspec` before host command exec) | blocked at input stage: `isula-build` treats crafted URL as local path and rejects before git exec | `artifacts/repro/docker/CVE-2019-13139/`, `artifacts/repro/isula/CVE-2019-13139/` |
| CVE-2019-14271 | baseline `18.09.0` and vulnerable-window retest `19.03.0` both reached `docker cp` trigger + malicious NSS replacement but no `/host_fs`; `BLOCKED_STAGE=post_trigger_no_escape_artifact` | mapped with `isula run/cp/exec/cp`; malicious NSS replacement succeeded, but `/host_fs` absent | `artifacts/repro/docker/CVE-2019-14271/`, `artifacts/repro/docker/CVE-2019-14271/docker-19.03.0-20260310-attempt1/`, `artifacts/repro/isula/CVE-2019-14271/` |
| CVE-2019-5736 | default `runc 1.1.8` still blocked (`BLOCKED_STAGE=trap_reexec_loader_dependency`); on vulnerable `runc 1.0.0-rc5` high-trigger rerun hit host proof `/tmp/CVE-2019-5736-PWNED` (`VULNERABLE_OR_PARTIALLY_VULNERABLE`) | `isula-build`/volume variants remain blocked; additional `runc 1.0.0-rc5` rerun could not start trap container due runtime compatibility (`runtime-log: namespace {"cgroup" ""} does not exist`) | `artifacts/repro/docker/CVE-2019-5736/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt3/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt4/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt5/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt6-bash-trigger/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt8-high-trigger/`, `artifacts/repro/isula/CVE-2019-5736/`, `artifacts/repro/isula/CVE-2019-5736/runc-1.0.0-rc5-high-trigger-rerun3/` |
| CVE-2024-21626 | Docker Attack-1/2: on `runc 1.1.8` blocked (`workdir_fd_path_validation`), on Docker `20.10.24` + `runc 1.1.5` Attack-1 hit host marker (`fd=9`, `VULNERABLE_OR_PARTIALLY_VULNERABLE`); direct-runc contrast still `1.1.7` hit / `1.1.8` block | synchronized isula `--workdir /proc/self/fd/N` scan on `runc 1.1.5` hit host marker (`fd=8`, `VULNERABLE_OR_PARTIALLY_VULNERABLE`) | `artifacts/repro/docker/CVE-2024-21626/`, `artifacts/repro/docker/CVE-2024-21626/docker20-runc1.1.5-20260310-attack-path/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/`, `artifacts/repro/isula/CVE-2024-21626/`, `artifacts/repro/isula/CVE-2024-21626/docker20-runc1.1.5-sync-20260310-attempt2/` |
| CVE-2025-31133 | on Docker `20.10.24` + `runc 1.1.5`, symlink-race PoC hit host `core_pattern` token and returned `VULNERABLE_OR_PARTIALLY_VULNERABLE` | under iSulad profile (`ROOTFS_RUNTIME=isula`) same PoC also hit host token on retry and returned `VULNERABLE_OR_PARTIALLY_VULNERABLE` | `artifacts/repro/docker/CVE-2025-31133/docker20-runc1.1.5-20260311-attempt5/`, `artifacts/repro/isula/CVE-2025-31133/isula2.1.6-runc1.1.5-20260311-attempt2/` |
| CVE-2025-23266 | imported upstream PoC (`jpts/cve-2025-23266-poc`) but blocked before exploit chain because Docker runtime list has no `nvidia` (`BLOCKED_STAGE=nvidia_runtime_unavailable`) | synchronized rerun under iSulad profile also blocked on missing `nvidia` runtime (`BLOCKED_STAGE=isula_nvidia_runtime_unavailable`) | `artifacts/repro/docker/CVE-2025-23266/docker20-runc1.1.5-20260311-attempt1/`, `artifacts/repro/isula/CVE-2025-23266/isula2.1.6-runc1.1.5-20260311-attempt1/` |
| CVE-2016-5195 | non-interactive safe Dirty-COW probe; read-only test file unchanged (`BLOCKED_STAGE=kernel_not_vulnerable_or_patched`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=kernel_not_vulnerable_or_patched`) | `artifacts/repro/docker/CVE-2016-5195/auto-run-20260310/`, `artifacts/repro/isula/CVE-2016-5195/` |
| CVE-2016-8655 | non-interactive safe AF_PACKET probe; unprivileged run lacked `CAP_NET_RAW` (`BLOCKED_STAGE=cap_net_raw_unavailable`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=cap_net_raw_unavailable`) | `artifacts/repro/docker/CVE-2016-8655/auto-run-20260310/`, `artifacts/repro/isula/CVE-2016-8655/` |
| CVE-2016-9962 | non-interactive `release_agent` probe finished; host marker absent (`BLOCKED_STAGE=no_host_marker`) | privileged run reached cgroup mount, but writing `release_agent` was denied; no host marker | `artifacts/repro/docker/CVE-2016-9962/`, `artifacts/repro/isula/CVE-2016-9962/` |
| CVE-2017-1000112 | non-interactive containerized PoC run; entered KASLR phase but aborted on SMAP (`BLOCKED_STAGE=smap_mitigation_detected`) | iSulad-mapped `run/cp/exec` chain completed; blocked at same mitigation (`BLOCKED_STAGE=smap_mitigation_detected`) | `artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/`, `artifacts/repro/isula/CVE-2017-1000112/` |
| CVE-2017-16995 | non-interactive safe eBPF probe; `BPF_MAP_CREATE` reachable but no exploit chain (`BLOCKED_STAGE=trigger_only_no_priv_esc_chain`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=trigger_only_no_priv_esc_chain`) | `artifacts/repro/docker/CVE-2017-16995/auto-run-20260310/`, `artifacts/repro/isula/CVE-2017-16995/` |
| CVE-2017-6074 | non-interactive safe DCCP probe; DCCP unavailable (`BLOCKED_STAGE=dccp_module_unavailable`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=dccp_module_unavailable`) | `artifacts/repro/docker/CVE-2017-6074/auto-run-20260310/`, `artifacts/repro/isula/CVE-2017-6074/` |
| CVE-2017-7308 | rebuilt script/image to remove apt dependency; final `BLOCKED_STAGE=no_success_marker` | privileged probe reached early exploit stages but no `got r00t` marker | `artifacts/repro/docker/CVE-2017-7308/`, `artifacts/repro/isula/CVE-2017-7308/` |
| CVE-2018-18955 | namespace PoC produced root markers in logs (`pass`) | sync rerun under isula profile also produced root markers (`pass`) | `artifacts/repro/docker/CVE-2018-18955/`, `artifacts/repro/isula/CVE-2018-18955/` |
| CVE-2020-14386 | non-interactive safe AF_PACKET vnet probe; unprivileged run lacked `CAP_NET_RAW` (`BLOCKED_STAGE=cap_net_raw_unavailable`) | sync rerun under isula profile reached same blocked stage (`BLOCKED_STAGE=cap_net_raw_unavailable`) | `artifacts/repro/docker/CVE-2020-14386/auto-run-20260310/`, `artifacts/repro/isula/CVE-2020-14386/` |
| CVE-2021-30465 | race probe aligned to `renameat2` exchange model: on `runc 1.0.0-rc94` hit `VULNERABLE_OR_PARTIALLY_VULNERABLE`; on `runc 1.1.8` blocked (`BLOCKED_STAGE=mount_path_or_permission_validation`) | synchronized rerun under iSula with Docker20 + `runc 1.0.0-rc94` also hit host-root-like entries (`victim_2`, `VULNERABLE_OR_PARTIALLY_VULNERABLE`) | `artifacts/repro/docker/CVE-2021-30465/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310-attempt2-race-create/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.1.8-20260310-attempt2-race-create/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/`, `artifacts/repro/docker/CVE-2021-30465/docker20-runc1.0.0-rc94-rerun/`, `artifacts/repro/isula/CVE-2021-30465/`, `artifacts/repro/isula/CVE-2021-30465/docker20-runc1.0.0-rc94-rerun/` |
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
- K8s 场景脚本已增加 `kubectl exec` 失败回退：当命中 `k8s_exec_cgroup_path_missing` 时自动读取启动日志中的 `K8S_LOG_PROBE_OK` 标记并返回 `PROBE_LOG_FALLBACK_OK`。
- 回退镜像验证：`kindest/node:v1.30.0` 与 `v1.27.13` 在当前主机上都可复现同一 exec/cgroup 报错（见 `artifacts/repro/docker/k8s-version-matrix/*.log`）。
- Docker 20.10 复测（`2026-03-10`）：
  - 首轮严格模式（禁用日志回退）与默认模式均直接命中 `PROBE_EXECUTED`（`docker20-v1.30.0.log`）。
  - 9 个 K8s 场景批跑均 `PROBE_EXECUTED` 且 `exit_code=0`（`docker20-batch-v1.30.0.log`）。
  - 后续重复 `kind-up` 出现 `kubelet is not healthy` / `context deadline exceeded`（`docker20-retry-kindup-full.log`），需作为“可用但不稳定”状态记录。
- Docker 漏洞窗口补测（`2026-03-10`）：
  - `CVE-2019-14271` 按公开受影响窗口切到 Docker `19.03.0`（Go `1.12.5` build）后仍未出现 `/host_fs`（`docker-19.03.0-20260310-attempt1/run.log`）。
  - `CVE-2024-21626` 在 Docker `20.10.24` + `runc 1.1.5` 命中 Attack-1 host marker（`fd=9`），同机 iSulad 同步验证命中 `fd=8`。
  - `CVE-2021-30465` 在 Docker `20.10.24` + `runc 1.0.0-rc94` 命中后，iSulad 同步竞态复测也命中 host-root-like listing（`victim_2`）。
  - `CVE-2019-5736` 在 iSulad + `runc 1.0.0-rc5` 复测时，容器创建阶段被 runtime 兼容性阻断（`namespace {"cgroup" ""} does not exist`）。
  - `CVE-2024-21626` 脚本判定已从“输出完全相等”调整为“输出包含 token”，避免 `getcwd` 噪声导致的假阴性。
- `scripts/runtime_version_switch.sh` verified switch/restore flows:
  - switched to `runc 1.0.0-rc94` for CVE-2021-30465 vulnerable-path validation.
  - switched to `runc 1.0.0-rc5` for CVE-2019-5736 and CVE-2021-30465 comparative reruns.
  - switched to `runc 1.1.7` for CVE-2024-21626 direct-runc probe (`fd=7` hit).
  - restored to `runc 1.1.8` and confirmed negative controls.
  - switched back to `runc 1.1.5` to keep Docker20/iSulad dual-runtime baseline available for follow-up reruns.
  - extended with Docker static-binary quick-switch path (`docker-prefetch/docker-use-local/docker-restore`) for fast same-tool multi-version toggling.
