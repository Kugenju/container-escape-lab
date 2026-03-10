# Current CVE Repro Overview

## 1. 文档目的

本文件用于统一记录当前仓库的容器逃逸复现状态，已将不同批次（含 2026-03-09 与 2026-03-10）的结果整合为一套连续结论，避免“基线记录”和“增量记录”分裂。

## 2. 环境与执行基线

- Host OS: openEuler 24.03 (LTS-SP3)
- Kernel: `6.6.0-132.0.0.111.oe2403sp3.x86_64`
- Docker: `18.09.0` (`EulerVersion 18.09.0.346`)
- iSulad: `2.1.6`
- Default `runc`: `1.1.8`

补充说明：
- 对版本敏感 CVE，已通过 `scripts/runtime_version_switch.sh` 做“脆弱版本命中 + 默认版本负对照”验证。

## 3. 统一复现流程

1. 基线采集：`uname`、runtime 版本、`scripts/env_labctl.sh status`。
2. Docker 主线批跑：执行 `cves/*/run_poc.sh`，统一收集 `run.log`/`journal`/`kernel` 证据。
3. 版本敏感 CVE 对照：切换到明确脆弱版本重跑，再恢复默认版本做负对照。
4. iSulad 映射复测：对全部 `cves/CVE-*/run_poc.sh` 条目做同步触发并记录语义差异。
5. K8s 场景回归：`kubectl` 可达性前置检查，不可达时统一输出 `BLOCKED_STAGE=k8s_api_unreachable`。
6. 结论回填：同步更新 `artifacts/repro/*` 汇总与各 CVE `README`。

## 4. 当前进度总览

- Docker：主线脚本已覆盖，成功项与阻断项均已阶段化归因。
- iSulad：CVE 主线条目已全部完成同步验证（含本地探针类脚本）。
- K8s：场景脚本可执行，但当前受集群可达性阻断。

## 5. Docker 结果矩阵

### 5.1 已命中（含版本对照）

| CVE | 结果 |
| --- | --- |
| CVE-2018-18955 | `pass`（success marker） |
| CVE-2021-3493 | `pass`（success marker） |
| CVE-2022-0847 | `pass`（success marker） |
| CVE-2021-30465（`runc 1.0.0-rc94`） | `pass`（`VULNERABLE_OR_PARTIALLY_VULNERABLE`） |
| CVE-2024-21626（`runc 1.1.7` direct-runc） | `pass`（命中 `fd=7`） |
| CVE-2019-5736（`runc 1.0.0-rc5` high-trigger） | `pass`（落地宿主机 proof `/tmp/CVE-2019-5736-PWNED`） |

### 5.2 阻断（已形成可解释结论）

| CVE | 结果 |
| --- | --- |
| CVE-2019-13139 | `BLOCKED_STAGE=parse_remote_refspec` |
| CVE-2019-14271 | `BLOCKED_STAGE=post_trigger_no_escape_artifact` |
| CVE-2019-5736（`runc 1.1.8`） | `BLOCKED_STAGE=trap_reexec_loader_dependency`（修复版本负对照） |
| CVE-2024-21626（`runc 1.1.8` direct-runc） | `BLOCKED_STAGE=direct_runc_fd_probe_no_hit` |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker` |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` |
| CVE-2021-30465（`runc 1.1.8`） | `BLOCKED_STAGE=mount_path_or_permission_validation` |
| CVE-2022-0995 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered` |
| CVE-2017-1000112 | `BLOCKED_STAGE=smap_mitigation_detected` |
| CVE-2016-5195 | `BLOCKED_STAGE=kernel_not_vulnerable_or_patched` |
| CVE-2016-8655 | `BLOCKED_STAGE=cap_net_raw_unavailable` |
| CVE-2017-16995 | `BLOCKED_STAGE=trigger_only_no_priv_esc_chain` |
| CVE-2017-6074 | `BLOCKED_STAGE=dccp_module_unavailable` |
| CVE-2020-14386 | `BLOCKED_STAGE=cap_net_raw_unavailable` |
| kata-escape-2020 | `BLOCKED_STAGE=kata_runtime_not_installed` |

## 6. iSulad 结果矩阵

| CVE | 结果 |
| --- | --- |
| CVE-2016-5195 | `BLOCKED_STAGE=kernel_not_vulnerable_or_patched`（与 Docker 同步） |
| CVE-2016-8655 | `BLOCKED_STAGE=cap_net_raw_unavailable`（与 Docker 同步） |
| CVE-2017-1000112 | `BLOCKED_STAGE=smap_mitigation_detected`（isula `run/cp/exec` 等价链路） |
| CVE-2017-16995 | `BLOCKED_STAGE=trigger_only_no_priv_esc_chain`（与 Docker 同步） |
| CVE-2017-6074 | `BLOCKED_STAGE=dccp_module_unavailable`（与 Docker 同步） |
| CVE-2018-18955 | `pass`（root marker） |
| CVE-2019-13139 | 输入构造阶段即被阻断（构建入口不匹配） |
| CVE-2019-14271 | 恶意 NSS 替换后未出现 `/host_fs` |
| CVE-2019-5736 | 未生成宿主机 proof，链路未闭环 |
| CVE-2020-14386 | `BLOCKED_STAGE=cap_net_raw_unavailable`（与 Docker 同步） |
| CVE-2024-21626 | `workdir/fd` 初始化阶段阻断 |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker`（`release_agent` 写入被拒） |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` |
| CVE-2021-30465 | `BLOCKED_STAGE=runtime_version_not_vulnerable_range_or_race_miss` |
| CVE-2021-3493 | `pass`（`uid=0/root` marker） |
| CVE-2022-0847 | `pass`（root-shell indicator） |
| CVE-2022-0995 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`（与 Docker 同步） |

## 7. K8s 场景结果

受影响脚本：`config-cap_*` 5 个 + `mount-*` 4 个（共 9 个）。

当前统一结论：
- `BLOCKED_STAGE=k8s_api_unreachable`
- 原因：`k8s-kind` 在该主机未稳定可用（镜像拉取不稳定 + Docker 18.09 与 kind 参数兼容限制）

## 8. 已合并的关键增量

### 8.1 版本对照复测

- 新增 `scripts/runtime_version_switch.sh`（`status/use/restore`）。
- `CVE-2021-30465`：`runc 1.0.0-rc94` 可命中，`1.1.8` 负对照阻断。
- `CVE-2019-5736`：`runc 1.0.0-rc5` 在 high-trigger 参数下命中宿主机 proof；默认 `1.1.8` 仍在 trap re-exec 依赖阶段阻断。
- `CVE-2024-21626`：direct-runc 链路下 `1.1.7` 可命中、`1.1.8` 阻断，形成清晰版本对照。

### 8.2 Placeholder 脚本补齐

以下条目已从“手工提示/脚手架”升级为“可批跑、非交互、可归因”：

- CVE-2022-0995
- CVE-2017-1000112
- CVE-2016-5195
- CVE-2016-8655
- CVE-2017-16995
- CVE-2017-6074
- CVE-2020-14386
- kata-escape-2020

## 9. 关键文档与证据入口

- 全局状态：`artifacts/repro/STATUS.md`
- Docker 批量：`artifacts/repro/docker/REMAINING_SUMMARY.md`
- iSulad 批量：`artifacts/repro/isula/REMAINING_SUMMARY.md`
- 执行手册：`docs/REPRO_SKILL_PLAYBOOK.md`
- 环境切换：`scripts/env_labctl.sh`
- runtime 切换：`scripts/runtime_version_switch.sh`

## 10. 当前未闭环项

1. K8s 场景依赖集群可达性，待 `k8s-kind` 稳定后统一复跑 9 个脚本。
2. CVE-2019-5736 的 iSulad 映射链路仍未形成宿主机 proof，后续可继续推进 build/exec 入口等价化验证。
