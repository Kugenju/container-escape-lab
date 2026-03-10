# Current CVE Repro Overview (2026-03-09)

## 1. 环境基线

- OS: openEuler 24.03 (LTS-SP3)
- Kernel: `6.6.0-132.0.0.111.oe2403sp3.x86_64`
- Docker: `18.09.0` (`EulerVersion 18.09.0.346`)
- iSulad: `2.1.6`
- runc: `1.1.8`

## 2. Docker 复现结果概览

### 2.1 明确阻断（已跑通脚本，未形成逃逸落地）

| CVE | 结果 |
| --- | --- |
| CVE-2019-13139 | `BLOCKED_STAGE=parse_remote_refspec` |
| CVE-2019-14271 | `BLOCKED_STAGE=post_trigger_no_escape_artifact` |
| CVE-2019-5736 | `BLOCKED_STAGE=trap_reexec_loader_dependency` |
| CVE-2024-21626 | `BLOCKED_STAGE=workdir_fd_path_validation` |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker` |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` |
| CVE-2021-30465 | `BLOCKED_STAGE=runtime_version_not_vulnerable_range` |
| CVE-2022-0995 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered` |
| CVE-2017-1000112 | `BLOCKED_STAGE=smap_mitigation_detected` |

### 2.2 有成功标记（脚本层面）

| CVE | 结果 |
| --- | --- |
| CVE-2018-18955 | `pass`（脚本报告 success marker） |
| CVE-2021-3493 | `pass`（脚本报告 success marker） |
| CVE-2022-0847 | `pass`（脚本报告 success marker） |




## 3. iSulad 复现结果概览

### 3.1 已完成映射验证

| CVE | 结果 |
| --- | --- |
| CVE-2019-13139 | 输入路径即被阻断（构建入口不匹配） |
| CVE-2019-14271 | 恶意 NSS 替换后未出现 `/host_fs` |
| CVE-2019-5736 | 未生成宿主机 proof，链路未闭环 |
| CVE-2024-21626 | `workdir/fd` 初始化阶段阻断 |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker`（`release_agent` 写入被拒） |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` |
| CVE-2021-30465 | `BLOCKED_STAGE=runtime_version_not_vulnerable_range_or_race_miss` |

## 4. K8s 场景结果概览

受影响脚本（9个）：

- `config-cap_*` 5 个脚本
- `mount-*` 4 个脚本

当前统一结果：

- `BLOCKED_STAGE=k8s_api_unreachable`
- 原因：`k8s-kind` 环境在该主机上仍未完成可用集群拉起（存在镜像拉取不稳定 + Docker 18.09 与 kind 参数兼容性限制）

## 5. 关键文件

- 全局状态：`artifacts/repro/STATUS.md`
- Docker 批量：`artifacts/repro/docker/REMAINING_SUMMARY_20260309.md`
- iSulad 批量：`artifacts/repro/isula/REMAINING_SUMMARY_20260309.md`
- 环境切换工具：`scripts/env_labctl.sh`

## 6. 本次结论

1. Docker / iSulad 主线 PoC 已基本覆盖，失败项都已转为“可解释的阶段化阻断”。  
2. 目前最大未闭环项是 K8s 场景（不是脚本缺失，而是集群可达性未满足）。  
3. 新会话复用时，优先用 `docs/REPRO_SKILL_PLAYBOOK.md` 作为执行手册。  

## 7. 2026-03-10 增量进展

### 7.1 Docker/runc 版本可复现性核查

| CVE | 上游受影响范围（简写） | 2026-03-09 环境匹配性（Docker 18.09.0 / runc 1.1.8） | 2026-03-10 动作 |
| --- | --- | --- | --- |
| CVE-2019-13139 | Docker `< 18.09.4` | 匹配（潜在可复现） | 保持原结论 |
| CVE-2019-14271 | Docker `19.03.x < 19.03.1` | 不匹配（18.09.x 不在该范围） | 结论补充为“版本路径不匹配” |
| CVE-2019-5736 | runc `< 1.0.0-rc6` | 不匹配 | 已切到 `runc 1.0.0-rc5` 并重跑 |
| CVE-2016-9962 | runc `< 1.0.0-rc2` | 不匹配 | 结论补充为“当前 runc 不在脆弱范围” |
| CVE-2021-30465 | runc `<= 1.0.0-rc94` | 不匹配 | 已切到 `runc 1.0.0-rc94` 并重跑 |
| CVE-2024-21626 | runc `< 1.1.12` | 匹配（1.1.8） | 保持原结论 |

### 7.2 版本切换重跑结果

- 新增 `scripts/runtime_version_switch.sh`（`status/use/restore`）用于 runc 版本切换验证。  
- `CVE-2021-30465` 在 `runc 1.0.0-rc94` 下复测：`BLOCKED_STAGE=race_not_hit_or_env_incompatible`。  
  证据：`artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310/`
- `CVE-2019-5736` 在 `runc 1.0.0-rc5` 下复测：触发链路进入 re-exec 阶段，但未生成宿主机 proof（`BLOCKED_STAGE=post_trigger_no_host_proof`）。  
  证据：`artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`
- `CVE-2021-30465` 在 `runc 1.0.0-rc5` 下复测：`BLOCKED_STAGE=race_not_hit_or_env_incompatible`。  
  证据：`artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/`

### 7.3 缺少可落地 PoC 的补齐进展

- `CVE-2022-0995` 已从“仅编译 + 手工提示”改为“自动编译 + 非交互执行 + 阶段化结论 + 内核日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`。  
  证据：`artifacts/repro/docker/CVE-2022-0995/auto-run-20260310/`
- `CVE-2017-1000112` 已从“仅输出手工步骤”改为“自动编译 + 特权容器触发 + 阶段化结论 + Docker 日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=smap_mitigation_detected`。  
  证据：`artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/`

### 7.4 版本信息来源（网络补充）

- CVE-2019-13139（Docker `<18.09.4`）：https://docs.docker.com/engine/release-notes/18.09/  
- CVE-2019-14271（Docker `19.03.x <19.03.1`）：https://nvd.nist.gov/vuln/detail/CVE-2019-14271  
- CVE-2019-5736（runc `<1.0.0-rc6`）：https://nvd.nist.gov/vuln/detail/CVE-2019-5736  
- CVE-2016-9962（runc `<1.0.0-rc2`）：https://nvd.nist.gov/vuln/detail/CVE-2016-9962  
- CVE-2021-30465（runc `<=1.0.0-rc94`）：https://github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r  
- CVE-2024-21626（runc `<1.1.12`）：https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv  
