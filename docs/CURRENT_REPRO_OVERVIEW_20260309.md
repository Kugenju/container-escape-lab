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

### 2.2 有成功标记（脚本层面）

| CVE | 结果 |
| --- | --- |
| CVE-2018-18955 | `pass`（脚本报告 success marker） |
| CVE-2021-3493 | `pass`（脚本报告 success marker） |
| CVE-2022-0847 | `pass`（脚本报告 success marker） |

### 2.3 占位/手工引导型脚本（非完整自动PoC）

| CVE/场景 |
| --- |
| CVE-2016-5195 |
| CVE-2016-8655 |
| CVE-2017-1000112 |
| CVE-2017-16995 |
| CVE-2017-6074 |
| CVE-2020-14386 |
| CVE-2022-0995 |
| kata-escape-2020 |

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
