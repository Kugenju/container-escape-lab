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
| CVE-2019-5736 | `BLOCKED_STAGE=runc_exe_handle_not_observed`（`runc 1.0.0-rc5` 最新复测） |
| CVE-2024-21626 | `BLOCKED_STAGE=workdir_fd_path_validation` |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker` |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` |
| CVE-2021-30465 | `BLOCKED_STAGE=runtime_version_not_vulnerable_range` |
| CVE-2022-0995 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered` |
| CVE-2017-1000112 | `BLOCKED_STAGE=smap_mitigation_detected` |
| CVE-2016-5195 | `BLOCKED_STAGE=kernel_not_vulnerable_or_patched` |
| CVE-2016-8655 | `BLOCKED_STAGE=cap_net_raw_unavailable` |
| CVE-2017-16995 | `BLOCKED_STAGE=trigger_only_no_priv_esc_chain` |
| CVE-2017-6074 | `BLOCKED_STAGE=dccp_module_unavailable` |
| CVE-2020-14386 | `BLOCKED_STAGE=cap_net_raw_unavailable` |
| kata-escape-2020 | `BLOCKED_STAGE=kata_runtime_not_installed` |

### 2.2 有成功标记（脚本层面）

| CVE | 结果 |
| --- | --- |
| CVE-2018-18955 | `pass`（脚本报告 success marker） |
| CVE-2021-3493 | `pass`（脚本报告 success marker） |
| CVE-2022-0847 | `pass`（脚本报告 success marker） |
| CVE-2024-21626（`run_poc_runc_direct.sh`） | `pass`（在切换 `runc 1.1.7` 后命中 `fd=7`） |




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
2. 2026-03-10 已完成剩余 placeholder（`CVE-2016-8655 / CVE-2017-16995 / CVE-2017-6074 / CVE-2020-14386 / kata-escape-2020`）自动化补齐。  
3. 目前最大未闭环项是 K8s 场景（不是脚本缺失，而是集群可达性未满足）。  
4. 新会话复用时，优先用 `docs/REPRO_SKILL_PLAYBOOK.md` 作为执行手册。  

## 7. 2026-03-10 增量进展

### 7.1 Docker/runc 版本可复现性核查

| CVE | 上游受影响范围（简写） | 2026-03-09 环境匹配性（Docker 18.09.0 / runc 1.1.8） | 2026-03-10 动作 |
| --- | --- | --- | --- |
| CVE-2019-13139 | Docker `< 18.09.4` | 匹配（潜在可复现） | 保持原结论 |
| CVE-2019-14271 | Docker `19.03.x < 19.03.1` | 不匹配（18.09.x 不在该范围） | 结论补充为“版本路径不匹配” |
| CVE-2019-5736 | runc `< 1.0.0-rc6` | 不匹配 | 已切到 `runc 1.0.0-rc5` 并重跑 |
| CVE-2016-9962 | runc `< 1.0.0-rc2` | 不匹配 | 结论补充为“当前 runc 不在脆弱范围” |
| CVE-2021-30465 | runc `<= 1.0.0-rc94` | 不匹配 | 已切到 `runc 1.0.0-rc94` 并重跑 |
| CVE-2024-21626 | runc `< 1.1.12` | 匹配（1.1.8） | 新增 direct-runc 链路：1.1.8 阻断、1.1.7 命中 |

### 7.2 版本切换重跑结果

- 新增 `scripts/runtime_version_switch.sh`（`status/use/restore`）用于 runc 版本切换验证。  
- `CVE-2021-30465` 在 `runc 1.0.0-rc94` 下复测：`BLOCKED_STAGE=race_not_hit_or_env_incompatible`。  
  证据：`artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310/`
- `CVE-2019-5736` 在 `runc 1.0.0-rc5` 下复测：触发链路进入 re-exec 阶段，但未生成宿主机 proof（`BLOCKED_STAGE=post_trigger_no_host_proof`）。  
  证据：`artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`
- `CVE-2019-5736` 按网络 PoC 细节继续增强并复测（`attempt3/4`）：  
  - `attempt3`：新增“等待 exploit 退出 + post-trigger”后，阻断收敛为 `BLOCKED_STAGE=trap_container_wait_timeout`。  
  - `attempt4`：新增 runc pid 重新探测后，阻断收敛为 `BLOCKED_STAGE=post_trigger_no_host_proof`（可见多次 pid 切换但仍无稳定句柄）。  
  证据：`artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt3/`、`artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt4/`
- `CVE-2019-5736` 继续对齐网络 PoC（即时句柄获取 + `/bin/bash` 触发，`attempt5/6`）：  
  - `attempt5`：`BLOCKED_STAGE=runc_exe_handle_not_observed`  
  - `attempt6-bash-trigger`：`BLOCKED_STAGE=runc_exe_handle_not_observed`  
  证据：`artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt5/`、`artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt6-bash-trigger/`
- `CVE-2021-30465` 在 `runc 1.0.0-rc5` 下复测：`BLOCKED_STAGE=race_not_hit_or_env_incompatible`。  
  证据：`artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/`
- `CVE-2024-21626` 新增 `runc-direct` 复现链路：  
  - `runc 1.1.8`：`BLOCKED_STAGE=direct_runc_fd_probe_no_hit`  
    证据：`artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/`
  - 切换 `runc 1.1.7`：命中 `fd=7`，`VULNERABLE_OR_PARTIALLY_VULNERABLE`  
    证据：`artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/`

### 7.3 缺少可落地 PoC 的补齐进展

- `CVE-2022-0995` 已从“仅编译 + 手工提示”改为“自动编译 + 非交互执行 + 阶段化结论 + 内核日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`。  
  证据：`artifacts/repro/docker/CVE-2022-0995/auto-run-20260310/`
- `CVE-2017-1000112` 已从“仅输出手工步骤”改为“自动编译 + 特权容器触发 + 阶段化结论 + Docker 日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=smap_mitigation_detected`。  
  证据：`artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/`
- `CVE-2016-5195` 已从“仅版本提示脚手架”改为“安全化 Dirty-COW 自动探测（临时只读文件）+ 非交互执行 + 阶段化结论 + 内核日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=kernel_not_vulnerable_or_patched`。  
  证据：`artifacts/repro/docker/CVE-2016-5195/auto-run-20260310/`
- `CVE-2016-8655` 已从“仅版本提示脚手架”改为“安全化 AF_PACKET 探测 + 非交互执行 + 阶段化结论 + 内核日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=cap_net_raw_unavailable`。  
  证据：`artifacts/repro/docker/CVE-2016-8655/auto-run-20260310/`
- `CVE-2017-16995` 已从“仅版本提示脚手架”改为“安全化 eBPF 探测 + 非交互执行 + 阶段化结论 + 内核日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=trigger_only_no_priv_esc_chain`。  
  证据：`artifacts/repro/docker/CVE-2017-16995/auto-run-20260310/`
- `CVE-2017-6074` 已从“仅版本提示脚手架”改为“安全化 DCCP 探测 + 非交互执行 + 阶段化结论 + 内核日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=dccp_module_unavailable`。  
  证据：`artifacts/repro/docker/CVE-2017-6074/auto-run-20260310/`
- `CVE-2020-14386` 已从“仅版本提示脚手架”改为“安全化 AF_PACKET vnet 探测 + 非交互执行 + 阶段化结论 + 内核日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=cap_net_raw_unavailable`。  
  证据：`artifacts/repro/docker/CVE-2020-14386/auto-run-20260310/`
- `kata-escape-2020` 已从“手工提示脚手架”改为“kata-runtime 版本/环境自动探测 + 非交互执行 + 阶段化结论 + runtime 日志采集”。  
- 2026-03-10 实跑结果：`BLOCKED_STAGE=kata_runtime_not_installed`。  
  证据：`artifacts/repro/docker/kata-escape-2020/auto-run-20260310/`

### 7.4 版本信息来源（网络补充）

- CVE-2019-13139（Docker `<18.09.4`）：https://docs.docker.com/engine/release-notes/18.09/  
- CVE-2019-14271（Docker `19.03.x <19.03.1`）：https://nvd.nist.gov/vuln/detail/CVE-2019-14271  
- CVE-2019-5736（runc `<1.0.0-rc6`）：https://nvd.nist.gov/vuln/detail/CVE-2019-5736  
- CVE-2019-5736 复现实现参考（Frichetten）：https://raw.githubusercontent.com/Frichetten/CVE-2019-5736-PoC/master/main.go  
- CVE-2019-5736 复现实现参考（Twistlock exec/malicious image）：https://github.com/twistlock/RunC-CVE-2019-5736  
- CVE-2016-9962（runc `<1.0.0-rc2`）：https://nvd.nist.gov/vuln/detail/CVE-2016-9962  
- CVE-2021-30465（runc `<=1.0.0-rc94`）：https://github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r  
- CVE-2024-21626（runc `<1.1.12`）：https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv  
- CVE-2024-21626 复现实操参考（runc direct）：https://github.com/NitroCao/CVE-2024-21626 、https://nitroc.org/en/posts/cve-2024-21626-illustrated/  
- CVE-2016-5195（Linux kernel `2.x/3.x/4.x before 4.8.3`）：https://cveawg.mitre.org/api/cve/CVE-2016-5195  
- CVE-2016-5195 官方 PoC 索引与源码：https://dirtycow.ninja/ 、https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c  
- CVE-2016-8655（Linux kernel `through 4.8.12`）：https://cveawg.mitre.org/api/cve/CVE-2016-8655  
- CVE-2016-8655 PoC 参考（EDB-47170）：https://www.exploit-db.com/download/47170  
- CVE-2017-16995（Linux kernel `through 4.4`）：https://cveawg.mitre.org/api/cve/CVE-2017-16995  
- CVE-2017-16995 PoC 参考（EDB-44298）：https://www.exploit-db.com/download/44298  
- CVE-2017-6074（Linux kernel `through 4.9.11`）：https://cveawg.mitre.org/api/cve/CVE-2017-6074  
- CVE-2017-6074 触发 PoC（EDB-41457）：https://www.exploit-db.com/download/41457  
- CVE-2020-14386（Linux kernel `before 5.9-rc4`）：https://cveawg.mitre.org/api/cve/CVE-2020-14386  
- CVE-2020-14386 漏洞分析：https://unit42.paloaltonetworks.com/cve-2020-14386/  
- kata-escape-2020 相关 CVE：https://cveawg.mitre.org/api/cve/CVE-2020-2024 、https://cveawg.mitre.org/api/cve/CVE-2020-2026 、https://cveawg.mitre.org/api/cve/CVE-2020-28914  
