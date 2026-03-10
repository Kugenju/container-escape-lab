# Current CVE Repro Overview

## 1. 文档目的

本文件用于统一记录当前仓库的容器逃逸复现状态，已将不同批次（含 2026-03-09 与 2026-03-10）的结果整合为一套连续结论，避免“基线记录”和“增量记录”分裂。

## 2. 环境与执行基线

- Host OS: openEuler 24.03 (LTS-SP3)
- Kernel: `6.6.0-132.0.0.111.oe2403sp3.x86_64`
- Docker (historical baseline): `18.09.0` (`EulerVersion 18.09.0.346`)
- Docker (latest K8s validation): `20.10.24`
- containerd (latest K8s validation): `1.6.20`
- runc (latest K8s validation): `1.1.5`
- iSulad: `2.1.6`
- Active `runc` (current Docker20 stack): `1.1.5`
- Historical default/negative-control `runc`: `1.1.8`

补充说明：
- 对版本敏感 CVE，已通过 `scripts/runtime_version_switch.sh` 做“脆弱版本命中 + 默认版本负对照”验证。

## 3. 统一复现流程

1. 基线采集：`uname`、runtime 版本、`scripts/env_labctl.sh status`。
2. Docker 主线批跑：执行 `cves/*/run_poc.sh`，统一收集 `run.log`/`journal`/`kernel` 证据。
3. 版本敏感 CVE 对照：切换到明确脆弱版本重跑，再恢复默认版本做负对照。
4. iSulad 映射复测：对全部 `cves/CVE-*/run_poc.sh` 条目做同步触发并记录语义差异。
5. K8s 场景回归：`kubectl` 可达性前置检查；不可达时输出 `BLOCKED_STAGE=k8s_api_unreachable`；若 `kubectl exec` 命中 cgroup 路径错误则自动回退到启动日志探针并给出 `PROBE_LOG_FALLBACK_OK`。
6. 结论回填：同步更新 `artifacts/repro/*` 汇总与各 CVE `README`。

## 4. 当前进度总览

- Docker：主线脚本已覆盖，成功项与阻断项均已阶段化归因。
- iSulad：CVE 主线条目已全部完成同步验证（含本地探针类脚本）。
- K8s（Docker 18.09 基线）：`kubectl exec` 阻断，已通过日志探针回退补齐 9 个场景证据并跑通（exit=0）。
- K8s（Docker 20.10.24 复测）：首轮严格模式可直接 `PROBE_EXECUTED`，9 场景批跑全部 `PROBE_EXECUTED` + `exit=0`；但后续重复 `kind-up` 仍出现 kubelet 健康检查超时。
- 最新 CVE 补录：`CVE-2025-31133` 已完成 Docker+iSulad 同步复现并形成统一 README；`CVE-2025-52881` 与 `CVE-2025-52565` 尚未检索到可直接复用的公开 runnable PoC。

## 5. Docker 结果矩阵

### 5.1 已命中（含版本对照）

| CVE | 结果 |
| --- | --- |
| CVE-2018-18955 | `pass`（success marker） |
| CVE-2021-3493 | `pass`（success marker） |
| CVE-2022-0847 | `pass`（success marker） |
| CVE-2021-30465（`runc 1.0.0-rc94`） | `pass`（`VULNERABLE_OR_PARTIALLY_VULNERABLE`） |
| CVE-2024-21626（Docker `20.10.24` + `runc 1.1.5`，Attack-1） | `pass`（host marker 命中 `fd=9`） |
| CVE-2025-31133（Docker `20.10.24` + `runc 1.1.5`） | `pass`（host `core_pattern` token 命中） |
| CVE-2024-21626（`runc 1.1.7` direct-runc） | `pass`（命中 `fd=7`） |
| CVE-2019-5736（`runc 1.0.0-rc5` high-trigger） | `pass`（落地宿主机 proof `/tmp/CVE-2019-5736-PWNED`） |

### 5.2 阻断（已形成可解释结论）

| CVE | 结果 |
| --- | --- |
| CVE-2019-13139 | `BLOCKED_STAGE=parse_remote_refspec` |
| CVE-2019-14271 | `BLOCKED_STAGE=post_trigger_no_escape_artifact`（`18.09.0` 与 `19.03.0` 补测一致） |
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
| CVE-2019-5736 | 未生成宿主机 proof；`runc 1.0.0-rc5` 在 iSulad 下额外命中 runtime 兼容性阻断（cgroup namespace） |
| CVE-2020-14386 | `BLOCKED_STAGE=cap_net_raw_unavailable`（与 Docker 同步） |
| CVE-2024-21626 | `pass`（同步 `workdir/fd` 探针命中 `fd=8`） |
| CVE-2025-31133 | `pass`（iSulad profile 下 attempt2 命中 host `core_pattern` token） |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker`（`release_agent` 写入被拒） |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` |
| CVE-2021-30465 | `pass`（Docker20 + `runc 1.0.0-rc94` 同步复测命中 host-root-like listing） |
| CVE-2021-3493 | `pass`（`uid=0/root` marker） |
| CVE-2022-0847 | `pass`（root-shell indicator） |
| CVE-2022-0995 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`（与 Docker 同步） |

## 7. K8s 场景结果

受影响脚本：`config-cap_*` 5 个 + `mount-*` 4 个（共 9 个）。

当前统一结论：
- `kubectl exec` 路径仍触发 `BLOCKED_STAGE=k8s_exec_cgroup_path_missing`。
- 场景脚本已启用回退：自动读取 Pod 启动日志中的 `K8S_LOG_PROBE_OK`，输出 `PROBE_LOG_FALLBACK_OK` 并返回 0。
- `v1.30.0` 与 `v1.27.13` 对照均复现相同 exec/cgroup 报错，说明单纯回退 K8s 小版本不足以根治当前主机环境问题。
- Docker 20.10.24 首轮复测中，`kubectl exec` 已直接恢复 `PROBE_EXECUTED`（无需回退）；但同机后续重复 `kind-up` 仍可出现 kubelet 不健康超时，稳定性待继续收敛。

环境补充：
- `scripts/env_labctl.sh profile k8s-kind` 已加入 Docker 18.09 兼容回退，可稳定拉起 kind 集群（自动移除 `--cgroupns=*` 参数）。
- K8s 版本对照与批跑证据：`artifacts/repro/docker/k8s-version-matrix/`。
- Docker 20.10 复测证据：
  - `artifacts/repro/docker/k8s-version-matrix/docker20-v1.30.0.log`
  - `artifacts/repro/docker/k8s-version-matrix/docker20-batch-v1.30.0.log`
  - `artifacts/repro/docker/k8s-version-matrix/docker20-retry-kindup-full.log`

## 8. 已合并的关键增量

### 8.1 版本对照复测

- 新增 `scripts/runtime_version_switch.sh`（`runc`: `status/use/restore`，`docker`: `docker-prefetch/docker-use-local/docker-restore`）。
- `CVE-2021-30465`：`runc 1.0.0-rc94` 可命中，`1.1.8` 负对照阻断。
- `CVE-2021-30465`：iSulad 同步竞态复测在 Docker20 + `runc 1.0.0-rc94` 也命中 `VULNERABLE_OR_PARTIALLY_VULNERABLE`（`victim_2`）。
- `CVE-2019-5736`：`runc 1.0.0-rc5` 在 high-trigger 参数下命中宿主机 proof；默认 `1.1.8` 仍在 trap re-exec 依赖阶段阻断。
- `CVE-2019-5736`：iSulad + `runc 1.0.0-rc5` 补测无法进入利用链，容器创建阶段报 `namespace {"cgroup" ""} does not exist`。
- `CVE-2024-21626`：direct-runc 链路下 `1.1.7` 可命中、`1.1.8` 阻断，形成清晰版本对照。
- `CVE-2024-21626`：Docker `20.10.24` + `runc 1.1.5` 攻击链复测中，Attack-1 命中 host marker（`fd=9`）；iSulad 同步探针命中 `fd=8`。
- `CVE-2024-21626`：探针脚本改为“输出包含 token 即命中”，消除 `getcwd` 警告噪声导致的误判。
- `CVE-2019-14271`：依据公开受影响区间补测 Docker `19.03.0` 后，仍为 `post_trigger_no_escape_artifact`（未观察到 `/host_fs`）。
- `CVE-2025-31133`：在 `runc 1.1.5` 下复现 symlink-race，Docker 与 iSulad profile 均命中 host `core_pattern` token。
- `scripts/runtime_version_switch.sh`：已从仅 `runc` 切换扩展到 `runc + docker` 双通道，支持 `docker-prefetch/docker-use-local/docker-restore` 的同工具多版本快切。
- 联网检索 `2025-11-05` 同批 runc 高危公告（`CVE-2025-31133/52881/52565`）后，当前仅 `CVE-2025-31133` 检索到可直接复用的公开 runnable PoC；其余两项先记录为“待公开 PoC/需自行构造”。

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

1. K8s 场景批跑已通过日志回退闭环；Docker 20.10 首轮可直接 `PROBE_EXECUTED`，但重复 `kind-up` 仍有稳定性问题，后续重点是收敛 kubelet 超时根因（优先 cgroup v2 基线）。
2. CVE-2019-5736 的 iSulad 映射链路仍未形成宿主机 proof，后续可继续推进 build/exec 入口等价化验证。

## 11. K8s 最佳解路径（联网资料 + 本地验证）

1. 官方兼容性约束：kind `v0.20.0` 起明确要求 Docker `20.10+`（当前主机 Docker `18.09` 不满足）。  
   参考：https://github.com/kubernetes-sigs/kind/releases/tag/v0.20.0
2. 本地版本回退对照：`v1.30.0` 与 `v1.27.13` 均在 exec 阶段命中同一 cgroup 错误，未因回退小版本而消失。  
   证据：`artifacts/repro/docker/k8s-version-matrix/v1.30.0-preload.log`、`artifacts/repro/docker/k8s-version-matrix/v1.27.13-preload.log`
3. 官方 issue 趋势：同类错误在 cgroup v1 / hybrid 场景反复出现，维护者建议优先统一到 cgroup v2（unified）并避免旧宿主组合。  
   参考：https://github.com/kubernetes-sigs/kind/issues/3340  
   参考：https://github.com/kubernetes-sigs/kind/issues/3558  
   参考：https://github.com/kubernetes-sigs/kind/issues/3598  
   参考：https://github.com/kubernetes-sigs/kind/issues/3685
4. 本地 Docker 20.10 复测结论：  
   - 首轮验证中 `kubectl exec` 已恢复，9 个场景全部 `PROBE_EXECUTED`（通过数量提升）。  
   - 但重复建集群仍可能触发 `kubelet healthz timeout`，当前判定为“能力恢复但稳定性未完全收敛”。
