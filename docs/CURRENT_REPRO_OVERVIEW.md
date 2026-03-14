# Current CVE Repro Overview

## 1. 文档目的

本文件用于统一记录当前仓库的容器逃逸复现状态，梳理归纳逃逸触发机理，总结漏洞复现经验。

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
- 最新 CVE 补录：`CVE-2025-31133` 已完成 Docker+iSulad 同步复现并形成统一 README；`CVE-2025-52565` 在本地 registry 重放模板路径已 `PROBE_EXECUTED`；`CVE-2025-52881` 在镜像可达性补齐后阻断前移为 `dockerfile_add_from_not_supported`。
- 联网补录：`CVE-2025-23266` 已找到公开 PoC（`jpts/cve-2025-23266-poc`）并完成 Docker+iSulad 实测；Docker 侧已启用 `nvidia` runtime 并推进到 hook 执行阶段，但阻断于宿主缺失 `libnvidia-ml.so.1`，iSulad 侧仍不支持 `runtime nvidia`。

### 4.1 已验证逃逸方式分类

| 逃逸方式 | 案例 | 机理解析 |
| --- | --- | --- |
| Runtime 初始化竞态/路径穿透 | CVE-2021-30465、CVE-2024-21626、CVE-2025-31133 | 利用 `runc` 初始化窗口、`workdir/fd` 与路径解析竞态，将容器内路径操作导向宿主侧文件系统。 |
| Runtime 二进制覆盖/重执行劫持 | CVE-2019-5736 | 通过覆盖/劫持运行时重执行链路（`/proc/self/exe` 等），在运行时重入时执行攻击者代码。 |
| Cgroup/边界控制面写入链 | CVE-2016-9962 | 试图借助 cgroup 控制面（如 `release_agent`）写入宿主控制路径，形成容器到宿主的命令执行桥接。 |
| Build 输入解析与上下文供应链触发链 | CVE-2019-13139、CVE-2025-52565、CVE-2025-52881 | 利用构建入口解析（refspec/context）和 Buildx named-context/Dockerfile frontend 语义，将恶意上下文引入构建-运行链。 |
| 用户态库加载/配置注入链 | CVE-2019-14271 | 通过用户态库解析与加载路径（如 NSS）替换或注入，尝试把容器执行路径延伸到宿主可见目录。 |
| Runtime Hook 注入链 | CVE-2025-23266 | 借助容器运行时 hook（GPU toolkit/nvidia runtime）装载流程，在 hook 执行点触发越界执行。 |
| 内核提权型逃逸 | CVE-2016-5195、CVE-2016-8655、CVE-2017-6074、CVE-2017-7308、CVE-2017-1000112、CVE-2017-16995、CVE-2018-18955、CVE-2020-14386、CVE-2021-3493、CVE-2022-0847、CVE-2022-0995 | 在容器内触发内核漏洞原语（越界写、UAF、脏写、pipe/watch_queue 等），若条件满足则升级到宿主权限上下文。 |
| 沙箱运行时实现差异/组件缺失 | kata-escape-2020 | 依赖特定沙箱运行时（Kata）与组件栈；当运行时/组件缺失时在环境前置阶段被阻断。 |
| 容器能力配置误用 | `config-privileged-container`、`config-cap_dac_read_search-container`、`config-cap_sys_admin-container`、`config-cap_sys_module-container`、`config-cap_sys_ptrace-container` | 通过 `privileged` 或高危 capability 直接放大容器权限边界，形成对宿主资源的越权访问能力。 |
| 主机资源挂载暴露 | `mount-docker-sock`、`mount-host-etc`、`mount-host-procfs`、`mount-var-log` | 将宿主敏感资源直接映射进容器，绕过隔离边界并获得控制平面或敏感数据访问路径。 |
| K8s 工作负载面越权（组合场景） | `config-cap_dac_read_search-container`、`config-cap_sys_admin-container`、`config-cap_sys_module-container`、`config-cap_sys_ptrace-container`、`config-privileged-container`、`mount-docker-sock`、`mount-host-etc`、`mount-host-procfs`、`mount-var-log` | 在编排层把高危 capability、特权运行与主机挂载组合，放大单点配置风险并形成可批量复现的越权链。 |

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
| CVE-2025-52565（local-registry replay） | `pass`（`PROBE_EXECUTED`，named-context 模板链路可执行） |

### 5.2 阻断（已形成可解释结论）

| CVE | 结果 | 阻断原因类型 |
| --- | --- | --- |
| CVE-2019-13139 | `BLOCKED_STAGE=parse_remote_refspec` | 输入构造/PoC 入口不兼容 |
| CVE-2019-14271 | `BLOCKED_STAGE=post_trigger_no_escape_artifact`（`18.09.0` 与 `19.03.0` 补测一致） | 利用链未形成宿主证据 |
| CVE-2019-5736（`runc 1.1.8`） | `BLOCKED_STAGE=trap_reexec_loader_dependency`（修复版本负对照） | 版本窗口不匹配（修复版本） |
| CVE-2024-21626（`runc 1.1.8` direct-runc） | `BLOCKED_STAGE=direct_runc_fd_probe_no_hit` | 版本窗口不匹配（修复版本） |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker` | 利用链未形成宿主证据 |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` | 利用链未形成成功标记 |
| CVE-2021-30465（`runc 1.1.8`） | `BLOCKED_STAGE=mount_path_or_permission_validation` | 版本窗口不匹配/路径校验阻断 |
| CVE-2022-0995 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered` | 内核特性受限/过滤 |
| CVE-2025-52565（official remote template） | `BLOCKED_STAGE=exploit_context_image_unreachable`（local-registry replay 已 `PROBE_EXECUTED`） | 外部依赖不可达（远端恶意 context 镜像） |
| CVE-2025-52881 | `BLOCKED_STAGE=dockerfile_add_from_not_supported`（先前为 frontend 镜像不可达） | 工具链语义缺口（可用 frontend 不支持 `ADD --from`） |
| CVE-2025-23266 | `BLOCKED_STAGE=nvidia_driver_library_unavailable`（`nvidia` runtime 已启用，阻断于宿主缺失 `libnvidia-ml.so.1`） | 宿主依赖缺失（GPU 驱动 userspace） |
| CVE-2017-1000112 | `BLOCKED_STAGE=smap_mitigation_detected` | 内核缓解机制生效 |
| CVE-2016-5195 | `BLOCKED_STAGE=kernel_not_vulnerable_or_patched` | 内核已修复/不在漏洞窗口 |
| CVE-2016-8655 | `BLOCKED_STAGE=cap_net_raw_unavailable` | 权限能力缺失 |
| CVE-2017-16995 | `BLOCKED_STAGE=trigger_only_no_priv_esc_chain` | 仅触发原语，未形成提权链 |
| CVE-2017-6074 | `BLOCKED_STAGE=dccp_module_unavailable` | 内核模块/协议缺失 |
| CVE-2020-14386 | `BLOCKED_STAGE=cap_net_raw_unavailable` | 权限能力缺失 |
| kata-escape-2020 | `BLOCKED_STAGE=kata_runtime_not_installed` | 运行时组件缺失 |

## 6. iSulad 结果矩阵

| CVE | 结果 | 阻断原因类型（阻断项） |
| --- | --- | --- |
| CVE-2016-5195 | `BLOCKED_STAGE=kernel_not_vulnerable_or_patched`（与 Docker 同步） | 内核已修复/不在漏洞窗口 |
| CVE-2016-8655 | `BLOCKED_STAGE=cap_net_raw_unavailable`（与 Docker 同步） | 权限能力缺失 |
| CVE-2017-1000112 | `BLOCKED_STAGE=smap_mitigation_detected`（isula `run/cp/exec` 等价链路） | 内核缓解机制生效 |
| CVE-2017-16995 | `BLOCKED_STAGE=trigger_only_no_priv_esc_chain`（与 Docker 同步） | 仅触发原语，未形成提权链 |
| CVE-2017-6074 | `BLOCKED_STAGE=dccp_module_unavailable`（与 Docker 同步） | 内核模块/协议缺失 |
| CVE-2018-18955 | `pass`（root marker） | - |
| CVE-2019-13139 | 输入构造阶段即被阻断（构建入口不匹配） | 输入构造/PoC 入口不兼容 |
| CVE-2019-14271 | 恶意 NSS 替换后未出现 `/host_fs` | 利用链未形成宿主证据 |
| CVE-2019-5736 | 未生成宿主机 proof；`runc 1.0.0-rc5` 在 iSulad 下额外命中 runtime 兼容性阻断（cgroup namespace） | runtime 兼容性限制 |
| CVE-2020-14386 | `BLOCKED_STAGE=cap_net_raw_unavailable`（与 Docker 同步） | 权限能力缺失 |
| CVE-2024-21626 | `pass`（同步 `workdir/fd` 探针命中 `fd=8`） | - |
| CVE-2025-31133 | `pass`（iSulad profile 下 attempt2 命中 host `core_pattern` token） | - |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker`（`release_agent` 写入被拒） | 利用链未形成宿主证据 |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` | 利用链未形成成功标记 |
| CVE-2021-30465 | `pass`（Docker20 + `runc 1.0.0-rc94` 同步复测命中 host-root-like listing） | - |
| CVE-2021-3493 | `pass`（`uid=0/root` marker） | - |
| CVE-2022-0847 | `pass`（root-shell indicator） | - |
| CVE-2022-0995 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered`（与 Docker 同步） | 内核特性受限/过滤 |
| CVE-2025-52565 | `BLOCKED_STAGE=isula_buildx_named_context_unsupported`（iSulad 无 buildx/bake/named-context 等价入口） | 工具链能力缺失（无等价入口） |
| CVE-2025-52881 | `BLOCKED_STAGE=isula_buildx_named_context_unsupported`（iSulad 无 buildx/bake/named-context 等价入口） | 工具链能力缺失（无等价入口） |
| CVE-2025-23266 | `BLOCKED_STAGE=isula_nvidia_runtime_unavailable`（补装 toolkit 后仍为 `runtime nvidia is not supported`） | runtime 组件缺失/不支持 |

## 7. K8s 场景结果

受影响脚本：`config-cap_*` 5 个 + `mount-*` 4 个（共 9 个）。

### 7.1 K8s 总体结果矩阵

| 维度 | 结果 | 结论 |
| --- | --- | --- |
| Docker 18.09 基线（9 场景批跑） | `kubectl exec` 阶段命中 `k8s_exec_cgroup_path_missing`；日志探针回退后统一 `PROBE_LOG_FALLBACK_OK`，`exit_code=0` | 可形成“可检测”证据链，但不是直接 exec 命中 |
| Docker 20.10.24 首轮复测（9 场景批跑） | 9 场景均 `PROBE_EXECUTED`，`exit_code=0` | 能力恢复，pass 数量提升 |
| Docker 20.10.24 重复 `kind-up` | 可出现 `kubelet is not healthy` / `context deadline exceeded` | 稳定性未完全收敛 |
| K8s 版本对照（`v1.30.0` vs `v1.27.13`） | 两个版本都可出现相同 exec/cgroup 报错 | 单纯回退 K8s 小版本不足以根治 |

### 7.2 9 个 K8s 场景批跑明细（表格化）

| 场景脚本 | Docker 18.09 基线 | Docker 20.10.24 首轮 | 当前判定 |
| --- | --- | --- | --- |
| `config-cap_dac_read_search-container/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `config-cap_sys_admin-container/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `config-cap_sys_module-container/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `config-cap_sys_ptrace-container/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `config-privileged-container/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `mount-docker-sock/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `mount-host-etc/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `mount-host-procfs/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |
| `mount-var-log/run_poc.sh` | `PROBE_LOG_FALLBACK_OK` | `PROBE_EXECUTED` | 已覆盖 |

### 7.3 K8s 证据索引

| 证据 | 路径 |
| --- | --- |
| Docker 20.10 单场景验证 | `artifacts/repro/docker/k8s-version-matrix/docker20-v1.30.0.log` |
| Docker 20.10 9 场景批跑 | `artifacts/repro/docker/k8s-version-matrix/docker20-batch-v1.30.0.log` |
| Docker 20.10 重复建群异常 | `artifacts/repro/docker/k8s-version-matrix/docker20-retry-kindup-full.log` |
| 版本对照（`v1.30.0`） | `artifacts/repro/docker/k8s-version-matrix/v1.30.0-preload.log` |
| 版本对照（`v1.27.13`） | `artifacts/repro/docker/k8s-version-matrix/v1.27.13-preload.log` |

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
- 联网补录 Buildx 官方 GHSA 模板后，`CVE-2025-52565`（procfs 模板）与 `CVE-2025-52881`（sysfs 模板）均已形成可执行脚本与证据目录；`CVE-2025-52565` 在本地 registry 重放路径可 `PROBE_EXECUTED`。
- `CVE-2025-23266`：已引入公开 PoC 并完成补测；Docker 在 `nvidia` runtime 可用后进入 hook 阶段，但因宿主缺失 `libnvidia-ml.so.1` 阻断，iSulad 仍阻断于 `runtime nvidia` 不支持。
- Buildx 执行环境补齐：已本地安装 `buildx v0.31.0`，并切换 `docker-container` builder（buildkit `v0.27.1`）以满足 official template 的 `frontend.contexts` 依赖。
- Buildx 镜像源与本地重放补测：`CVE-2025-52881` 在 frontend 镜像可达后仍阻断于 `dockerfile_add_from_not_supported`，说明当前可用 frontend 语义与官方 `docker/dockerfile:1.20.0-rc.1` 模板存在能力差异。

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
