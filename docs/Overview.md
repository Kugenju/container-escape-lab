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
2. Docker 执行 `cves/*/run_poc.sh`脚本，并通过`collect_escape_evidence.sh`收集 `run.log`/`journal`/`kernel` 证据。
3. 版本敏感 CVE 对照：切换到明确脆弱版本重跑，再恢复默认版本做负对照。
4. iSulad 复测：切换到iSulad环境下重新运行 `cves/CVE-*/run_poc.sh` 脚本，并做同步记录，观察结果并于Docker运行结果对照。
5. 结论更新：将获取到的日志放置于 `artifacts/repro/*` 对应文件夹下，更新本文档于对应的CVE文件夹下的 `README.md`。

## 4. 当前进度总览

- Docker：收集的poc脚本已全部进行测试，成功逃逸案例与阻断案例均已总结于本文档，并对其逃逸机理进行大致分类。
- iSulad：CVE 脚本目已全部完成同步验证记录见对应章节表格。
- K8s（Docker 18.09 基线）：`kubectl exec` 阻断，已通过日志探针回退补齐 9 个场景证据并跑通（exit=0）。
- K8s（Docker 20.10.24 复测）：首轮严格模式可直接 `PROBE_EXECUTED`，9 场景批跑全部 `PROBE_EXECUTED` + `exit=0`；但后续重复 `kind-up` 仍出现 kubelet 健康检查超时。

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

## 5. Docker 复现结果

### 5.1 已复现成功

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

### 5.2 阻断

| CVE | 结果 | 阻断原因类型 |
| --- | --- | --- |
| CVE-2019-13139 | `BLOCKED_STAGE=parse_remote_refspec` | 输入构造/PoC 入口不兼容 |
| CVE-2019-14271 | `BLOCKED_STAGE=post_trigger_no_escape_artifact`（`18.09.0` 与 `19.03.0` 补测一致） | 利用链未形成宿主证据 |
| CVE-2016-9962 | `BLOCKED_STAGE=no_host_marker` | 利用链未形成宿主证据 |
| CVE-2017-7308 | `BLOCKED_STAGE=no_success_marker` | 利用链未形成成功标记 |
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

## 6. iSulad 复现结果

| CVE | 结果 | 阻断原因类型 |
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
| Docker 20.10.24 首轮复测（9 场景批跑） | 9 场景均 `PROBE_EXECUTED`，`exit_code=0` | 成功完成复现 |
| Docker 20.10.24 重复 `kind-up` | 可出现 `kubelet is not healthy` / `context deadline exceeded` | 稳定性未完全收敛 |

### 7.2 K8s 复现结果

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

## 9. 关键文档与证据入口

- 全局状态：`artifacts/repro/STATUS.md`
- Docker 批量：`artifacts/repro/docker/REMAINING_SUMMARY.md`
- iSulad 批量：`artifacts/repro/isula/REMAINING_SUMMARY.md`
- 执行手册：`docs/REPRO_SKILL_PLAYBOOK.md`
- 环境切换：`scripts/env_labctl.sh`
- runtime 切换：`scripts/runtime_version_switch.sh`


