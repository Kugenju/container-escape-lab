# Container Escape Repro Skill Playbook

## 1. 目标与适用范围

本手册用于在本实验机上重复执行 `cves/*/run_poc.sh`，并在遇到环境不匹配时快速切换运行时环境、修脚本、补证据。

适用对象：

- Docker 场景 PoC
- iSulad 场景 PoC
- Kubernetes 场景（`kubectl apply` 类型）

## 2. 核心原则

1. 先统一环境，再跑脚本。  
2. 每次失败都要输出明确阻断阶段（`BLOCKED_STAGE=...`）。  
3. 每次复跑都要落盘证据（run log + journal + kernel log）。  
4. 不依赖交互输入；脚本优先改成非交互可重复执行。  
5. 每个 CVE 在形成“初步结论”后，必须回填该 CVE `README`：补充更细机理分析 + 成功/阻断对照日志。  

## 3. 环境切换工具

使用脚本：`scripts/env_labctl.sh`、`scripts/runtime_version_switch.sh`

常用命令：

```bash
# 查看当前环境
scripts/env_labctl.sh status

# 切到 Docker
scripts/env_labctl.sh profile docker

# 切到 iSulad
scripts/env_labctl.sh profile isula

# 同时启 Docker + iSulad
scripts/env_labctl.sh profile dual

# 拉起 K8s(kind) 环境
scripts/env_labctl.sh profile k8s-kind

# 删除 kind 集群
scripts/env_labctl.sh kind-down

# 查看/切换/恢复 runc 版本
scripts/runtime_version_switch.sh status
scripts/runtime_version_switch.sh use 1.0.0-rc94
scripts/runtime_version_switch.sh restore
```

补充：

- 已支持自动安装 `kubectl` / `kind`。
- 已支持镜像互导：`scripts/env_labctl.sh sync-image <image> docker-to-isula`
- 已支持 `runc` 版本切换（含备份恢复）：`scripts/runtime_version_switch.sh`
- 对 Docker 18.09 等不支持 `--cgroupns` 的环境，`profile k8s-kind` 已内置兼容回退（kind create 自动移除该参数）。

## 4. 推荐执行流程（下次会话直接照做）

### Step A: 基线采集

```bash
uname -a
docker --version || true
isula version || true
runc --version || true
scripts/env_labctl.sh status
```

补充：先做“版本可复现性判定”，确认目标 CVE 所需 Docker/runc 版本范围；不在范围内先切版本再跑。

### Step B: Docker 复现批跑

1. 先跑目标 `run_poc.sh`。  
2. 输出写入 `artifacts/repro/docker/<CVE>/run.log`。  
3. 同步采集：
   - `docker_journal.log`
   - `kernel_journal.log`
   - `dmesg_tail.log`
   - `exit_code.txt`

### Step C: iSulad 复测

1. `scripts/env_labctl.sh profile isula`  
2. 对已完成 Docker 的 CVE 做等价触发（同目录单独 wrapper 或命令链）。
3. 即使 PoC 是 runtime 无关的“本地探针”，也要在 isula profile 下同步跑一轮，形成可对照证据。
4. 证据落盘到 `artifacts/repro/isula/<CVE>/`。

### Step D: K8s 场景

1. `scripts/env_labctl.sh profile k8s-kind`
2. 若 API 不可达，脚本应返回：
   - `BLOCKED_STAGE=k8s_api_unreachable`
3. 保证 `run.log` 内有可操作提示（如 `Hint: run scripts/env_labctl.sh profile k8s-kind`）。
4. 若 Pod 已 `Ready` 但 `kubectl exec` 报 `error adding pid ... cgroup.procs: no such file or directory`：
   - 先保留阻断证据：`BLOCKED_STAGE=k8s_exec_cgroup_path_missing`
   - 再自动回退到 `kubectl logs` 启动探针（`K8S_LOG_PROBE_OK`），命中时输出：
   - `PROBE_LOG_FALLBACK_OK`
5. 批跑 K8s 场景前优先执行 `kind load docker-image ubuntu:latest --name escape-lab`，避免把镜像仓库波动误判为漏洞链路阻断。

## 5. 常见失败类型与修复套路

### 5.1 交互阻塞

现象：`read -p` / 长等待导致批跑卡死。  
修复：改为非交互参数（默认不破坏宿主机），必要时加 `--cleanup`。

### 5.2 网络依赖导致构建失败

现象：`apt-get` / DockerHub 拉取失败。  
修复：

- 宿主机编译二进制，再 volume 挂载进容器。
- Dockerfile 尽量改为“仅 COPY + chmod”，避免在线包管理器。

### 5.3 脚本格式问题（CRLF）

现象：`$'\r': command not found`、返回码异常。  
修复：统一去 CRLF，再 `bash -n` 全量语法检查。

### 5.4 版本不匹配（漏洞已修）

现象：脚本全流程执行，但无成功 marker。  
修复：

- 在日志中显式版本判定（例如 runc 固定版本边界）。
- 给出阻断结论：`BLOCKED_STAGE=runtime_version_not_vulnerable_range`

### 5.5 K8s 环境不可达

现象：`kubectl` 脚本直接失败。  
修复：

- 场景脚本前置 `kubectl cluster-info` 检查。
- 返回 `BLOCKED_STAGE=k8s_api_unreachable`，不要仅“command not found”。

### 5.6 K8s 可达但 Exec 阶段失败

现象：Pod 已 `Ready`，但 `kubectl exec` 返回 OCI runtime cgroup 路径错误（`cgroup.procs: no such file or directory`）。  
修复：

- 保留 `kubectl wait` 与 `kubectl exec` 分段日志，确认阻断位置在 exec 而非调度阶段。
- 脚本统一先输出 `BLOCKED_STAGE=k8s_exec_cgroup_path_missing`，随后自动执行日志探针回退并尝试输出 `PROBE_LOG_FALLBACK_OK`。
- 若主机 Docker 版本较旧（如 18.09）导致 kind 参数不兼容，优先通过 `env_labctl` 的兼容回退拉起集群后再复测。
- 若需要根治而非回退探针，优先升级宿主到 cgroup v2（unified）并使用 Docker 20.10+；仅回退 K8s 小版本通常不足以消除该类问题。

### 5.7 版本切换下载不稳定

现象：`runc` 旧版本下载时出现 `connection reset/timeout`。  
修复：

- 优先复用 `/tmp/runtime-version-switch/<tag>/runc.amd64` 本地缓存。
- 使用代理回退链路（如 `gh-proxy.com`、`ghproxy.net`）重试下载。
- 在结论中明确记录阻断：`BLOCKED_STAGE=runtime_binary_fetch_unstable_network`。
- 先完成可执行的版本验证项（如已下载版本），再补跑缺失版本。

### 5.8 Placeholder PoC 补齐

现象：目录只有说明文档，`run_poc.sh` 仅提示手工步骤。  
修复：

- 用“安全化探测 PoC”替代高破坏 exploit（如只对临时只读文件做竞态写检测）。
- 统一改为非交互执行，并输出明确 `BLOCKED_STAGE`。
- 网络补齐至少两类来源：官方 CVE 记录（受影响版本）+ 官方/社区主仓 PoC 来源。
- 复跑后按规范补齐证据目录与汇总文档，确保 placeholder 退出批跑列表。

### 5.9 `su nobody` 执行返回 126

现象：`probe exit code=126`，日志无 PoC marker。  
修复：

- 不要直接执行位于 `/root/...` 的二进制（`nobody` 无法遍历该路径）。
- 先把编译产物复制到 `/tmp` 并 `chmod 0755`，再用 `su nobody` 执行。

### 5.10 CVE-2024-21626 的 `workdir/fd` 判定与对照

现象：`docker run -w /proc/self/fd/N` 输出中出现大量 `getcwd` 噪声，脚本若使用“完全相等”匹配可能误判未命中。  
修复：

- 命中判定统一用“输出包含 token”（`grep -Fq "$token"`），不要要求输出仅等于 token。
- 先跑 Docker Attack-1 扫描（`fd` 枚举），再补 Attack-2/exec 路径；两条链路分开记录。
- 同步保留 direct-runc 对照（如 `1.1.7` 命中、`1.1.8` 阻断），用于证明“版本窗口”而非脚本偶然命中。
- iSulad 侧等价复测优先使用 `--workdir /proc/self/fd/N`，不要强依赖 `apparmor=unconfined` 参数。

### 5.11 CVE-2019-5736 trap 链路提前清理/句柄竞争

现象：`docker exec` 已持续出现 `No help topic for '/bin/sh'` 或 `'/bin/bash'`，但无 host proof。  
修复：

- `run_poc.sh` 不要在 trigger 后立即清理，先 `docker wait` 并设置明确超时窗口。
- 若日志出现 overwrite marker 但尚未落地 proof，补做 post-trigger `docker run` 轮次验证“下一次 runc 调用”。
- 在 exploit 中把“发现 runc 进程”和“打开 `/proc/<pid>/exe`”尽量并行/紧邻执行，减少短生命周期进程窗口丢失。
- 若长期无法拿到稳定句柄，统一记录：`BLOCKED_STAGE=runc_exe_handle_not_observed`。

## 6. 阻断阶段命名建议

建议统一格式：`BLOCKED_STAGE=<snake_case>`

常见示例：

- `parse_remote_refspec`
- `workdir_fd_path_validation`
- `trap_reexec_loader_dependency`
- `runc_exe_handle_not_observed`
- `cgroup_v1_controller_unavailable`
- `runtime_version_not_vulnerable_range`
- `k8s_api_unreachable`
- `k8s_exec_cgroup_path_missing`
- `k8s_log_probe_missing`
- `runtime_binary_fetch_unstable_network`

## 7. 证据规范

每个场景目录建议固定包含：

- `run.log`
- `exit_code.txt`
- `start_time.txt`
- `<runtime>_journal.log`
- `kernel_journal.log`
- `dmesg_tail.log`（Docker侧常用）

统一汇总：

- `artifacts/repro/STATUS.md`
- `artifacts/repro/docker/REMAINING_SUMMARY.md`
- `artifacts/repro/isula/REMAINING_SUMMARY.md`

README 回填要求：

- 不再按日期堆叠“复现记录”小节，统一改为单一的 `统一复现记录（已整合）` 段落。
- 统一模板固定为 5 个小节：`复现范围与环境`、`结果摘要`、`关键运行输出（机理印证）`、`机理补充说明`、`证据索引`。
- `关键运行输出（机理印证）` 必须引用真实运行日志原文，使用 fenced code block（` ```text `）粘贴关键行。
- 每个 README 至少包含 2 组“结论级”日志证据：命中证据（如 `SUCCESS` / `VULNERABLE_OR_PARTIALLY_VULNERABLE`）或阻断证据（`BLOCKED_STAGE=*` + 关键报错）。
- 若同一 CVE 有版本对照（脆弱版本与修复版本），必须同时给出两侧日志片段并说明机理差异。
- `证据索引` 至少列出 `run.log` 与对应 runtime 日志路径（`docker_journal.log` / `isulad_journal.log` / `kernel_journal.log`）。
- 对“Docker 已跑但 iSulad 未跑”的 CVE，README 不可留空；需补齐 iSulad 同步验证（或明确给出不可等价迁移的阻断证据和判定）。

## 8. 已验证的关键经验

1. Docker 18.09 与较新 kind 组合会因 `--cgroupns` 参数不兼容失败。  
2. 只要脚本能稳定输出 `BLOCKED_STAGE`，即使未“成功逃逸”也具备检测策略价值。  
3. iSulad 与 Docker 对安全参数和错误语义不同（如 `apparmor=unconfined` 支持差异），必须单独记录。  
4. 网络不稳定是主要噪音源，脚本必须有重试、超时和明确失败归因。
5. 对 K8s 场景，优先保证“证据链完整性”：`exec` 阻断 + 启动日志探针回退，两者都要落盘。
