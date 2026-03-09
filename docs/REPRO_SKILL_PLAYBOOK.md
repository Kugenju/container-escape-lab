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

## 3. 环境切换工具

使用脚本：`scripts/env_labctl.sh`

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
```

补充：

- 已支持自动安装 `kubectl` / `kind`。
- 已支持镜像互导：`scripts/env_labctl.sh sync-image <image> docker-to-isula`

## 4. 推荐执行流程（下次会话直接照做）

### Step A: 基线采集

```bash
uname -a
docker --version || true
isula version || true
runc --version || true
scripts/env_labctl.sh status
```

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
3. 证据落盘到 `artifacts/repro/isula/<CVE>/`。

### Step D: K8s 场景

1. `scripts/env_labctl.sh profile k8s-kind`
2. 若 API 不可达，脚本应返回：
   - `BLOCKED_STAGE=k8s_api_unreachable`
3. 保证 `run.log` 内有可操作提示（如 `Hint: run scripts/env_labctl.sh profile k8s-kind`）。

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

## 6. 阻断阶段命名建议

建议统一格式：`BLOCKED_STAGE=<snake_case>`

常见示例：

- `parse_remote_refspec`
- `workdir_fd_path_validation`
- `trap_reexec_loader_dependency`
- `cgroup_v1_controller_unavailable`
- `runtime_version_not_vulnerable_range`
- `k8s_api_unreachable`

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
- `artifacts/repro/docker/REMAINING_SUMMARY_20260309.md`
- `artifacts/repro/isula/REMAINING_SUMMARY_20260309.md`

## 8. 已验证的关键经验

1. Docker 18.09 与较新 kind 组合会因 `--cgroupns` 参数不兼容失败。  
2. 只要脚本能稳定输出 `BLOCKED_STAGE`，即使未“成功逃逸”也具备检测策略价值。  
3. iSulad 与 Docker 对安全参数和错误语义不同（如 `apparmor=unconfined` 支持差异），必须单独记录。  
4. 网络不稳定是主要噪音源，脚本必须有重试、超时和明确失败归因。  
