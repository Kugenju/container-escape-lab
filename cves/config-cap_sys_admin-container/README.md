# 滥用 CAP_SYS_ADMIN 导致容器逃逸

## 1. 场景简介

该场景是典型高危能力配置问题：容器被授予 `CAP_SYS_ADMIN`。
该 capability 覆盖大量挂载、命名空间和系统管理相关操作，常被称为“近似 root 的万能能力”。

本目录基于 `cves/metarget/writeups_cnv/config-cap_sys_admin-container/` 场景定义（对应 README 为空）重组，并与脚本行为对齐。

## 2. 复现该场景的价值

- 验证平台是否错误放行 `CAP_SYS_ADMIN` 到业务容器。
- 验证容器侧 mount/chroot 等关键操作是否可被滥用。
- 验证准入与运行时策略对高危 capability 的阻断能力。

## 3. 作用机理（分阶段）

这一节按“前提 -> 触发 -> 越权 -> 证据”讲清楚漏洞链路，并和脚本关键命令一一对应。

### 先看关键代码链（按执行顺序）
- `run_poc.sh:L16`: `command -v kubectl >/dev/null 2>&1 || { echo "[-] Missing dependency: kubectl"; exit 1; }`
- `run_poc.sh:L22`: `echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"`
- `run_poc.sh:L28`: `kubectl apply -f "$MANIFEST"`
- `run_poc.sh:L32`: `echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"`
- `run_poc.sh:L36`: `"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; grep CapEff /proc/1/status; mkdir -p /tmp/mt_test && mount -t tmpfs tmpfs /tmp/mt_test && echo "[+] mount t...`
- `run_poc.sh:L38`: `echo "[*] 可继续按业务场景挂载宿主机目录并执行 chroot。"`

### 阶段 1：前提条件
- 先确认依赖、运行时版本和实验目标是否可达。否则脚本会在最外层提前退出。
- 对应代码：`run_poc.sh:L16` -> `command -v kubectl >/dev/null 2>&1 || { echo "[-] Missing dependency: kubectl"; exit 1; }`。

### 阶段 2：触发漏洞
- 利用链真正开始于“把目标进程拉起并喂入特定参数/路径/时序”，让程序走进有缺陷的分支。
- 对应代码：`run_poc.sh:L28` -> `kubectl apply -f "$MANIFEST"`。

### 阶段 3：越权动作
- 这一阶段的目标是把容器内可控行为转换成宿主机影响（文件、进程、运行时执行链）。
- 对应代码：`run_poc.sh:L36` -> `"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; grep CapEff /proc/1/status; mkdir -p /tmp/mt_test && mount -t tmpfs tmpfs /tmp/mt_test && echo "[+] mount t...`。
- 对应代码：`run_poc.sh:L38` -> `echo "[*] 可继续按业务场景挂载宿主机目录并执行 chroot。"`。

### 阶段 4：结果落地与证据
- 成功不是“脚本跑完”，而是日志出现强语义判定，并且有可复核文件证据。
- 对应代码：`run_poc.sh:L22` -> `echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"`。
- 对应代码：`run_poc.sh:L32` -> `echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"`。

### artifacts 对应证据（示例）
- `artifacts/repro/docker/config-cap_sys_admin-container/run.log`: `[+] mount tmpfs success`
- `artifacts/repro/docker/config-cap_sys_admin-container/run.log`: `[*] Verdict: PROBE_LOG_FALLBACK_OK`
- `artifacts/repro/docker/config-cap_sys_admin-container/events_tail.txt`: `85s Normal Scheduled pod/cap-dac-read-search-container Successfully assigned metarget/cap-dac-read-search-container to escape-lab-control-plane`
- `artifacts/repro/docker/config-cap_sys_admin-container/events_tail.txt`: `2s Normal Scheduled pod/cap-sys-admin-container Successfully assigned metarget/cap-sys-admin-container to escape-lab-control-plane`

## 4. 容器逃逸关键节点分析

1. `CAP_SYS_ADMIN` 是核心风险前提。
2. 需要存在可用的宿主机资源入口（挂载点、设备、hostPath 等）。
3. 一旦可挂载并切换到宿主机文件系统，上层容器隔离机制会被绕过。
4. 该类问题根因是配置错误，通常不依赖复杂内核漏洞。

## 5. 目录结构

```text
config-cap_sys_admin-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 会验证 capability 与基础挂载能力；完整逃逸步骤需在实验环境手工延伸。

## 7. 一键复现场景

```bash
bash run_poc.sh
```


## 成功判定（结合 run_poc.sh 与 artifacts）

建议用“可复核”的口径判定，避免只看单行输出。

### 成功判定（建议同时满足）
1. 脚本进入判定分支，没有在依赖检查阶段退出。
2. 日志中出现 `SUCCESS` / `VULNERABLE` / `pass` 等强语义词。
3. 有落地证据文件或宿主机侧状态变化可复查。

### 阻断/失败判定
1. 出现 `BLOCKED_STAGE=...`：说明链路被明确阻断，可据此定位阶段。
2. 只出现环境类错误（API 不可达、依赖缺失）：属于前置失败，不能据此判漏洞不存在。
3. 有触发动作但没有证据落地：记为“未稳定命中”，需调参重试。

### 与脚本代码对应的判定点
- `run_poc.sh:L22`: `echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"`
- `run_poc.sh:L32`: `echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"`

### artifacts 运行证据
- `artifacts/repro/docker/config-cap_sys_admin-container/run.log`: `[+] mount tmpfs success`
- `artifacts/repro/docker/config-cap_sys_admin-container/run.log`: `[*] Verdict: PROBE_LOG_FALLBACK_OK`
- `artifacts/repro/docker/config-cap_sys_admin-container/events_tail.txt`: `85s Normal Scheduled pod/cap-dac-read-search-container Successfully assigned metarget/cap-dac-read-search-container to escape-lab-control-plane`
- `artifacts/repro/docker/config-cap_sys_admin-container/events_tail.txt`: `2s Normal Scheduled pod/cap-sys-admin-container Successfully assigned metarget/cap-sys-admin-container to escape-lab-control-plane`

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://man7.org/linux/man-pages/man7/capabilities.7.html
- cves/metarget/writeups_cnv/config-cap_sys_admin-container/
