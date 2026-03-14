# 挂载 /var/log 导致容器逃逸

## 1. 场景简介

该场景属于 Kubernetes 配置链路风险：Pod 以可写方式挂载宿主机 `/var/log`，
并且该 Pod 的 ServiceAccount 具备读取节点日志接口（`nodes/log`）的权限。
攻击者可借助符号链接与日志读取路径实现宿主机文件读取。

本目录内容参考 `cves/metarget/writeups_cnv/mount-var-log/README.md`，并与当前脚本流程对齐。

## 2. 复现该场景的价值

- 验证 `hostPath + RBAC` 组合是否形成可利用逃逸链。
- 验证 kubelet 日志读取路径在错误配置下的安全边界。
- 验证平台是否能识别并阻断可写 `/var/log` 挂载。

## 3. 作用机理（分阶段）

这一节按“前提 -> 触发 -> 越权 -> 证据”讲清楚漏洞链路，并和脚本关键命令一一对应。

### 先看关键代码链（按执行顺序）
- `run_poc.sh:L16`: `command -v kubectl >/dev/null 2>&1 || { echo "[-] Missing dependency: kubectl"; exit 1; }`
- `run_poc.sh:L22`: `echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"`
- `run_poc.sh:L28`: `kubectl apply -f "$MANIFEST"`
- `run_poc.sh:L32`: `echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"`

### 阶段 1：前提条件
- 先确认依赖、运行时版本和实验目标是否可达。否则脚本会在最外层提前退出。
- 对应代码：`run_poc.sh:L16` -> `command -v kubectl >/dev/null 2>&1 || { echo "[-] Missing dependency: kubectl"; exit 1; }`。

### 阶段 2：触发漏洞
- 利用链真正开始于“把目标进程拉起并喂入特定参数/路径/时序”，让程序走进有缺陷的分支。
- 对应代码：`run_poc.sh:L28` -> `kubectl apply -f "$MANIFEST"`。

### 阶段 3：越权动作
- 这一阶段的目标是把容器内可控行为转换成宿主机影响（文件、进程、运行时执行链）。

### 阶段 4：结果落地与证据
- 成功不是“脚本跑完”，而是日志出现强语义判定，并且有可复核文件证据。
- 对应代码：`run_poc.sh:L22` -> `echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"`。
- 对应代码：`run_poc.sh:L32` -> `echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"`。

### artifacts 对应证据（示例）
- `artifacts/repro/docker/mount-var-log/run.log`: `[*] Verdict: PROBE_LOG_FALLBACK_OK`
- `artifacts/repro/docker/mount-var-log/events_tail.txt`: `99s Normal Scheduled pod/cap-dac-read-search-container Successfully assigned metarget/cap-dac-read-search-container to escape-lab-control-plane`
- `artifacts/repro/docker/mount-var-log/events_tail.txt`: `16s Normal Scheduled pod/cap-sys-admin-container Successfully assigned metarget/cap-sys-admin-container to escape-lab-control-plane`

## 4. 容器逃逸关键节点分析

1. 必须存在可写 `hostPath` 挂载：宿主机 `/var/log`。
2. ServiceAccount 需要具备日志读取相关权限（如 `nodes/log`）。
3. kubelet 日志读取对符号链接路径的处理成为关键利用点。
4. 一旦宿主机敏感文件可读，后续凭据窃取与主机接管风险显著上升。

## 5. 目录结构

```text
mount-var-log/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 会部署场景并尝试调用 `lsh/cath`；若镜像中未包含对应工具，会显示未找到。

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
- `artifacts/repro/docker/mount-var-log/run.log`: `[*] Verdict: PROBE_LOG_FALLBACK_OK`
- `artifacts/repro/docker/mount-var-log/events_tail.txt`: `99s Normal Scheduled pod/cap-dac-read-search-container Successfully assigned metarget/cap-dac-read-search-container to escape-lab-control-plane`
- `artifacts/repro/docker/mount-var-log/events_tail.txt`: `16s Normal Scheduled pod/cap-sys-admin-container Successfully assigned metarget/cap-sys-admin-container to escape-lab-control-plane`

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts
- https://github.com/danielsagi/kube-pod-escape
- cves/metarget/writeups_cnv/mount-var-log/README.md
