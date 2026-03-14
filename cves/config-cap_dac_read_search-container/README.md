# 滥用 CAP_DAC_READ_SEARCH（Shocker）导致容器逃逸

## 1. 场景简介

该场景属于高危能力配置问题：容器被授予 `CAP_DAC_READ_SEARCH` 后，可调用 `open_by_handle_at()` 并绕过常规目录/文件读检查。
在容器与宿主机文件系统存在可关联路径时，攻击者可跨容器边界读取宿主机敏感文件。

本目录内容参考 `cves/metarget/writeups_cnv/config-cap_dac_read_search-container/README.md`，并与当前脚本流程对齐。

## 2. 复现该场景的价值

- 验证高危 capability（`CAP_DAC_READ_SEARCH`）是否被误授予业务容器。
- 验证容器对宿主机文件系统信息泄露的可行性与影响面。
- 验证平台策略（PSP/PSA/准入控制）是否拦截危险 capability 组合。

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
- `artifacts/repro/docker/config-cap_dac_read_search-container/run.log`: `[*] Verdict: PROBE_LOG_FALLBACK_OK`
- `artifacts/repro/docker/config-cap_dac_read_search-container/events_tail.txt`: `83s Normal Scheduled pod/cap-dac-read-search-container Successfully assigned metarget/cap-dac-read-search-container to escape-lab-control-plane`

## 4. 容器逃逸关键节点分析

1. 容器必须被授予 `CAP_DAC_READ_SEARCH`。
2. 容器内需要能拿到可解释到宿主机文件系统的 `mount_fd` 入口。
3. 目标文件系统要支持句柄相关操作（并非所有 FS 都可同样利用）。
4. 一旦成功读取宿主机高敏信息，容器边界即失去安全意义。

## 5. 目录结构

```text
config-cap_dac_read_search-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 只部署场景并验证 capability；完整 Shocker 利用需手工准备 `open_by_handle_at` PoC。

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
- `artifacts/repro/docker/config-cap_dac_read_search-container/run.log`: `[*] Verdict: PROBE_LOG_FALLBACK_OK`
- `artifacts/repro/docker/config-cap_dac_read_search-container/events_tail.txt`: `83s Normal Scheduled pod/cap-dac-read-search-container Successfully assigned metarget/cap-dac-read-search-container to escape-lab-control-plane`

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://github.com/gabrtv/shocker/blob/master/shocker.c
- https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html
- https://man7.org/linux/man-pages/man7/capabilities.7.html
- cves/metarget/writeups_cnv/config-cap_dac_read_search-container/README.md
