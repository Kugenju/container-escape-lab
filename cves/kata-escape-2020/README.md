# Kata 容器逃逸（kata-escape-2020）

## 1. 场景简介

本目录记录 Kata Containers 在 2020 年披露的多类 guest-host 边界问题，重点覆盖：

- CVE-2020-2024：Kata `< 1.11.0`
- CVE-2020-2026：Kata `1.11 < 1.11.1`、`1.10 < 1.10.5`、以及 `1.9` 及更早版本
- CVE-2020-28914：Kata `< 1.11.5`

这类问题通常需要特定运行时配置（如 clh、hostPath、teardown 场景）才能形成完整逃逸链。

## 2. 本目录自动化探测说明

当前目录已补齐非交互自动化流程：

- `run_poc.sh`：自动检查 `kata-runtime` 是否存在、解析版本并输出 `BLOCKED_STAGE`；同时采集 `runtime_journal.log`。

默认结论语义：

- `BLOCKED_STAGE=kata_runtime_not_installed`
- `BLOCKED_STAGE=kata_runtime_version_parse_failed`
- `BLOCKED_STAGE=runtime_version_not_vulnerable_range`
- `BLOCKED_STAGE=runtime_in_range_but_poc_chain_not_available`


## 漏洞作用机理（结合本目录脚本）

这一节按“前提 -> 触发 -> 越权 -> 证据”讲清楚漏洞链路，并和脚本关键命令一一对应。

### 先看关键代码链（按执行顺序）
- `run_poc.sh:L36`: `echo "[*] Reference vulnerable ranges:"`
- `run_poc.sh:L44`: `echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed" | tee -a "$LOG_FILE"`
- `run_poc.sh:L45`: `journalctl --since "$START_TS" --no-pager -u containerd.service -u docker.service >"$RUNTIME_JOURNAL_FILE" 2>/dev/null || true`
- `run_poc.sh:L56`: `echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_version_parse_failed" | tee -a "$LOG_FILE"`
- `run_poc.sh:L59`: `echo "[-] kata-runtime version outside listed vulnerable ranges." | tee -a "$LOG_FILE"`
- `run_poc.sh:L60`: `echo "[*] Verdict: BLOCKED_STAGE=runtime_version_not_vulnerable_range" | tee -a "$LOG_FILE"`

### 阶段 1：前提条件
- 先确认依赖、运行时版本和实验目标是否可达。否则脚本会在最外层提前退出。
- 对应代码：`run_poc.sh:L44` -> `echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed" | tee -a "$LOG_FILE"`。
- 对应代码：`run_poc.sh:L45` -> `journalctl --since "$START_TS" --no-pager -u containerd.service -u docker.service >"$RUNTIME_JOURNAL_FILE" 2>/dev/null || true`。

### 阶段 2：触发漏洞
- 利用链真正开始于“把目标进程拉起并喂入特定参数/路径/时序”，让程序走进有缺陷的分支。

### 阶段 3：越权动作
- 这一阶段的目标是把容器内可控行为转换成宿主机影响（文件、进程、运行时执行链）。

### 阶段 4：结果落地与证据
- 成功不是“脚本跑完”，而是日志出现强语义判定，并且有可复核文件证据。
- 对应代码：`run_poc.sh:L36` -> `echo "[*] Reference vulnerable ranges:"`。
- 对应代码：`run_poc.sh:L44` -> `echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed" | tee -a "$LOG_FILE"`。
- 对应代码：`run_poc.sh:L56` -> `echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_version_parse_failed" | tee -a "$LOG_FILE"`。
- 对应代码：`run_poc.sh:L59` -> `echo "[-] kata-runtime version outside listed vulnerable ranges." | tee -a "$LOG_FILE"`。

### artifacts 对应证据（示例）
- `cves/kata-escape-2020/run_poc.log`: `[*] Reference vulnerable ranges:`
- `cves/kata-escape-2020/run_poc.log`: `[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed`
- `artifacts/repro/docker/kata-escape-2020/run.log`: `[*] This scene requires vulnerable Kata runtime (e.g. 1.10.0 with clh) and dedicated PoC.`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/run.log`: `[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/run_poc.local.log`: `[*] Reference vulnerable ranges:`

## 3. 目录结构

```text
kata-escape-2020/
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 4. 一键检查

```bash
bash run_poc.sh
```

清理产物：

```bash
bash run_poc.sh --cleanup
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
- `run_poc.sh:L36`: `echo "[*] Reference vulnerable ranges:"`
- `run_poc.sh:L44`: `echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed" | tee -a "$LOG_FILE"`
- `run_poc.sh:L56`: `echo "[*] Verdict: BLOCKED_STAGE=kata_runtime_version_parse_failed" | tee -a "$LOG_FILE"`
- `run_poc.sh:L59`: `echo "[-] kata-runtime version outside listed vulnerable ranges." | tee -a "$LOG_FILE"`
- `run_poc.sh:L60`: `echo "[*] Verdict: BLOCKED_STAGE=runtime_version_not_vulnerable_range" | tee -a "$LOG_FILE"`

### artifacts 运行证据
- `cves/kata-escape-2020/run_poc.log`: `[*] Reference vulnerable ranges:`
- `cves/kata-escape-2020/run_poc.log`: `[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed`
- `artifacts/repro/docker/kata-escape-2020/run.log`: `[*] This scene requires vulnerable Kata runtime (e.g. 1.10.0 with clh) and dedicated PoC.`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/run.log`: `[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/run_poc.local.log`: `[*] Reference vulnerable ranges:`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/run_poc.local.log`: `[*] Verdict: BLOCKED_STAGE=kata_runtime_not_installed`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/dmesg_tail.log`: `[Tue Mar 10 11:53:15 2026] systemd[1]: initrd-switch-root.service: Deactivated successfully.`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/dmesg_tail.log`: `[Tue Mar 10 11:53:15 2026] systemd[1]: Dispatch Password Requests to Console Directory Watch was skipped because of an unmet condition check (Condi...`

## 5. 参考

- CVE-2020-2024：https://cveawg.mitre.org/api/cve/CVE-2020-2024
- CVE-2020-2026：https://cveawg.mitre.org/api/cve/CVE-2020-2026
- CVE-2020-28914：https://cveawg.mitre.org/api/cve/CVE-2020-28914
