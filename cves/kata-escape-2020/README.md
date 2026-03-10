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

## 5. 参考

- CVE-2020-2024：https://cveawg.mitre.org/api/cve/CVE-2020-2024
- CVE-2020-2026：https://cveawg.mitre.org/api/cve/CVE-2020-2026
- CVE-2020-28914：https://cveawg.mitre.org/api/cve/CVE-2020-28914
