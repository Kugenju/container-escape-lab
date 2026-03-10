# Remaining PoC iSulad Verification

## 1. Result Table

| CVE | Exit | Verdict | Summary |
| --- | --- | --- | --- |
| CVE-2016-9962 | 1 | `BLOCKED_STAGE=no_host_marker` | Trigger reached cgroup setup, but writing `/tmp/cgrp/release_agent` was denied. |
| CVE-2017-7308 | 1 | `BLOCKED_STAGE=no_success_marker` | Probe reached early exploit stages, no `got r00t` marker. |
| CVE-2021-30465 | 1 | `BLOCKED_STAGE=runtime_version_not_vulnerable_range_or_race_miss` | Symlink race process started, but no host artifact in target directory. |

## 2. Evidence Index

- `artifacts/repro/isula/CVE-2016-9962/`
- `artifacts/repro/isula/CVE-2017-7308/`
- `artifacts/repro/isula/CVE-2021-30465/`

说明：以上目录包含 `run.log`、`isulad_journal.log` 与 `kernel_journal.log`，可用于复核阻断阶段。
