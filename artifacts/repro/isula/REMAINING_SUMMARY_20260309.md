# Remaining PoC iSulad Verification (2026-03-09)

| CVE | Exit | Verdict | Notes |
| --- | --- | --- | --- |
| CVE-2016-9962 | 1 | `BLOCKED_STAGE=no_host_marker` | Trigger reached cgroup setup, but `release_agent` write was denied (`/tmp/cgrp/release_agent: Permission denied`). |
| CVE-2017-7308 | 1 | `BLOCKED_STAGE=no_success_marker` | Probe started and reached KASLR bypass stage, no `got r00t` marker. |
| CVE-2021-30465 | 1 | `BLOCKED_STAGE=runtime_version_not_vulnerable_range_or_race_miss` | Symlink race process started, but no host artifact observed in target directory. |

## Evidence

- `artifacts/repro/isula/CVE-2016-9962/run.log`
- `artifacts/repro/isula/CVE-2016-9962/isulad_journal.log`
- `artifacts/repro/isula/CVE-2016-9962/kernel_journal.log`
- `artifacts/repro/isula/CVE-2017-7308/run.log`
- `artifacts/repro/isula/CVE-2017-7308/isulad_journal.log`
- `artifacts/repro/isula/CVE-2017-7308/kernel_journal.log`
- `artifacts/repro/isula/CVE-2021-30465/run.log`
- `artifacts/repro/isula/CVE-2021-30465/isulad_journal.log`
- `artifacts/repro/isula/CVE-2021-30465/kernel_journal.log`
