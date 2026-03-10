# Remaining PoC Batch Verification

## 1. Batch Result Table

| Script | Exit | Category | Summary |
| --- | --- | --- | --- |
| `cves/CVE-2016-5195/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=kernel_not_vulnerable_or_patched` |
| `cves/CVE-2016-8655/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=cap_net_raw_unavailable` |
| `cves/CVE-2016-9962/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/CVE-2017-1000112/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=smap_mitigation_detected` |
| `cves/CVE-2017-16995/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=trigger_only_no_priv_esc_chain` |
| `cves/CVE-2017-6074/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=dccp_module_unavailable` |
| `cves/CVE-2017-7308/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/CVE-2018-18955/run_poc.sh` | 0 | pass | success marker observed |
| `cves/CVE-2020-14386/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=cap_net_raw_unavailable` |
| `cves/CVE-2021-30465/run_poc.sh` (`runc 1.1.8`) | 1 | blocked-stage | `BLOCKED_STAGE=mount_path_or_permission_validation` |
| `cves/CVE-2021-30465/run_poc.sh` (`runc 1.0.0-rc94`) | 0 | pass | `VULNERABLE_OR_PARTIALLY_VULNERABLE` (host-root-like entries observed) |
| `cves/CVE-2021-3493/run_poc.sh` | 0 | pass | success marker observed |
| `cves/CVE-2022-0847/run_poc.sh` | 0 | pass | success marker observed |
| `cves/CVE-2022-0995/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered` |
| `cves/CVE-2024-21626/run_poc_runc_direct.sh` (`runc 1.1.7`) | 0 | pass | direct-runc probe hit (`VULNERABLE_OR_PARTIALLY_VULNERABLE`) |
| `cves/config-cap_dac_read_search-container/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/config-cap_sys_admin-container/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/config-cap_sys_module-container/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/config-cap_sys_ptrace-container/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/config-privileged-container/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/kata-escape-2020/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=kata_runtime_not_installed` |
| `cves/mount-docker-sock/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/mount-host-etc/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/mount-host-procfs/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |
| `cves/mount-var-log/run_poc.sh` | 1 | blocked-stage | explicit blocked stage recorded |

## 2. Version-Switch Comparative Runs (Merged)

| CVE | Comparative result | Evidence directory |
| --- | --- | --- |
| CVE-2021-30465 | vulnerable `runc 1.0.0-rc94` can hit; default `1.1.8` blocked | `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310-attempt2-race-create/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.1.8-20260310-attempt2-race-create/` |
| CVE-2019-5736 | vulnerable `runc 1.0.0-rc5` in high-trigger rerun hit host proof (`/tmp/CVE-2019-5736-PWNED`); default `1.1.8` remains blocked | `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt3/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt4/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt5/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt6-bash-trigger/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt8-high-trigger/` |
| CVE-2024-21626 | direct-runc: `runc 1.1.7` hit, `1.1.8` blocked | `artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/` |

## 3. Evidence Index

说明：每个目录按统一规范包含 `run.log`、`exit_code.txt`、`start_time.txt` 以及 runtime/kernel 相关日志。

- `artifacts/repro/docker/CVE-2016-5195/auto-run-20260310/`
- `artifacts/repro/docker/CVE-2016-8655/auto-run-20260310/`
- `artifacts/repro/docker/CVE-2017-16995/auto-run-20260310/`
- `artifacts/repro/docker/CVE-2017-6074/auto-run-20260310/`
- `artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/`
- `artifacts/repro/docker/CVE-2020-14386/auto-run-20260310/`
- `artifacts/repro/docker/CVE-2022-0995/auto-run-20260310/`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/`
- `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310-attempt2-race-create/`
- `artifacts/repro/docker/CVE-2021-30465/runc-1.1.8-20260310-attempt2-race-create/`
- `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt3/`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt4/`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt5/`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt6-bash-trigger/`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt8-high-trigger/`
- `artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/`
- `artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/`
