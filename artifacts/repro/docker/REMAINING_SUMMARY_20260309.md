# Remaining PoC Batch Verification (2026-03-09)

| Script | Exit | Category | Note |
| --- | --- | --- | --- |
| cves/CVE-2016-5195/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=kernel_not_vulnerable_or_patched` |
| cves/CVE-2016-8655/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=cap_net_raw_unavailable` |
| cves/CVE-2016-9962/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/CVE-2017-1000112/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=smap_mitigation_detected` |
| cves/CVE-2017-16995/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=trigger_only_no_priv_esc_chain` |
| cves/CVE-2017-6074/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=dccp_module_unavailable` |
| cves/CVE-2017-7308/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/CVE-2018-18955/run_poc.sh | 0 | pass | script reported success marker |
| cves/CVE-2020-14386/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=cap_net_raw_unavailable` |
| cves/CVE-2021-30465/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/CVE-2021-3493/run_poc.sh | 0 | pass | script reported success marker |
| cves/CVE-2022-0847/run_poc.sh | 0 | pass | script reported success marker |
| cves/CVE-2022-0995/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered` |
| cves/CVE-2024-21626/run_poc_runc_direct.sh | 0 | pass | switched to vulnerable `runc 1.1.7` and hit direct-runc fd probe (`VULNERABLE_OR_PARTIALLY_VULNERABLE`) |
| cves/config-cap_dac_read_search-container/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/config-cap_sys_admin-container/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/config-cap_sys_module-container/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/config-cap_sys_ptrace-container/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/config-privileged-container/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/kata-escape-2020/run_poc.sh | 1 | blocked-stage | upgraded non-interactive run returned `BLOCKED_STAGE=kata_runtime_not_installed` |
| cves/mount-docker-sock/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/mount-host-etc/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/mount-host-procfs/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |
| cves/mount-var-log/run_poc.sh | 1 | blocked-stage | script completed with explicit block stage |

## 2026-03-10 Incremental Evidence

- `artifacts/repro/docker/CVE-2022-0995/auto-run-20260310/run.log`
- `artifacts/repro/docker/CVE-2022-0995/auto-run-20260310/kernel_journal.log`
- `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310/run.log`
- `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310/docker_journal.log`
- `artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/run.log`
- `artifacts/repro/docker/CVE-2017-1000112/auto-run-20260310/docker_journal.log`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/run.log`
- `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/docker_journal.log`
- `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/run.log`
- `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc5-20260310/docker_journal.log`
- `artifacts/repro/docker/CVE-2016-5195/auto-run-20260310/run.log`
- `artifacts/repro/docker/CVE-2016-5195/auto-run-20260310/kernel_journal.log`
- `artifacts/repro/docker/CVE-2016-8655/auto-run-20260310/run.log`
- `artifacts/repro/docker/CVE-2016-8655/auto-run-20260310/kernel_journal.log`
- `artifacts/repro/docker/CVE-2017-16995/auto-run-20260310/run.log`
- `artifacts/repro/docker/CVE-2017-16995/auto-run-20260310/kernel_journal.log`
- `artifacts/repro/docker/CVE-2017-6074/auto-run-20260310/run.log`
- `artifacts/repro/docker/CVE-2017-6074/auto-run-20260310/kernel_journal.log`
- `artifacts/repro/docker/CVE-2020-14386/auto-run-20260310/run.log`
- `artifacts/repro/docker/CVE-2020-14386/auto-run-20260310/kernel_journal.log`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/run.log`
- `artifacts/repro/docker/kata-escape-2020/auto-run-20260310/runtime_journal.log`
- `artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/run.log`
- `artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/run.log`
