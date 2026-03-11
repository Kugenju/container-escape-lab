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
| `cves/CVE-2024-21626/run_poc.sh` (`docker 20.10.24 + runc 1.1.5`) | 0 | pass | Attack-1 probe hit host marker (`fd=9`, `VULNERABLE_OR_PARTIALLY_VULNERABLE`) |
| `cves/CVE-2025-31133/run_poc.sh` (`docker 20.10.24 + runc 1.1.5`) | 0 | pass | symlink-race hit host `core_pattern` token (`VULNERABLE_OR_PARTIALLY_VULNERABLE`) |
| `cves/CVE-2025-52565/run_poc.sh` (`docker 20.10.24 + buildx v0.31.0 + buildkit v0.27.1`) | 1 | blocked-stage | `BLOCKED_STAGE=exploit_context_image_unreachable`（官方 Buildx `procfs` 模板阻断于 `cyphar/procfs-trap-in-docker-buildx` 镜像元数据拉取） |
| `cves/CVE-2025-52881/run_poc.sh` (`docker 20.10.24 + buildx v0.31.0 + buildkit v0.27.1`) | 1 | blocked-stage | `BLOCKED_STAGE=dockerfile_frontend_image_unreachable`（官方 Buildx `sysfs` 模板阻断于 Dockerfile frontend 镜像拉取） |
| `cves/CVE-2025-23266/run_poc.sh` (`docker 20.10.24 + runc 1.1.5 + nct 1.17.7`) | 1 | blocked-stage | `BLOCKED_STAGE=nvidia_driver_library_unavailable`（`nvidia` runtime 已注册，阻断于 `libnvidia-ml.so.1` 缺失） |
| `cves/CVE-2024-21626/run_poc_runc_direct.sh` (`runc 1.1.7`) | 0 | pass | direct-runc probe hit (`VULNERABLE_OR_PARTIALLY_VULNERABLE`) |
| `cves/config-cap_dac_read_search-container/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（exec 失败后由启动日志探针补证） |
| `cves/config-cap_sys_admin-container/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（含 `mount tmpfs success`） |
| `cves/config-cap_sys_module-container/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（能力与工具链探针已落盘） |
| `cves/config-cap_sys_ptrace-container/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（hostPID 进程视图证据已落盘） |
| `cves/config-privileged-container/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（设备与块盘可见性证据已落盘） |
| `cves/kata-escape-2020/run_poc.sh` | 1 | blocked-stage | `BLOCKED_STAGE=kata_runtime_not_installed` |
| `cves/mount-docker-sock/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（docker.sock 暴露证据已落盘） |
| `cves/mount-host-etc/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（宿主机 `/etc` 可见性证据已落盘） |
| `cves/mount-host-procfs/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（`core_pattern` 读取证据已落盘） |
| `cves/mount-var-log/run_poc.sh` | 0 | pass | `PROBE_LOG_FALLBACK_OK`（日志挂载链路证据已落盘） |

## 2. Version-Switch Comparative Runs (Merged)

| CVE | Comparative result | Evidence directory |
| --- | --- | --- |
| CVE-2021-30465 | vulnerable `runc 1.0.0-rc94` can hit; default `1.1.8` blocked | `artifacts/repro/docker/CVE-2021-30465/runc-1.0.0-rc94-20260310-attempt2-race-create/`, `artifacts/repro/docker/CVE-2021-30465/runc-1.1.8-20260310-attempt2-race-create/` |
| CVE-2019-5736 | vulnerable `runc 1.0.0-rc5` in high-trigger rerun hit host proof (`/tmp/CVE-2019-5736-PWNED`); default `1.1.8` remains blocked | `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt2/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt3/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt4/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt5/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt6-bash-trigger/`, `artifacts/repro/docker/CVE-2019-5736/runc-1.0.0-rc5-20260310-attempt8-high-trigger/` |
| CVE-2024-21626 | Docker Attack-1 on `20.10.24 + runc 1.1.5` hit (`fd=9`); direct-runc keeps `1.1.7` hit / `1.1.8` blocked | `artifacts/repro/docker/CVE-2024-21626/docker20-runc1.1.5-20260310-attack-path/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.7-direct-20260310/`, `artifacts/repro/docker/CVE-2024-21626/runc-1.1.8-direct-20260310/` |
| CVE-2025-31133 | `runc 1.1.5` 下 symlink-race PoC 可命中 host `core_pattern` token（首轮即命中） | `artifacts/repro/docker/CVE-2025-31133/docker20-runc1.1.5-20260311-attempt5/` |
| CVE-2025-52565 | official Buildx `procfs` template 已进入 named-context 解析，但阻断于 exploit context 镜像 `cyphar/procfs-trap-in-docker-buildx` 远端可达性 | `artifacts/repro/docker/CVE-2025-52565/buildx-template-20260311-attempt1/` |
| CVE-2025-52881 | official Buildx `sysfs` template 已进入 frontend 解析，但阻断于 Dockerfile frontend 镜像 `docker/dockerfile:1.20.0-rc.1` 远端可达性 | `artifacts/repro/docker/CVE-2025-52881/buildx-template-20260311-attempt1/` |
| CVE-2025-23266 | 引入公开 PoC 后补装并启用 `nvidia-container-toolkit 1.17.7`，已推进至 hook 执行阶段；当前阻断为宿主缺失 `libnvidia-ml.so.1`（NVIDIA driver userspace） | `artifacts/repro/docker/CVE-2025-23266/docker20-runc1.1.5-20260311-attempt1/`, `artifacts/repro/docker/CVE-2025-23266/docker20-runc1.1.5-nct1.17.7-20260311-attempt6/` |
| CVE-2019-14271 | vulnerable-window retest on Docker `19.03.0` remained blocked (`post_trigger_no_escape_artifact`) | `artifacts/repro/docker/CVE-2019-14271/docker-19.03.0-20260310-attempt1/` |

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
- `artifacts/repro/docker/CVE-2024-21626/docker20-runc1.1.5-20260310-attack-path/`
- `artifacts/repro/docker/CVE-2024-21626/docker20-runc115-fdscan-20260310.log`
- `artifacts/repro/docker/CVE-2025-31133/docker20-runc1.1.5-20260311-attempt5/`
- `artifacts/repro/docker/CVE-2025-52565/buildx-template-20260311-attempt1/`
- `artifacts/repro/docker/CVE-2025-52881/buildx-template-20260311-attempt1/`
- `artifacts/repro/docker/CVE-2025-23266/docker20-runc1.1.5-20260311-attempt1/`
- `artifacts/repro/docker/CVE-2025-23266/docker20-runc1.1.5-nct1.17.7-20260311-attempt6/`
- `artifacts/repro/docker/CVE-2019-14271/docker-19.03.0-20260310-attempt1/`
- `artifacts/repro/docker/version-matrix/docker19-switch.log`
- `artifacts/repro/docker/version-matrix/docker-restore-20.10-from-backup.log`
- `artifacts/repro/docker/k8s-version-matrix/v1.30.0-preload.log`
- `artifacts/repro/docker/k8s-version-matrix/v1.27.13-preload.log`
- `artifacts/repro/docker/k8s-version-matrix/fallback-batch-v1.27.13.log`

## 4. K8s Docker 20.10 Validation (Latest)

- Validation stack: Docker `20.10.24` + containerd `1.6.20` + runc `1.1.5`
- First strict check (`K8S_EXEC_FALLBACK_TO_LOGS=0`) reached `PROBE_EXECUTED`
- 9 scenario batch all `exit_code=0` with `PROBE_EXECUTED`
- Repeated `kind-up` on same host can still hit kubelet health timeout (`localhost:10248/healthz`), so stability is currently marked as partial

Evidence:

- `artifacts/repro/docker/k8s-version-matrix/docker20-v1.30.0.log`
- `artifacts/repro/docker/k8s-version-matrix/docker20-batch-v1.30.0.log`
- `artifacts/repro/docker/k8s-version-matrix/docker20-retry-kindup-full.log`
