# iSulad Batch Verification

## 1. Result Table

| CVE | Exit | Verdict | Summary |
| --- | --- | --- | --- |
| CVE-2016-5195 | 1 | `BLOCKED_STAGE=kernel_not_vulnerable_or_patched` | Dirty-COW safe probe did not change read-only target content. |
| CVE-2016-8655 | 1 | `BLOCKED_STAGE=cap_net_raw_unavailable` | AF_PACKET probe blocked by missing `CAP_NET_RAW` in unprivileged context. |
| CVE-2016-9962 | 1 | `BLOCKED_STAGE=no_host_marker` | Trigger reached cgroup setup, but writing `/tmp/cgrp/release_agent` was denied. |
| CVE-2017-1000112 | 1 | `BLOCKED_STAGE=smap_mitigation_detected` | iSulad-mapped `run/cp/exec` chain ran, PoC aborted on SMAP mitigation. |
| CVE-2017-16995 | 1 | `BLOCKED_STAGE=trigger_only_no_priv_esc_chain` | eBPF primitive reachable, but no privilege-escalation chain in safe mode. |
| CVE-2017-6074 | 1 | `BLOCKED_STAGE=dccp_module_unavailable` | DCCP protocol/module unavailable in current kernel profile. |
| CVE-2017-7308 | 1 | `BLOCKED_STAGE=no_success_marker` | Privileged probe reached early stages, no `got r00t` marker. |
| CVE-2018-18955 | 0 | `pass` | Root markers detected in `subuid_shell/subshell` logs. |
| CVE-2019-13139 | 1 | `BLOCKED_STAGE=parse_remote_refspec` | `isula-build` treats crafted URL as local path and rejects before git exec path. |
| CVE-2019-14271 | 0 | `BLOCKED_STAGE=post_trigger_no_escape_artifact` | NSS replacement completed, but `/host_fs` escape artifact not observed. |
| CVE-2019-5736 | 1 | `BLOCKED_STAGE=runtime_cgroup_namespace_incompatible` | when `runc=1.0.0-rc5`, iSula container start failed with `namespace {"cgroup" ""} does not exist`; vulnerable chain cannot be entered. |
| CVE-2020-14386 | 1 | `BLOCKED_STAGE=cap_net_raw_unavailable` | AF_PACKET vnet probe blocked by missing `CAP_NET_RAW`. |
| CVE-2021-30465 | 0 | `VULNERABLE_OR_PARTIALLY_VULNERABLE` | Docker20 + `runc=1.0.0-rc94` sync rerun hit host-root-like listing under `/test1/zzz` (`victim_2`). |
| CVE-2021-3493 | 0 | `pass` | `uid=0/root` markers observed in run output. |
| CVE-2022-0847 | 0 | `pass` | `uid=0` + `popping root shell` markers observed. |
| CVE-2022-0995 | 1 | `BLOCKED_STAGE=notification_pipe_unavailable_or_filtered` | Notification pipe creation failed; exploit chain did not start. |
| CVE-2024-21626 | 0 | `VULNERABLE_OR_PARTIALLY_VULNERABLE` | Docker20 同步探针命中 host marker（`fd=8`），`workdir/fd` 泄露链路可触达。 |
| CVE-2025-31133 | 0 | `VULNERABLE_OR_PARTIALLY_VULNERABLE` | iSulad profile 下（`ROOTFS_RUNTIME=isula`）symlink-race 在 attempt2 命中 host `core_pattern` token。 |
| CVE-2025-52565 | 1 | `BLOCKED_STAGE=isula_buildx_named_context_unsupported` | iSulad 侧无 buildx/bake/named-context 等价入口，无法迁移官方 Buildx 模板。 |
| CVE-2025-52881 | 1 | `BLOCKED_STAGE=isula_buildx_named_context_unsupported` | iSulad 侧无 buildx/bake/named-context 等价入口，无法迁移官方 Buildx 模板。 |
| CVE-2025-23266 | 1 | `BLOCKED_STAGE=isula_nvidia_runtime_unavailable` | 补装 `nvidia-container-toolkit 1.17.7` 后复测仍阻断；isulad 明确报错 `runtime nvidia is not supported`。 |

## 2. Backfilled This Round

新增补录并完成 iSulad 同步验证的 CVE：

- CVE-2016-5195
- CVE-2016-8655
- CVE-2017-1000112
- CVE-2017-16995
- CVE-2017-6074
- CVE-2018-18955
- CVE-2020-14386
- CVE-2021-3493
- CVE-2022-0847
- CVE-2022-0995
- CVE-2025-52565（Buildx 链路同步判定）
- CVE-2025-52881（Buildx 链路同步判定）

## 3. Evidence Index

说明：每个目录包含 `run.log`、`exit_code.txt`、`isulad_journal.log`、`kernel_journal.log`（以及场景附加日志）。

- `artifacts/repro/isula/CVE-2016-5195/`
- `artifacts/repro/isula/CVE-2016-8655/`
- `artifacts/repro/isula/CVE-2016-9962/`
- `artifacts/repro/isula/CVE-2017-1000112/`
- `artifacts/repro/isula/CVE-2017-16995/`
- `artifacts/repro/isula/CVE-2017-6074/`
- `artifacts/repro/isula/CVE-2017-7308/`
- `artifacts/repro/isula/CVE-2018-18955/`
- `artifacts/repro/isula/CVE-2019-13139/`
- `artifacts/repro/isula/CVE-2019-14271/`
- `artifacts/repro/isula/CVE-2019-5736/`
- `artifacts/repro/isula/CVE-2019-5736/runc-1.0.0-rc5-high-trigger-rerun3/`
- `artifacts/repro/isula/CVE-2020-14386/`
- `artifacts/repro/isula/CVE-2021-30465/`
- `artifacts/repro/isula/CVE-2021-30465/docker20-runc1.0.0-rc94-rerun/`
- `artifacts/repro/isula/CVE-2021-3493/`
- `artifacts/repro/isula/CVE-2022-0847/`
- `artifacts/repro/isula/CVE-2022-0995/`
- `artifacts/repro/isula/CVE-2024-21626/`
- `artifacts/repro/isula/CVE-2024-21626/docker20-runc1.1.5-sync-20260310-attempt2/`
- `artifacts/repro/isula/CVE-2025-31133/isula2.1.6-runc1.1.5-20260311-attempt2/`
- `artifacts/repro/isula/CVE-2025-52565/isula2.1.6-sync-20260311-attempt1/`
- `artifacts/repro/isula/CVE-2025-52881/isula2.1.6-sync-20260311-attempt1/`
- `artifacts/repro/isula/CVE-2025-23266/isula2.1.6-runc1.1.5-20260311-attempt1/`
- `artifacts/repro/isula/CVE-2025-23266/isula2.1.6-runc1.1.5-nct1.17.7-20260311-attempt2/`
