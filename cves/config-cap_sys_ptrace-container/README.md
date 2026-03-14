# 滥用 CAP_SYS_PTRACE + hostPID 导致容器逃逸

## 1. 简介

这同样不是单一 CVE，而是一类高危组合配置：

- `hostPID: true`
- `CAP_SYS_PTRACE`

把这两个条件放在一起，相当于做了两件危险的事：

1. 先把宿主机进程世界暴露给容器看。
2. 再给容器一把可以“调试、附加、读写目标进程状态”的能力。

如果目标宿主机进程还能被成功附加，那么后续就不只是“看见宿主机进程”这么简单，而是可能进入内存读写、执行流劫持甚至借高权限宿主机进程完成逃逸。

当前目录里的脚本主要是在验证：这个危险组合是不是已经真实生效，而不是自动替你完成完整注入利用。

## 2. 价值

- 验证准入策略是否真的拦住了 `hostPID + SYS_PTRACE` 这种危险组合。
- 帮助初学者理解“为什么看到宿主机进程”本身就已经很危险。
- 为后续 ptrace 注入、宿主机进程控制等完整利用链提供前置证据。

## 3. 作用机理

这个场景可以把它想成两把钥匙同时交给了容器。

- 第一把钥匙是 `hostPID: true`，它打开的是“看见宿主机进程”的门。
- 第二把钥匙是 `CAP_SYS_PTRACE`，它打开的是“对这些进程做调试级操作”的门。

单独看其中一把，风险已经不低；两把叠在一起，就可能从“容器内 root”走向“干预宿主机进程”。

### 第一步：危险配置首先写在 `scene.yaml` 里

真正把风险引进来的，不是脚本输出，而是 Pod 定义：

```yaml
# scene.yaml
spec:
  hostPID: true
  containers:
  - name: ubuntu
    securityContext:
      capabilities:
        add: ["SYS_PTRACE"]

# 注释 1：hostPID: true 让容器看到宿主机 PID 命名空间
# 注释 2：SYS_PTRACE 让容器具备对其他进程进行调试/附加的能力基础
```

如果没有 `hostPID: true`，容器通常只能看到自己的 PID 世界；
如果没有 `SYS_PTRACE`，即使看见了宿主机进程，也未必有能力去附加和操作。

### 第二步：`run_poc.sh` 先确认集群可用，再把场景部署起来

脚本的主体逻辑并不复杂：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

这一步的含义是：

- 只有 Pod 真正跑起来，危险组合才算实际落地。
- 如果 Pod 没就绪，就还不能说这个风险已经进入可利用状态。

### 第三步：探针不做真正注入，只做“危险前提是否成立”的验证

Pod Ready 后，脚本会调用公共探针执行下面这组命令：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" \
  'id; grep CapEff /proc/1/status; ps -eo pid,comm | head'

# 注释：这里不是直接发起 ptrace 注入
# 而是在验证三个前提：当前身份、能力位、能否看见宿主机进程列表
```

这三条命令分别在证明：

- `id`：当前容器里是什么用户身份。
- `grep CapEff /proc/1/status`：当前进程的有效能力集合里是否带上了高权限 capability。
- `ps -eo pid,comm | head`：容器看到的是不是宿主机 PID 空间，而不是只看到自己。

### 第四步：为什么看到 `systemd`、`containerd` 这类进程就是危险信号

如果容器没有 `hostPID: true`，一般不会直接在 `ps` 里看到宿主机的 `systemd`、`containerd`、`containerd-shim` 这些进程。

一旦看到了，说明容器和宿主机的 PID 边界已经被打通了一大块。
再叠加 `CAP_SYS_PTRACE`，攻击者理论上就可以继续尝试：

1. 定位高价值宿主机进程。
2. 对进程执行附加、内存读写、寄存器修改等操作。
3. 借宿主机高权限进程把容器边界进一步打穿。

当前脚本没有自动执行这些后续动作，但它已经证明“最危险的前提组合真的存在”。

### artifacts 运行证据

当前日志里最关键的证据有三块：

```text
# artifacts/repro/docker/config-cap_sys_ptrace-container/run.log
pod/cap-sys-ptrace-container created
pod/cap-sys-ptrace-container condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
CapEff: 0000003fffffffff
    PID COMMAND
      1 systemd
    274 systemd-journal
    301 containerd
    413 containerd-shim
    414 containerd-shim
...
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK

# 注释 1：uid=0(root) 说明容器里是 root 身份
# 注释 2：CapEff 说明有效能力集合非常高，包含危险 capability
# 注释 3：systemd/containerd/containerd-shim 出现在进程列表里，说明容器看到的是宿主机 PID 空间
```

和上一个 K8s 场景一样，这次在线 `exec` 探针也失败了：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

但后面的 `K8S_LOG_PROBE_BEGIN` 到 `K8S_LOG_PROBE_OK` 依然把关键证据补齐了，所以当前 artifacts 仍然可以作为有效运行证明。

## 4. 关键节点分析

1. `hostPID: true` 让容器看到宿主机进程世界，这是第一道边界放松。
2. `CAP_SYS_PTRACE` 提供了进一步调试和干预这些进程的能力基础。
3. `ps` 输出里出现宿主机关键进程，是“危险前提已经成立”的直接证据。
4. 当前样本证明的是“高危组合已落地”，不是“完整 ptrace 注入已经自动跑完”。

## 5. 目录结构

```text
config-cap_sys_ptrace-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先确保有可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/config-cap_sys_ptrace-container/run_poc.sh
```

清理：

```bash
bash cves/config-cap_sys_ptrace-container/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# 集群 API 不可达，场景还没被部署出来

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没 ready，危险组合还没有真正进入运行状态

情况 3：exec probe failed, attempting startup-log fallback
# 在线 exec 失败，但不一定影响最终取证
# 如果日志里仍然出现 K8S_LOG_PROBE_BEGIN / K8S_LOG_PROBE_OK，就说明回退取证成功
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

这里同样要区分“当前脚本验证成功”与“最终逃逸成功”。

### 真正命中当前脚本要验证的目标

下面这些条件同时出现，就说明这份 PoC 要验证的危险前提已经成立：

1. Pod 创建并 Ready。
2. 日志里出现 `CapEff:`，说明能力集合确实被加进去了。
3. `ps` 输出里出现 `systemd`、`containerd`、`containerd-shim` 这类宿主机进程。
4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这代表：

- 容器已经看到宿主机 PID 空间。
- 高危 capability 也已经生效。

对于“危险配置验证”这一层目标来说，这就算命中。

### 只到中间阶段 / 部分命中

如果出现下面这种情况：

```text
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
...
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

说明在线探针失败了，但日志回退仍然拿到了证据。
这可以算当前脚本的有效命中，只是取证路径不是最理想的那条。

### 前置失败 / 明确阻断

以下情况都属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

它们只能说明实验环境没准备好，不能说明 `hostPID + SYS_PTRACE` 这个组合是安全的。

### 如果要算“最终逃逸成功”，还差什么

对于这个场景，真正的完整逃逸至少还需要：

1. 选定一个可附加的宿主机目标进程。
2. 成功执行 ptrace 附加或等价注入动作。
3. 观察到宿主机进程状态被改写，或宿主机执行流被控制。

当前仓库里的现有 `run.log` 还没有这部分证据，所以不能把它写成“已经自动拿到宿主机进程控制”。

## 8. 参考

- https://man7.org/linux/man-pages/man2/ptrace.2.html
- https://man7.org/linux/man-pages/man7/capabilities.7.html
- `cves/metarget/writeups_cnv/config-cap_sys_ptrace-container/`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：部署 `hostPID: true` 且添加 `SYS_PTRACE` 的 Pod。
- 当前仓库中已有的证据来自 Docker/Kubernetes 组合环境。
- 统一判定口径：Pod Ready + `CapEff` 可见 + 宿主机进程列表可见。

### 9.2 当前结果摘要

| 观察项 | 结果 |
| --- | --- |
| Pod 创建 | 成功 |
| Pod Ready | 成功 |
| 在线 exec 探针 | 失败，随后切换日志回退 |
| 日志回退取证 | 成功 |
| 最终 verdict | `PROBE_LOG_FALLBACK_OK` |

### 9.3 结论

当前样本已经证明：

- 容器能看到宿主机 PID 空间。
- 高危能力集合已经生效。
- `hostPID + SYS_PTRACE` 这组错误配置确实落地了。

但它目前仍是一份“高危前提验证样本”，不是“自动完成 ptrace 注入并接管宿主机进程”的样本。
