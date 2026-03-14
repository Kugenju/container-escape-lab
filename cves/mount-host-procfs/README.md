# 挂载宿主机 Procfs 导致容器逃逸

## 1. 简介

这不是单一 CVE，而是一类高危错误配置：把宿主机的 `/proc` 挂进容器。

`/proc` 不是普通目录，它更像 Linux 内核和进程状态的“实时控制面板”。如果把宿主机 `/proc` 暴露给容器，攻击者看到的就不再只是容器自己的进程和内核参数，而是宿主机那一套真实状态。再往前走一步，如果容器还能写关键节点，比如 `/proc/sys/kernel/core_pattern`，那就有机会把容器内的操作转化成宿主机命令执行。

当前目录里的脚本主要负责两件事：

- 部署这个错误配置场景。
- 证明容器里确实看到了宿主机 `/proc` 的内容。

它不是一份“自动完成最终逃逸”的脚本，而是一份“把危险前提证据跑出来”的脚本。

## 2. 价值

- 验证 Kubernetes `hostPath` 把宿主机 `/proc` 暴露给容器时，边界是否已经明显松动。
- 帮助初学者理解“为什么一个目录挂载也可能变成逃逸前提”。
- 为后续 `core_pattern` 劫持、宿主机崩溃触发等完整利用链准备可复核证据。

## 3. 作用机理

理解这个场景，最重要的是先记住一句话：`/proc` 不是普通数据目录，而是内核和进程的接口。

所以问题不在“容器多看到了几个文件”，而在“容器开始直接接触宿主机内核参数和宿主机进程世界”。

### 第一步：错误配置发生在 `scene.yaml`，不是发生在脚本输出里

真正把风险引进来的，是下面这段 Pod 配置：

```yaml
# scene.yaml
spec:
  containers:
  - name: ubuntu
    volumeMounts:
    - name: host-procfs
      mountPath: /host-proc
  volumes:
  - name: host-procfs
    hostPath:
      path: /proc

# 注释：这里把宿主机 /proc 原样挂进了容器的 /host-proc
# 容器后面读到的 /host-proc/sys/kernel/core_pattern，不是“容器自己的参数”，而是宿主机的参数
```

这一步本身就已经很危险，因为 `/proc/sys` 下面有大量内核参数，很多参数一旦可写，就不仅仅是“看一眼信息”这么简单了。

### 第二步：`run_poc.sh` 只是负责把这个场景部署起来

脚本最核心的动作其实很少：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

可以把它理解成：

1. 先把错误配置 Pod 真正创建出来。
2. 等待这个 Pod 进入可运行状态。
3. 如果 Pod 都起不来，说明危险前提还没有成立，脚本就直接停止。

### 第三步：真正的“印证动作”是去容器里读取宿主机 `/proc`

Pod 就绪后，脚本会调用公共探针，在容器里执行下面这组命令：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" \
  'id; cat /host-proc/sys/kernel/core_pattern || true; ls /host-proc | head'

# 注释：这里不是在读容器自己的 /proc
# 而是在读 hostPath 挂进去的 /host-proc，也就是宿主机 /proc
```

这里面三条命令分别在证明三件事：

- `id`：说明当前探测进程在容器里是以什么身份运行。
- `cat /host-proc/sys/kernel/core_pattern`：证明容器已经能直接读到宿主机内核参数。
- `ls /host-proc | head`：证明这不是一个空挂载，而是真正的宿主机 procfs 视图。

### 第四步：为什么读到 `core_pattern` 会让人紧张

`core_pattern` 可以简单理解成“系统发生崩溃转储时，核心文件怎么处理”。
如果这个值被改成一条管道命令，例如把崩溃数据送进某个程序，那么宿主机后续在处理崩溃时，就可能去执行攻击者指定的路径。

所以这个场景的危险链是：

1. 容器先通过 `hostPath` 看到了宿主机 `/proc`。
2. 如果权限继续放大，容器就可能改写 `/host-proc/sys/kernel/core_pattern`。
3. 一旦宿主机后续出现崩溃处理动作，就可能把“一个内核参数修改”变成“宿主机执行攻击者脚本”。

当前脚本只做到第 1 步和第 2 步的“可见性证明”，没有自动去做第 3 步和第 4 步的完整利用。

### artifacts 运行证据

当前日志非常适合拿来说明“危险前提已经成立，但最终逃逸没有在脚本里自动完成”。

```text
# artifacts/repro/docker/mount-host-procfs/run.log
pod/mount-host-procfs created
pod/mount-host-procfs condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d
1
1319
1337
1375
...
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
[*] 完整逃逸可结合 core_pattern + 崩溃触发执行宿主机路径脚本。

# 注释 1：这里的 core_pattern 值已经被容器读到了
# 注释 2：后面的数字来自 ls /host-proc | head，说明 /host-proc 里确实有宿主机进程目录
# 注释 3：Verdict 是 PROBE_LOG_FALLBACK_OK，表示“探针证据拿到了”，不是“宿主机代码执行已经发生”
```

这次运行里还有一个细节值得说明：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

这说明 `kubectl exec` 探针当时因为运行时执行路径异常而失败了，但脚本没有直接放弃，而是改用容器启动日志中的 `K8S_LOG_PROBE_BEGIN` 到 `K8S_LOG_PROBE_OK` 这段内容做回退取证。

也就是说，当前 artifacts 依然是有效证据，只是证据来源从“在线 exec”切换成了“启动日志回退”。

## 4. 关键节点分析

1. 真正危险的源头是 `scene.yaml` 里的 `hostPath: /proc`，不是脚本本身。
2. `run_poc.sh` 负责把错误配置落地，并验证容器能否读到宿主机 `/proc`。
3. `core_pattern` 是后续最典型的利用支点，因为它可能把一次参数修改放大成宿主机命令执行。
4. 当前 PoC 是“风险前提验证”型样本，不是“自动拿宿主机 shell”型样本。

## 5. 目录结构

```text
mount-host-procfs/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先准备一个可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/mount-host-procfs/run_poc.sh
```

清理：

```bash
bash cves/mount-host-procfs/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# Kubernetes API 不可达，场景还没部署成功

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没准备好，错误配置没有真正落地到可运行状态

情况 3：exec probe failed, attempting startup-log fallback
# 这不等于失败，只是在线 exec 没拿到结果，脚本改用容器启动日志取证
# 如果后面仍然出现 K8S_LOG_PROBE_BEGIN / K8S_LOG_PROBE_OK，就说明证据依然有效
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

这份 README 里要特别区分两种“成功”：

- 场景成功搭起来。
- 最终逃逸真的发生。

当前 `run_poc.sh` 实际验证的是第一种，不是第二种。

### 真正命中当前脚本要验证的目标

只要同时满足下面几点，就说明“挂载宿主机 procfs 这个危险前提”已经被成功证实：

1. Pod 创建并 Ready。
2. 日志里出现 `K8S_LOG_PROBE_BEGIN` 和 `K8S_LOG_PROBE_OK`。
3. 日志里能看到 `core_pattern` 的实际内容，以及 `/host-proc` 的目录项。
4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

注意，这里的“命中”指的是：

- 错误配置已经生效。
- 容器确实能看到宿主机 `/proc`。

而不是“宿主机命令已经被自动执行”。

### 只到中间阶段 / 部分命中

下面这种情况说明场景部署成功了，但取证路径有波动：

```text
error: Internal error occurred: error executing command in container: ...
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
...
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这类结果依然可以算当前脚本的有效命中，因为回退日志已经把核心证据补齐了。

### 前置失败 / 明确阻断

以下情况属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

这些都只能说明环境没有准备好，不能说明这个错误配置本身不危险。

### 如果要算“最终逃逸成功”，还差什么

对于这个场景，真正的完整逃逸至少还要补上：

1. 容器对 `/host-proc/sys/kernel/core_pattern` 的可写能力。
2. 一个会在宿主机路径上被执行的脚本或程序。
3. 一次能触发宿主机崩溃处理逻辑的动作。
4. 最终观察到宿主机执行了该路径。

当前仓库的现有 artifacts 还没有走到这一步，所以不能写成“已自动复现宿主机命令执行”。

## 8. 参考

- http://man7.org/linux/man-pages/man5/core.5.html
- `cves/metarget/writeups_cnv/mount-host-procfs/README.md`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：通过 `kubectl apply` 部署 `hostPath: /proc` 的 Pod。
- 当前仓库中的证据主要来自 Docker/Kubernetes 组合环境。
- 统一判定口径：Pod Ready + `core_pattern` 可读 + `/host-proc` 目录内容可见。

### 9.2 当前结果摘要

| 观察项 | 结果 |
| --- | --- |
| Pod 创建 | 成功 |
| Pod Ready | 成功 |
| 在线 exec 探针 | 失败，随后切换日志回退 |
| 启动日志回退取证 | 成功 |
| 最终 verdict | `PROBE_LOG_FALLBACK_OK` |

### 9.3 结论

当前样本已经证明：

- 容器里能看到宿主机 `/proc`。
- 宿主机 `core_pattern` 已经暴露给容器。
- 这足以说明该错误配置具有明显逃逸风险。

但它目前仍是一份“危险前提验证样本”，不是“自动完成最终宿主机执行”的样本。
