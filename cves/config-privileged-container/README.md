# 特权容器导致容器逃逸

## 1. 简介

`privileged: true` 往往可以把容器的隔离边界削弱到非常危险的程度。

直观理解是：普通容器像是“借住在宿主机里的租客”，还有很多门被锁着；而特权容器更像是“被直接给了一大串万能钥匙的人”，设备访问、系统管理、很多安全限制都会被大幅放宽。

当前目录里的脚本没有自动替你挂载宿主机磁盘并 `chroot` 进去，但它已经验证了这类场景最关键的前提之一：特权容器里是否能直接看到宿主机块设备信息。

## 2. 价值

- 验证平台是否允许 `privileged: true` 工作负载上线。
- 帮助初学者理解“看到宿主机磁盘设备”为什么已经是重大风险信号。
- 为后续挂载宿主机分区、`chroot` 到宿主机文件系统等完整逃逸链准备证据。

## 3. 作用机理

这个场景最容易理解的方式，是把它看成“容器的安全围栏被整体拆掉了一大半”。

普通容器通常看不到太多宿主机设备，更别说直接拿这些设备做进一步操作。
而特权容器一旦跑起来，攻击者往往就能直接看到更多 `/dev` 节点，甚至进一步识别宿主机磁盘和分区。

### 第一步：真正的风险在 `scene.yaml` 里

根源是下面这段配置：

```yaml
# scene.yaml
spec:
  containers:
  - name: ubuntu
    securityContext:
      privileged: true

# 注释：这里不是加一个 capability，而是直接把容器切到了“特权模式”
# 对理解来说，可以把它看成“同时打开了很多原本关闭的权限开关”
```

这也是为什么特权容器通常被视为极高风险，而不是“比普通容器多一点权限”而已。

### 第二步：脚本先确认特权 Pod 已经真实运行起来

`run_poc.sh` 先做部署和 Ready 检查：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

只有 Pod 真正运行了，后面的设备可见性探针才有实际意义。

### 第三步：当前脚本的关键验证，是直接看 `/dev` 和 `lsblk`

Pod Ready 后，脚本执行的是：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; ls /dev | head; (lsblk || true)'

# 注释 1：ls /dev | head 用来确认容器内是否能看到大量设备节点
# 注释 2：lsblk 更关键，它会把当前系统能识别到的块设备和分区列出来
# 注释 3：如果容器里能直接看到宿主机磁盘分区，后续挂载和 chroot 的可能性就大大提高了
```

为什么 `lsblk` 很重要？

因为它会把磁盘拓扑直接展示出来。对于攻击者来说，这几乎就是在回答：

- 宿主机有哪些磁盘？
- 哪些分区可能是宿主机根分区？
- 下一步应该尝试挂载哪一个？

### 第四步：为什么“看见宿主机分区”会通向逃逸

典型后续链路通常是：

1. 容器通过特权模式看到宿主机块设备。
2. 挂载某个宿主机分区到容器内目录。
3. `chroot` 到挂载出来的宿主机根目录。
4. 以宿主机文件系统视角执行后续操作。

所以当前脚本虽然只做到“看见设备”，但这一步已经把后续完整逃逸的路线图画出来了。

### artifacts 运行证据

当前日志已经给出非常直观的证据：

```text
# artifacts/repro/docker/config-privileged-container/run.log
pod/privileged-container created
pod/privileged-container condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
autofs
bsg
btrfs-control
bus
cdrom2
core
cpu
cpu_dma_latency
cuse
dm-0
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda      8:0    0   40G  0 disk
|-sda1   8:1    0    1M  0 part
|-sda2   8:2    0    1G  0 part
`-sda3   8:3    0   39G  0 part
sr0     11:0    1  4.7G  0 rom
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
[*] 可按 writeup 挂载宿主机磁盘分区后 chroot 到宿主机文件系统。

# 注释 1：/dev 中出现大量设备节点，说明容器看到的设备面已经很宽
# 注释 2：lsblk 直接列出了 sda、sda1、sda2、sda3，这已经是宿主机块设备视角
# 注释 3：这份证据非常适合说明“完整逃逸前的危险前提已经成立”
```

和前几个 K8s 场景一样，这次也发生了在线 `exec` 失败后回退日志取证：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

但最终关键证据已经在启动日志里完整出现，所以判定仍然有效。

## 4. 关键节点分析

1. `privileged: true` 是风险根源，它不是一个小权限，而是整体弱化隔离。
2. 当前脚本最关键的证据是 `lsblk` 输出，而不是单纯的 `id`。
3. 一旦容器能看到宿主机块设备，后续挂载宿主机分区就有了现实路径。
4. 当前样本证明的是“危险前提已经成立”，不是“自动完成挂载和 chroot”。

## 5. 目录结构

```text
config-privileged-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先准备可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/config-privileged-container/run_poc.sh
```

清理：

```bash
bash cves/config-privileged-container/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# 集群 API 不可达，场景还没部署成功

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没 ready，特权容器还没有真正跑起来

情况 3：exec probe failed, attempting startup-log fallback
# 在线 exec 失败不等于验证失败
# 只要后面还能看到 /dev 节点和 lsblk 输出，当前脚本的关键证据仍然成立
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

这里要区分“当前脚本验证成功”与“最终挂载宿主机分区并 chroot 成功”。

当前 `run_poc.sh` 验证的是前者。

### 真正命中当前脚本要验证的目标

下面这些条件同时出现，就说明当前脚本的目标已经命中：

1. Pod 创建并 Ready。
2. 日志里出现多条 `/dev` 设备节点输出。
3. `lsblk` 输出里能看到像 `sda`、`sda1`、`sda2`、`sda3` 这样的块设备和分区信息。
4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这代表：

- 特权容器已经成功运行。
- 它已经看到了宿主机块设备视角。

### 只到中间阶段 / 部分命中

如果只能看到 Pod Ready，但拿不到设备节点或 `lsblk` 输出不完整，那只能算“场景起了，但危险证据还不够完整”。

当前仓库里的现成 artifacts 比这更强，因为它已经直接列出了 `sda` 及其分区。

### 前置失败 / 明确阻断

以下情况属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

这些都不能说明特权容器是安全的，只能说明环境没准备好。

### 如果要算“最终逃逸成功”，还差什么

至少还要补：

1. 选定正确的宿主机分区。
2. 成功把该分区挂载到容器内目录。
3. `chroot` 到宿主机文件系统。
4. 观察到宿主机视角下的文件或命令执行证据。

当前仓库里的现有日志还没有这些步骤，所以不能写成“已经自动挂载宿主机并完成 chroot 逃逸”。

## 8. 参考

- https://www.docker.com/blog/docker-can-now-run-within-docker/
- https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities
- `cves/metarget/writeups_cnv/config-privileged-container/README.md`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：部署 `privileged: true` 的 Pod。
- 当前仓库已有证据来自 Docker/Kubernetes 组合环境。
- 统一判定口径：Pod Ready + `/dev` 设备节点可见 + `lsblk` 输出可见 + `PROBE_LOG_FALLBACK_OK`。

### 9.2 当前结果摘要

| 观察项 | 结果 |
| --- | --- |
| Pod 创建 | 成功 |
| Pod Ready | 成功 |
| 在线 exec 探针 | 失败，随后切换日志回退 |
| 回退日志取证 | 成功 |
| `/dev` 设备节点 | 可见 |
| `lsblk` 输出 | 可见，包含 `sda/sda1/sda2/sda3` |
| 最终 verdict | `PROBE_LOG_FALLBACK_OK` |

### 9.3 结论

当前样本已经证明：

- 特权容器的高危前提确实已经落地。
- 容器已经看到了宿主机块设备信息。
- 这足以支撑后续“挂载宿主机分区并 `chroot`”的完整逃逸链继续展开。
