# 滥用 CAP_SYS_ADMIN 导致容器逃逸

## 1. 简介

`CAP_SYS_ADMIN` 常被称为“最接近万能钥匙的 capability”。

原因很简单：它覆盖了大量和挂载、命名空间、系统管理相关的操作。很多本来只有宿主机高权限进程才能做的事，只要容器被授予了 `CAP_SYS_ADMIN`，就可能突然变得可以做。

当前目录里的脚本没有直接自动挂载宿主机根分区并 `chroot` 进去，但它已经验证了一个非常关键的前提：带着 `CAP_SYS_ADMIN` 的容器，能否在容器内完成实际的 `mount` 操作。

## 2. 价值

- 验证平台是否错误地下发了 `CAP_SYS_ADMIN`。
- 帮助初学者理解“为什么能 mount”本身就已经是高度危险信号。
- 为后续 hostPath、块设备挂载、`chroot` 等完整逃逸链提供前置证据。

## 3. 作用机理

理解这个场景，可以先抓住一句话：很多容器逃逸并不是“靠内核 0day 突破”，而是“平台先把门钥匙递给了容器”。

`CAP_SYS_ADMIN` 就是这样一把门钥匙。

### 第一步：危险配置写在 `scene.yaml` 里

风险的根源是 Pod 定义中的这段内容：

```yaml
# scene.yaml
spec:
  containers:
  - name: ubuntu
    securityContext:
      capabilities:
        add: ["SYS_ADMIN"]

# 注释：这里把 SYS_ADMIN 加给了容器
# 它不是一个小能力，而是一大批系统管理类操作的入口
```

一旦这把 capability 生效，容器就可能具备挂载文件系统、配合宿主机资源入口进一步突破边界的能力。

### 第二步：脚本先把场景部署起来，再确认容器真的运行了

`run_poc.sh` 的主流程很直接：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

这一步是在确认：

- 带 `SYS_ADMIN` 的 Pod 不是停留在 YAML 里，而是已经变成了真实运行中的容器。

### 第三步：真正的关键探针，是在容器内尝试一次 `mount tmpfs`

这是这份脚本里最值得看的代码：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" \
  'id; grep CapEff /proc/1/status; mkdir -p /tmp/mt_test && mount -t tmpfs tmpfs /tmp/mt_test && echo "[+] mount tmpfs success" && umount /tmp/mt_test'

# 注释 1：先看身份和能力位
# 注释 2：再实际尝试 mount tmpfs
# 注释 3：如果 mount 成功，就说明这个容器确实具备了高危的挂载能力，而不是只在配置文件里“看起来有权限”
```

为什么这里选 `tmpfs`？

因为它足够简单：

- 不需要额外块设备。
- 能直接验证挂载操作是否被允许。
- 对教学来说很直观，成功与失败一眼就能看出来。

### 第四步：为什么“能 mount”就已经很危险

因为挂载能力本身就是后续很多逃逸动作的跳板。

典型思路包括：

1. 挂载宿主机目录或设备。
2. 访问宿主机文件系统中的敏感内容。
3. 进一步 `chroot` 到宿主机根目录。
4. 把“容器里的高权限”转化成“宿主机文件系统视角下的高权限”。

所以当前脚本虽然只演示了一个 `mount tmpfs`，但它要说明的是：这把能力钥匙已经能转动锁芯了。

### artifacts 运行证据

当前 artifacts 给出的证据非常清楚：

```text
# artifacts/repro/docker/config-cap_sys_admin-container/run.log
pod/cap-sys-admin-container created
pod/cap-sys-admin-container condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
CapEff: 00000000a82425fb
[+] mount tmpfs success
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
[*] 可继续按业务场景挂载宿主机目录并执行 chroot。

# 注释 1：CapEff 说明高危 capability 已经生效
# 注释 2：[+] mount tmpfs success 是当前脚本最关键的“机理印证”
# 注释 3：这说明容器不是“理论上可能有权限”，而是真的已经能执行挂载动作
```

这次运行同样是在线 `exec` 探针失败后，转用启动日志回退取证：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

但只要后面拿到了 `mount tmpfs success`，证据仍然成立。

## 4. 关键节点分析

1. 风险根源是 `SYS_ADMIN` 被下发给容器。
2. 当前脚本的核心证据不是 `CapEff`，而是“实际 mount 成功”。
3. 只要能稳定 mount，后续就可以沿着 hostPath、设备挂载、`chroot` 等方向继续扩展。
4. 这类问题往往是配置错误，不需要复杂漏洞链也可能打穿边界。

## 5. 目录结构

```text
config-cap_sys_admin-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先准备可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/config-cap_sys_admin-container/run_poc.sh
```

清理：

```bash
bash cves/config-cap_sys_admin-container/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# 集群 API 不可达，场景还没部署成功

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没 ready，危险 capability 还没真正生效在运行容器里

情况 3：exec probe failed, attempting startup-log fallback
# 在线 exec 失败，不等于验证失败
# 只要回退日志里仍然出现 [+] mount tmpfs success，就说明关键证据已经拿到
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

这里同样要区分“当前脚本验证成功”与“最终挂载宿主机并 chroot 成功”。

当前 `run_poc.sh` 负责的是前者。

### 真正命中当前脚本要验证的目标

下面这些条件同时出现，就说明当前脚本的目标已经命中：

1. Pod 创建并 Ready。
2. 日志里出现 `CapEff:`。
3. 日志里出现：

```text
[+] mount tmpfs success
```

4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这代表：

- 容器确实拿到了高危 capability。
- 更重要的是，容器已经真的完成了一个挂载动作。

### 只到中间阶段 / 部分命中

如果出现：

```text
K8S_LOG_PROBE_BEGIN
CapEff: ...
[-] mount tmpfs failed
```

那么说明 capability 可能已下发，但当前运行环境仍然把实际挂载动作挡住了。这可以算“碰到关键前提，但没拿到完整机理证据”。

当前仓库里的现成日志不是这种情况，而是更强的 `mount tmpfs success`。

### 前置失败 / 明确阻断

以下情况属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

它们只能说明环境没准备好，不能说明 `CAP_SYS_ADMIN` 是安全的。

### 如果要算“最终逃逸成功”，还差什么

至少还要补：

1. 可被容器挂载的宿主机目录或设备入口。
2. 成功挂载宿主机资源。
3. 最终 `chroot` 到宿主机文件系统并观察到宿主机视角结果。

当前仓库日志还没有这些后续证据，所以不能直接写成“已经自动完成宿主机逃逸”。

## 8. 参考

- https://man7.org/linux/man-pages/man7/capabilities.7.html
- `cves/metarget/writeups_cnv/config-cap_sys_admin-container/`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：部署带 `SYS_ADMIN` 的 Pod。
- 当前仓库已有证据来自 Docker/Kubernetes 组合环境。
- 统一判定口径：Pod Ready + `mount tmpfs success` + `PROBE_LOG_FALLBACK_OK`。

### 9.2 当前结果摘要

| 观察项 | 结果 |
| --- | --- |
| Pod 创建 | 成功 |
| Pod Ready | 成功 |
| 在线 exec 探针 | 失败，随后切换日志回退 |
| 回退日志取证 | 成功 |
| `mount tmpfs` | 成功 |
| 最终 verdict | `PROBE_LOG_FALLBACK_OK` |

### 9.3 结论

当前样本已经证明：

- `CAP_SYS_ADMIN` 确实进入了容器。
- 容器已经具备真实挂载能力。
- 这足以说明该配置具备继续向宿主机文件系统逃逸延伸的高风险。
