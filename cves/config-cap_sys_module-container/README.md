# 滥用 CAP_SYS_MODULE 导致容器逃逸

## 1. 简介

`CAP_SYS_MODULE` 是一类非常危险的 capability，因为它对应的是“加载内核模块”的能力。

容器和宿主机共享同一个 Linux 内核，所以一旦容器真的能把模块装进内核，代码执行位置就不再是容器用户态，而是直接到了宿主机内核态。到了这一步，容器边界基本已经失去意义。

当前目录里的脚本没有自动去编译和加载恶意 `.ko` 模块，但它已经做了一件非常关键的事：验证这个危险 capability 是否真的进入了容器，以及容器里是否至少能看到常见的模块加载工具入口。

## 2. 价值

- 验证平台是否把 `SYS_MODULE` 这种几乎直接通向内核的能力下发给容器。
- 帮助初学者理解“共享内核”为什么让这类 capability 特别危险。
- 为后续恶意内核模块 PoC 的完整演示准备前置证据。

## 3. 作用机理

这个场景最关键的一点，是不要把“容器里执行命令”和“命令实际作用在哪”混为一谈。

对于 `insmod` / `modprobe` 这种动作来说，虽然命令是在容器里敲的，但目标是宿主机正在运行的同一个内核。

### 第一步：危险配置写在 `scene.yaml` 里

真正引入风险的是下面这段 Pod 配置：

```yaml
# scene.yaml
spec:
  containers:
  - name: ubuntu
    securityContext:
      capabilities:
        add: ["SYS_MODULE"]

# 注释：这里给容器加的不是“多一点权限”，而是“直接碰内核模块系统”的入口
# 如果后续再有可用的 .ko 文件和加载条件，影响面就是宿主机内核本身
```

### 第二步：先让带危险 capability 的 Pod 真正跑起来

脚本先部署并等待 Pod Ready：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

只有在 Pod 真实运行后，后面的 capability 和工具探针才有意义。

### 第三步：当前脚本验证的是“能力是否已下发”和“工具链入口是否可见”

Pod Ready 后，脚本会运行：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" \
  'id; grep CapEff /proc/1/status; (command -v insmod || true); (command -v modprobe || true)'

# 注释 1：CapEff 用来确认 capability 是否真的生效
# 注释 2：insmod / modprobe 用来确认容器里有没有常见的模块加载工具入口
```

这里为什么只检查工具而不直接 `insmod evil.ko`？

因为完整利用还取决于很多额外条件：

- 有没有恶意 `.ko` 文件。
- 内核是否开启模块签名强制。
- 主机是否处于 kernel lockdown 等防护模式。

所以当前脚本先停在“危险前提是否成立”这一层，是更稳妥也更容易教学的做法。

### 第四步：为什么这类能力一旦可用，后果会比普通文件读写更严重

因为内核模块不是普通程序。

如果恶意模块真的被装进内核，攻击者可以获得的能力通常会远超过用户态提权，包括但不限于：

1. 直接操作内核对象。
2. 隐藏进程或文件。
3. 改写安全检查逻辑。
4. 在宿主机内核态长时间驻留。

所以这类场景的危险点不是“容器里多了一个命令”，而是“容器被给了一个可能直接修改宿主机内核行为的入口”。

### artifacts 运行证据

当前仓库里的日志表明：脚本已经成功把这个危险能力对应的探针跑起来，但还没有进入真正的恶意模块加载阶段。

```text
# artifacts/repro/docker/config-cap_sys_module-container/run.log
pod/cap-sys-module-container created
pod/cap-sys-module-container condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
CapEff: 00000000a80525fb
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
[*] 完整利用需要自定义恶意内核模块(.ko)并在容器中加载。

# 注释 1：CapEff 说明危险 capability 已经进了容器
# 注释 2：当前日志没有出现“模块加载成功”，因为脚本本来就没有自动执行这一步
# 注释 3：这是一份“前提验证成功”的样本，不是“宿主机内核已被模块接管”的样本
```

和前几个 Kubernetes 场景一样，这次也是在线 `exec` 失败后回退到启动日志：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

只要后续的 `K8S_LOG_PROBE_BEGIN` / `K8S_LOG_PROBE_OK` 和 `CapEff` 还在，证据仍然有效。

## 4. 关键节点分析

1. `SYS_MODULE` 的风险级别很高，因为它直接面向共享内核。
2. 当前脚本验证的是 capability 生效和工具入口存在，不是最终模块加载成功。
3. 即使当前没自动加载 `.ko`，只要 capability 已被下发，风险就已经非常高。
4. 这类场景最终能否完整命中，还会受到模块签名、lockdown 等宿主机防护影响。

## 5. 目录结构

```text
config-cap_sys_module-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先准备可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/config-cap_sys_module-container/run_poc.sh
```

清理：

```bash
bash cves/config-cap_sys_module-container/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# 集群 API 不可达，场景还没部署成功

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没 ready，危险 capability 还没真正进入运行容器

情况 3：exec probe failed, attempting startup-log fallback
# 在线 exec 失败不等于验证失败
# 只要后面仍出现 CapEff 和 K8S_LOG_PROBE_OK，当前脚本的证据就还是成立的
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

### 真正命中当前脚本要验证的目标

下面这些条件同时出现，就说明当前脚本的目标已经命中：

1. Pod 创建并 Ready。
2. 日志里出现 `CapEff:`。
3. 日志里出现 `K8S_LOG_PROBE_OK`。
4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这说明：

- 高危 capability 已经真实进入容器。
- 当前脚本的前提验证已经完成。

### 只到中间阶段 / 部分命中

如果日志里能看到 Pod Ready，但没有拿到 `CapEff` 或探针输出不完整，那就只能算“场景起了，但关键证据不足”。

当前仓库已有样本比这更强，因为它至少拿到了 `CapEff` 和完整的回退日志。

### 前置失败 / 明确阻断

以下情况属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

这些都不能用来证明 `CAP_SYS_MODULE` 是安全配置。

### 如果要算“最终逃逸成功”，还差什么

至少还要补：

1. 一份可加载的恶意 `.ko` 模块。
2. 模块加载动作本身的成功日志。
3. 宿主机内核态效果的实际证据。

当前仓库的现有日志没有这些部分，所以不能写成“已自动加载恶意模块并接管内核”。

## 8. 参考

- https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd
- `cves/metarget/writeups_cnv/config-cap_sys_module-container/README.md`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：部署带 `SYS_MODULE` 的 Pod。
- 当前仓库已有证据来自 Docker/Kubernetes 组合环境。
- 统一判定口径：Pod Ready + `CapEff` 可见 + `PROBE_LOG_FALLBACK_OK`。

### 9.2 当前结果摘要

| 观察项 | 结果 |
| --- | --- |
| Pod 创建 | 成功 |
| Pod Ready | 成功 |
| 在线 exec 探针 | 失败，随后切换日志回退 |
| 回退日志取证 | 成功 |
| 最终 verdict | `PROBE_LOG_FALLBACK_OK` |

### 9.3 结论

当前样本已经证明：

- `CAP_SYS_MODULE` 确实进入了容器。
- 这个场景具备继续向“恶意内核模块加载”延伸的危险前提。

但它目前仍是一份“高危前提验证样本”，不是“自动完成内核态接管”的样本。
