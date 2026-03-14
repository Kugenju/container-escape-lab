# 滥用 CAP_DAC_READ_SEARCH（Shocker）导致容器逃逸

## 1. 简介

这不是一个内核 CVE，而是一类高危能力配置问题：容器被授予了 `CAP_DAC_READ_SEARCH`。

这个 capability 的危险点在于，它会削弱内核对“目录能不能遍历、文件能不能读取”的常规 DAC（自主访问控制）检查。再配合 `open_by_handle_at()` 这类按文件句柄直接打开对象的接口，攻击者就有机会绕过平时依赖的路径权限限制，去读本来不该被容器读到的宿主机文件。

当前目录里的脚本不是自动把完整 Shocker 利用链跑完，而是先验证一个更基础、也更关键的事实：这个危险 capability 是否真的被下发到容器里。

## 2. 价值

- 验证平台是否误把 `CAP_DAC_READ_SEARCH` 发给业务容器。
- 帮助初学者理解“文件权限检查”为什么不只看 `chmod`，还和 capability 有关。
- 为后续 `open_by_handle_at()` / Shocker PoC 的完整复现准备前置证据。

## 3. 作用机理

这个场景的核心不是“容器突然看到宿主机目录”，而是“容器被给了一把能绕过普通读检查的钥匙”。

平时我们理解文件访问，习惯于看路径和权限位，比如“有没有 `r`、有没有 `x`”。
但如果进程带着 `CAP_DAC_READ_SEARCH`，那么很多基于路径遍历和读权限的拦截就不再可靠了。

### 第一步：危险配置首先写在 `scene.yaml` 里

真正把风险带进来的，是 Pod 的能力配置：

```yaml
# scene.yaml
spec:
  containers:
  - name: ubuntu
    securityContext:
      capabilities:
        add: ["DAC_READ_SEARCH"]

# 注释：这里不是普通 root 权限，而是额外给了一个专门影响文件读取/搜索检查的 capability
# 后续 Shocker 类利用，就是靠这把“绕过常规目录和文件访问检查”的钥匙向前推进
```

如果没有这一行，很多 `open_by_handle_at()` 相关利用会在更前面的权限检查阶段就被内核挡住。

### 第二步：`run_poc.sh` 先确保场景真的跑起来

脚本主体很短，因为它的目标不是完整攻击，而是先把高危前提落地：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

可以把这段理解成：

1. 先把带危险 capability 的 Pod 创建出来。
2. 等它进入 Ready。
3. 如果 Pod 都没跑起来，就还谈不上 capability 已经在真实容器里生效。

### 第三步：探针不直接跑 Shocker，而是先验证 capability 是否真的进了容器

Pod Ready 后，脚本会在容器里执行：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; grep CapEff /proc/1/status'

# 注释 1：id 用来确认当前进程身份
# 注释 2：CapEff 是更关键的证据，它显示当前进程真正生效的 capability 位图
```

这里为什么不直接上 `open_by_handle_at()` PoC？

因为这份脚本的职责是先把“危险前提是否成立”说清楚。

### 第四步：为什么 `CAP_DAC_READ_SEARCH` 会通向 Shocker 类读取宿主机文件

Shocker 这类利用的大致思路可以概括成：

1. 想办法拿到某个文件系统对象的句柄（file handle）。
2. 调用 `open_by_handle_at()`，不再完全依赖常规路径权限检查。
3. 在 `CAP_DAC_READ_SEARCH` 的帮助下，读取本来不该被当前进程读到的宿主机文件。

所以这类场景危险的本质是：

- 容器和宿主机共享同一个内核。
- 一旦 capability 放宽得过头，攻击者就可能利用内核接口绕开“看起来还在”的文件权限边界。

当前脚本没有自动去跑这条完整链，而是停在“高危能力已经下发”的证据层。

### artifacts 运行证据

当前日志很适合说明“危险前提已经被验证，但完整读取宿主机文件的利用没有在脚本里自动执行”。

```text
# artifacts/repro/docker/config-cap_dac_read_search-container/run.log
pod/cap-dac-read-search-container created
pod/cap-dac-read-search-container condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
CapEff: 00000000a80425ff
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
[*] 原始 writeup 的完整逃逸需要 shocker(open_by_handle_at) PoC。

# 注释 1：CapEff 说明 capability 已经真实进入容器进程的有效能力集
# 注释 2：Verdict 是 PROBE_LOG_FALLBACK_OK，表示“危险前提验证成功”，不是“宿主机文件已经被自动读出来”
```

这次运行里，在线 `exec` 探针失败后，脚本回退到了容器启动日志取证：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

但后面仍然拿到了 `K8S_LOG_PROBE_BEGIN` 到 `K8S_LOG_PROBE_OK` 这段完整证据，所以当前 artifacts 仍然是有效的。

## 4. 关键节点分析

1. 风险真正来自 `scene.yaml` 中的 `DAC_READ_SEARCH`，不是来自脚本本身。
2. 当前脚本的目标是证明 capability 生效，而不是自动完成 Shocker 利用。
3. `CapEff` 是判断能力是否真的进了容器的关键证据。
4. 如果后续再补 `open_by_handle_at()` PoC，这份 README 就是它的前置说明书。

## 5. 目录结构

```text
config-cap_dac_read_search-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先准备可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/config-cap_dac_read_search-container/run_poc.sh
```

清理：

```bash
bash cves/config-cap_dac_read_search-container/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# 集群 API 不可达，场景还没有部署成功

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没 ready，危险 capability 还没进入一个真实运行中的容器

情况 3：exec probe failed, attempting startup-log fallback
# 在线 exec 失败，但不等于证据失效
# 如果后面仍然出现 K8S_LOG_PROBE_BEGIN / K8S_LOG_PROBE_OK，就说明日志回退取证成功
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

这里要区分两层“成功”：

- 当前脚本验证成功。
- 完整 Shocker 读取宿主机文件成功。

当前 `run_poc.sh` 只负责第一层。

### 真正命中当前脚本要验证的目标

下面这些条件同时出现，就说明这份 PoC 想验证的危险前提已经成立：

1. Pod 创建并 Ready。
2. 日志里出现 `CapEff:`。
3. 日志里出现 `K8S_LOG_PROBE_OK`。
4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这代表：

- 容器已经带着危险 capability 运行起来了。
- 当前脚本的取证目标已经完成。

### 只到中间阶段 / 部分命中

如果出现下面这种情况：

```text
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
CapEff: ...
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这依然可以算当前脚本的有效命中，只是证据来自回退日志，而不是在线 exec。

### 前置失败 / 明确阻断

以下情况都属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

它们只能说明环境没有准备好，不能说明 `CAP_DAC_READ_SEARCH` 这个配置是安全的。

### 如果要算“完整逃逸成功”，还差什么

对于这个场景，至少还要补：

1. 可工作的 `open_by_handle_at()` / Shocker PoC。
2. 目标文件系统句柄获取过程。
3. 最终读到宿主机敏感文件的实际证据。

当前仓库里的 `run.log` 还没有这些证据，所以不能写成“已经自动读到宿主机敏感文件”。

## 8. 参考

- https://github.com/gabrtv/shocker/blob/master/shocker.c
- https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html
- https://man7.org/linux/man-pages/man7/capabilities.7.html
- `cves/metarget/writeups_cnv/config-cap_dac_read_search-container/README.md`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：部署带 `DAC_READ_SEARCH` 的 Pod。
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

- 容器内危险 capability 已经真实生效。
- 场景具备继续跑 Shocker 类利用的前提。

但它目前仍是一份“高危前提验证样本”，不是“自动完成宿主机文件读取”的样本。
