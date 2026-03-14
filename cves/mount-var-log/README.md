# 挂载 /var/log 导致容器逃逸

## 1. 简介

这个场景不是单一漏洞，而是一条“错误配置组合链”：

- Pod 以可写方式挂载宿主机 `/var/log`
- ServiceAccount 又拿到了 `nodes/log` 相关读取权限

这两个条件叠在一起，就可能把一个普通容器变成“能借 kubelet 日志读取路径去碰宿主机文件”的攻击起点。公开 writeup 里常见的思路，是在 `/var/log` 下面构造符号链接，再用专门工具去读本来不该暴露的宿主机文件。

当前目录里的脚本主要负责验证：

- 这条危险配置链有没有真的落地。
- 容器里是否具备继续执行 writeup 中 `lsh/cath` 路线的前提。

## 2. 价值

- 验证 `hostPath + RBAC` 的组合是否形成危险攻击面。
- 帮助初学者理解“权限看起来不高的两个点，组合起来为什么会变危险”。
- 让文档能明确区分“场景已经搭起来”与“已经成功读到宿主机文件”。

## 3. 作用机理

这个场景最容易让人误判的地方是：单看“挂了 `/var/log`”或者“多了一条 RBAC 权限”，都不一定显得特别危险；但把它们组合起来，风险会突然放大。

### 第一步：危险不只在 Pod 上，还在 RBAC 上

`scene.yaml` 里首先创建了一个能读 `nodes/log` 的 ServiceAccount：

```yaml
# scene.yaml
kind: ClusterRole
rules:
- apiGroups: [""]
  resources:
  - nodes/log
  verbs: ["get", "list", "watch"]

# 注释：这一段的意义是，Pod 里用的身份不只是普通业务账号
# 它额外具备了访问节点日志接口的能力
```

然后 Pod 本身又把宿主机 `/var/log` 挂进了容器：

```yaml
# scene.yaml
spec:
  serviceAccountName: logger
  containers:
  - name: escaper
    volumeMounts:
    - name: logs
      mountPath: /var/log/host
  volumes:
  - name: logs
    hostPath:
      path: /var/log/
      type: Directory

# 注释：这里把宿主机日志目录暴露给了容器
# 如果攻击者能在这里制造符号链接，再结合 nodes/log 读取链，就有机会让读取目标偏离到宿主机其他文件
```

### 第二步：脚本先确认这条组合链已经真实落地

`run_poc.sh` 先部署资源并等待 Pod Ready：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

这里的重点是：

- 不是只看 Pod 起没起，而是看“带 RBAC + hostPath 组合的完整场景”有没有跑起来。

### 第三步：当前脚本不直接做文件读取，而是检查 `lsh/cath` 这条利用链能不能继续走

脚本真正执行的探针是：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" \
  'id; (command -v lsh >/dev/null 2>&1 && lsh / | head || echo "lsh not found"); (command -v cath >/dev/null 2>&1 && cath /etc/hostname || echo "cath not found")'

# 注释 1：lsh / head 对应 writeup 里的目录枚举工具
# 注释 2：cath /etc/hostname 对应 writeup 里的文件读取工具
# 注释 3：如果镜像里没有这两个工具，脚本就会明确打印 not found，而不是假装已经读到了宿主机文件
```

这一步很关键，因为它决定了 README 应该怎么写。

- 如果 `lsh/cath` 真跑起来并读到了文件，那可以写“利用链已进一步推进”。
- 如果像当前样本一样工具根本不在镜像里，就只能写“场景已部署，利用工具链尚未进镜像”。

### 第四步：为什么 `/var/log` 会和“读宿主机其他文件”扯上关系

因为公开利用思路依赖的是：

1. 容器能写宿主机 `/var/log`。
2. 攻击者在日志目录里构造特殊路径或符号链接。
3. kubelet/日志读取接口后续沿着这个路径去读文件。
4. 结果就可能从“读日志”偏离成“读宿主机别的文件”。

所以这个场景的本质是“路径和身份的组合滥用”，而不是单纯的目录挂载问题。

### artifacts 运行证据

当前日志非常适合说明：场景已经部署成功，但 writeup 里真正用来读文件的工具并没有进入镜像。

```text
# artifacts/repro/docker/mount-var-log/run.log
serviceaccount/logger created
clusterrole.rbac.authorization.k8s.io/user-log-reader created
clusterrolebinding.rbac.authorization.k8s.io/user-log-reader created
pod/mount-var-log created
pod/mount-var-log condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
lsh not found
cath not found
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
[*] writeup 中通过 lsh/cath 可读取宿主机文件。

# 注释 1：RBAC、ServiceAccount、Pod 都已经创建成功，说明危险组合场景已经落地
# 注释 2：lsh not found / cath not found 说明当前镜像里并没有把利用工具链带进去
# 注释 3：所以这次运行能证明“场景准备完成”，但不能证明“已经读到了宿主机文件”
```

这次同样发生了在线 `exec` 失败后回退到启动日志：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

因此当前 artifacts 的有效结论是：

- 场景落地了。
- 工具链缺失导致完整读取动作没有继续执行。

## 4. 关键节点分析

1. 风险不是来自单一组件，而是 `hostPath /var/log + nodes/log RBAC` 的组合。
2. 当前脚本最重要的价值，是把“场景已落地”和“利用工具缺失”分开写清楚。
3. `lsh not found` / `cath not found` 是当前样本的核心事实，不能被写成已经读取成功。
4. 如果后续把 writeup 所需工具放进镜像，这条链才会继续向宿主机文件读取推进。

## 5. 目录结构

```text
mount-var-log/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先准备可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/mount-var-log/run_poc.sh
```

清理：

```bash
bash cves/mount-var-log/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# 集群 API 不可达，组合场景还没部署成功

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没 ready，利用链的执行载体还没真正起来

情况 3：日志里出现 lsh not found / cath not found
# 这不是脚本失败，而是当前镜像没有内置 writeup 依赖的工具
# 这种情况下只能把结论写成“场景已落地，利用工具链未进入镜像”
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

### 真正命中当前脚本要验证的目标

对这份脚本来说，下面这些条件同时出现，就说明当前验证目标已经命中：

1. ServiceAccount、ClusterRole、ClusterRoleBinding、Pod 都创建成功。
2. Pod Ready。
3. 出现 `K8S_LOG_PROBE_OK`。
4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这代表：

- 危险配置组合已经真实落地。
- 当前脚本的场景验证已经完成。

### 只到中间阶段 / 部分命中

当前仓库里的样本就是典型的“部分命中”：

```text
lsh not found
cath not found
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这说明：

- 场景本身已经搭起来了。
- 但 writeup 依赖的利用工具不在镜像里，所以没有继续走到“读取宿主机文件”那一步。

### 前置失败 / 明确阻断

以下情况属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

这些都只能说明环境没准备好，不能说明这条配置链是安全的。

### 如果要算“最终逃逸成功”，还差什么

至少还要补：

1. 将 `lsh/cath` 或等效工具带入镜像。
2. 在 `/var/log/host` 下构造 writeup 所需的路径/符号链接。
3. 观察到宿主机文件被实际读出。

当前仓库里的现有日志还没有这些证据，所以不能写成“已成功读取宿主机文件”。

## 8. 参考

- https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts
- https://github.com/danielsagi/kube-pod-escape
- `cves/metarget/writeups_cnv/mount-var-log/README.md`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：部署可写 `/var/log` 挂载 + `nodes/log` RBAC 的 Pod。
- 当前仓库已有证据来自 Docker/Kubernetes 组合环境。
- 统一判定口径：资源创建成功 + Pod Ready + `PROBE_LOG_FALLBACK_OK` + 工具链状态可见。

### 9.2 当前结果摘要

| 观察项 | 结果 |
| --- | --- |
| ServiceAccount / RBAC / Pod 创建 | 成功 |
| Pod Ready | 成功 |
| 在线 exec 探针 | 失败，随后切换日志回退 |
| 回退日志取证 | 成功 |
| `lsh` | 未找到 |
| `cath` | 未找到 |
| 最终 verdict | `PROBE_LOG_FALLBACK_OK` |

### 9.3 结论

当前样本已经证明：

- `hostPath + RBAC` 的危险组合链已经落地。
- 但镜像中缺少 writeup 所需工具，所以完整利用链没有继续推进。

因此它应被写成“场景已就绪、利用工具缺失”的样本，而不是“已成功读取宿主机文件”的样本。
