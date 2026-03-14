# 挂载 docker.sock 导致容器逃逸

## 1. 场景简介

该场景不是内核漏洞，而是高危配置错误：将宿主机 Docker Socket（`/var/run/docker.sock`）挂入容器。
任何能访问该 socket 的进程，实质上都可调用 Docker daemon API，获得接近宿主机 root 的控制能力。

本目录内容参考 `cves/metarget/writeups_cnv/mount-docker-sock/README.md`，并重组为脚本化场景。

## 2. 复现该场景的价值

- 验证“容器内有 docker.sock”是否等价于主机接管风险。
- 验证平台对高危挂载（docker.sock）的检测与阻断能力。
- 验证 RBAC/准入策略是否能阻止这类危险 Pod 落地。

## 3. 作用机理（分阶段）

这一篇和前面的 CVE 不一样，它不是“程序里有一个 bug”，而是“配置本身就把宿主机的高权限控制接口送进了容器”。  

这里最该抓住的一句话是：  
`/var/run/docker.sock` 不是一个普通文件，它是宿主机 Docker daemon 的控制入口。谁能和它对话，谁就几乎等于能指挥宿主机 Docker 做事。

### 第一步：场景文件先把危险前提搭好

真正的高危点不在 `run_poc.sh`，而在 [scene.yaml](/root/container-escape-lab/container-escape-lab/cves/mount-docker-sock/scene.yaml)。这个清单里明确写了：

- `hostPath.path: /var/run/docker.sock`
- `mountPath: /var/run/docker.sock`

也就是说，宿主机自己的 Docker socket 被原封不动挂进了 Pod。  
从软件工程视角看，这相当于你本来只想给容器一个业务数据文件，结果却把“宿主机控制台的管理员接口”直接插进了容器里。

场景文件本身就已经把风险写死了：

```yaml
# cves/mount-docker-sock/scene.yaml
volumeMounts:
  - name: docker-sock
    mountPath: /var/run/docker.sock   # 容器里看到的路径

volumes:
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock      # 实际来自宿主机
```

### 第二步：脚本只负责把这个危险场景真正落地

`run_poc.sh` 做的事情其实很朴素：

- `run_poc.sh:16-23` 先确认 `kubectl` 和 Kubernetes API 可用
- `run_poc.sh:26-28` 创建命名空间并 `kubectl apply -f "$MANIFEST"`
- `run_poc.sh:30-33` 等待 Pod Ready
- `run_poc.sh:36` 进入容器执行 `id; ls -l /var/run/docker.sock`

这说明这份 PoC 的目标不是“自动把宿主机打下来”，而是先验证最关键的危险前提是否成立：  
容器里到底能不能看到并访问宿主机的 Docker socket。

脚本主体其实很短：

```bash
# run_poc.sh:19-36
if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_api_unreachable"
  exit 1
fi

kubectl apply -f "$MANIFEST"

if ! kubectl wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=120s; then
  echo "[*] Verdict: BLOCKED_STAGE=k8s_pod_not_ready"
  exit 1
fi

"$HELPER" "$NAMESPACE" "$POD_NAME" 'id; ls -l /var/run/docker.sock'

# 脚本的重点不是自动利用，而是确认危险 Pod 已经落地，并尝试在容器里看到 docker.sock
```

### 第三步：为什么看到 docker.sock 就已经很危险

很多初学者会问：只是看到一个 socket 文件，为什么就能叫“容器逃逸风险”？  

原因是 Docker daemon 本身运行在宿主机高权限上下文。只要容器里的进程能调用这个 daemon，就可以请求它：

- 启动一个新的特权容器
- 挂载宿主机 `/`
- 进入宿主机命名空间
- 读写宿主机文件系统

也就是说，真正危险的不是“这个 Pod 现在做了什么”，而是“它已经拿到了向宿主机管理员发命令的电话线”。

### 第四步：这份脚本的证据链要分成“场景成立”和“完全利用”两层看

这份目录里的脚本目前停在“场景成立”的验证层面。它没有继续自动安装 Docker 客户端，也没有自动新起一个特权容器去挂 `/`。  

所以你在读结果时要分两层：

- 第一层：Pod 是否成功创建，容器内探针是否能跑
- 第二层：容器里是否真的能看到并进一步使用 `docker.sock`

对教学来说，这样分层反而更清楚。因为它把“危险前提成立”与“后续怎么扩展成完整逃逸”拆开了。

### artifacts 对应证据（建议这样读）

- `artifacts/repro/docker/mount-docker-sock/run.log:3-4` 先证明 Pod 已经创建并进入 Ready 状态。
- `artifacts/repro/docker/mount-docker-sock/run.log:7-10` 的 `K8S_LOG_PROBE_BEGIN`、`uid=0(root)`、`K8S_LOG_PROBE_OK` 说明容器内探针确实执行过，至少场景已经成功落地。
- `artifacts/repro/docker/mount-docker-sock/run.log:11` 给出 `Verdict: PROBE_LOG_FALLBACK_OK`，表示这次归档保留的是 fallback 证据链。
- 需要注意：这份已归档日志里没有完整保留 `ls -l /var/run/docker.sock` 的直接输出，所以它更适合证明“危险 Pod 已经起来并且探针执行成功”，而不是证明“完整逃逸已经自动完成”。

当前归档下来的日志长这样：

```text
# artifacts/repro/docker/mount-docker-sock/run.log
pod/mount-docker-sock created
pod/mount-docker-sock condition met
[*] Exec probe failed, attempting startup-log fallback...
K8S_LOG_PROBE_BEGIN
uid=0(root) gid=0(root) groups=0(root)
K8S_LOG_PROBE_OK
[*] Verdict: PROBE_LOG_FALLBACK_OK

# 这能证明：危险 Pod 已经创建成功，容器内探针也确实跑起来了
# 但这份归档没有完整保留 docker.sock 的 ls 输出，所以这里只能判定“场景成立”
```

## 4. 容器逃逸关键节点分析

1. 关键前提是 docker.sock 被暴露给不可信容器。
2. Docker daemon 充当高权限控制面，被低信任工作负载间接调用。
3. `--privileged` 与主机目录挂载把“容器权限”转化为“宿主机权限”。
4. 该类风险通常与业务镜像漏洞无关，根因是运行时配置错误。

## 5. 目录结构

```text
mount-docker-sock/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 主要部署场景并检查 socket 是否暴露；完整逃逸步骤可在容器内安装 docker 客户端后手工触发。

## 7. 可直接复现步骤与故障排查

```bash
bash run_poc.sh
```

预期：Pod 成功创建并 Ready；如果 `exec` 探针失败，日志里至少会保留 fallback 取证结果，例如 `K8S_LOG_PROBE_BEGIN`、`uid=0(root)`、`K8S_LOG_PROBE_OK`。

建议先核对场景文件，再执行：

```bash
sed -n '1,80p' cves/mount-docker-sock/scene.yaml
bash cves/mount-docker-sock/run_poc.sh
```

如果你要清理场景：

```bash
bash cves/mount-docker-sock/run_poc.sh --cleanup
```

常见故障：

- `BLOCKED_STAGE=k8s_api_unreachable`
  处理：先确认当前 `kubectl` 已连接到正确集群，例如切到实验用的 `k8s-kind` profile。
- `BLOCKED_STAGE=k8s_pod_not_ready`
  处理：优先看 `kubectl describe pod mount-docker-sock -n metarget`，确认镜像拉取、节点状态和 hostPath 挂载是否正常。
- `Exec probe failed, attempting startup-log fallback...`
  处理：这不代表场景一定失败，只表示这次改用容器启动日志取证；应继续看后面的 `K8S_LOG_PROBE_*` 与 `Verdict`。


## 成功判定（结合 run_poc.sh 与 artifacts）

这篇目录最好分两层判定，不然很容易把“高危场景已成立”和“完整逃逸已自动完成”混为一谈。

### 第一层：高危场景是否已经成立

下面这些现象出现，就可以判定“docker.sock 暴露场景成立”：

1. `run_poc.sh:28` 成功把 Pod 创建出来。
2. `run_poc.sh:30-33` 没有停在 `BLOCKED_STAGE=k8s_pod_not_ready`。
3. `run_poc.sh:36` 的探针能够进入容器执行，或者至少从容器日志 fallback 拿到有效输出。

对这个目录来说，这一层其实就是最重要的判定，因为一旦 docker.sock 真的暴露给了不可信容器，后续的宿主机控制已经是顺理成章的扩展步骤。

### 第二层：是否已经拿到“直接证据”

更强的证据通常是下面两类：

1. 容器里直接看到 `ls -l /var/run/docker.sock` 的输出。
2. 后续手工用 Docker API 或 Docker CLI 成功启动一个挂宿主机根目录的特权容器。

当前仓库里保存下来的 artifacts 主要覆盖到了第一层，并没有把第二层完整自动化保留下来。

### 什么情况算阻断

- `run_poc.sh:19-23` 输出 `BLOCKED_STAGE=k8s_api_unreachable`，说明 Kubernetes API 没通。
- `run_poc.sh:30-33` 输出 `BLOCKED_STAGE=k8s_pod_not_ready`，说明危险 Pod 根本没跑起来。
- 如果 Pod 起了，但探针也拿不到有效输出，那么只能说明这次取证不完整，不能直接写成“场景不存在”。

### artifacts 运行证据

- Pod 已创建：`artifacts/repro/docker/mount-docker-sock/run.log:3`
- Pod 已 Ready：`artifacts/repro/docker/mount-docker-sock/run.log:4`
- 容器内探针开始执行：`artifacts/repro/docker/mount-docker-sock/run.log:7`
- 探针执行身份：`artifacts/repro/docker/mount-docker-sock/run.log:8`
- 当前归档结论：`artifacts/repro/docker/mount-docker-sock/run.log:11`

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://mp.weixin.qq.com/s/_GwGS0cVRmuWEetwMesauQ
- cves/metarget/writeups_cnv/mount-docker-sock/README.md
