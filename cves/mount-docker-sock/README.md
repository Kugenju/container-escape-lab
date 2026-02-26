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

### 阶段 A：容器内进程获得 Docker API 通道

`/var/run/docker.sock` 是 Docker daemon 的 Unix 套接字。
容器挂载该文件后，容器内程序可直接向 daemon 发起管理请求。

### 阶段 B：通过 API 创建具备宿主机访问能力的新容器

攻击者可在容器内使用 docker 客户端（或直接调用 API），
启动一个高权限容器并把宿主机根目录挂载进去（如 `-v /:/host --privileged`）。

### 阶段 C：在新容器中直接读写宿主机文件系统

攻击者进入新容器后可访问 `/host` 下宿主机文件，
可进一步修改系统配置、投递持久化后门，完成容器边界突破。

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

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://mp.weixin.qq.com/s/_GwGS0cVRmuWEetwMesauQ
- cves/metarget/writeups_cnv/mount-docker-sock/README.md
