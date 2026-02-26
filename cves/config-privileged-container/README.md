# 特权容器导致容器逃逸

## 1. 场景简介

该场景不是内核 CVE，而是高危运行配置：容器以 `privileged` 模式运行。
在该模式下，容器获得接近宿主机进程的设备访问和内核操作能力，极易突破容器隔离。

本目录内容参考 `cves/metarget/writeups_cnv/config-privileged-container/README.md`，并与当前脚本流程对齐。

## 2. 复现该场景的价值

- 验证平台是否允许高风险 `privileged: true` 工作负载上线。
- 验证容器运行时能力边界是否被彻底打穿。
- 验证审计系统能否发现“容器挂载宿主机磁盘并 chroot”这类关键动作。

## 3. 作用机理（分阶段）

### 阶段 A：特权容器获取近乎完整宿主机能力

`privileged` 会放宽设备访问、能力集与安全策略限制（如 LSM 约束弱化），
使容器对宿主机资源的可操作面大幅扩大。

### 阶段 B：容器内识别并挂载宿主机磁盘分区

攻击者在容器内枚举块设备（如 `/dev/sd*`），
随后将宿主机分区挂载到容器目录（例如 `/host`）。

### 阶段 C：通过 `chroot` 切入宿主机文件系统上下文

挂载后执行 `chroot /host`，即可在宿主机根文件系统视角运行命令，
后续可修改系统配置、落地持久化、获取宿主机 shell。

## 4. 容器逃逸关键节点分析

1. `privileged` 本身已接近“关闭容器隔离”。
2. 块设备可见且可挂载，是从容器进入宿主机文件系统的直接跳板。
3. `chroot` 将访问视角切到宿主机根目录，形成实际逃逸效果。
4. 因此该问题根因是配置错误，不依赖复杂漏洞链。

## 5. 目录结构

```text
config-privileged-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 负责部署场景与基础检查；完整逃逸步骤需在目标容器内手工执行挂载与 `chroot`。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://www.docker.com/blog/docker-can-now-run-within-docker/
- https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities
- cves/metarget/writeups_cnv/config-privileged-container/README.md
