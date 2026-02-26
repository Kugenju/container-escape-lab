# 挂载宿主机 /etc 导致容器逃逸

## 1. 场景简介

该场景不是内核漏洞，而是高危挂载配置：将宿主机 `/etc` 目录直接挂载进容器。
`/etc` 包含主机身份、认证、网络与服务配置，暴露后可被用于信息泄露、持久化和进一步接管。

本目录基于 `cves/metarget/writeups_cnv/mount-host-etc/` 场景定义（对应 README 为空）重组，并与脚本行为对齐。

## 2. 复现该场景的价值

- 验证 `hostPath` 挂载是否把宿主机敏感配置直接暴露给容器。
- 验证平台是否能识别并阻断对 `/etc` 的危险挂载。
- 验证最小权限策略是否禁止非必要主机目录映射。

## 3. 作用机理（分阶段）

### 阶段 A：容器获得宿主机 `/etc` 的直接访问路径

通过 `hostPath`，宿主机 `/etc` 被映射到容器内（本场景为 `/host-etc`），
容器进程可以直接读取该目录内容。

### 阶段 B：读取主机关键配置与凭据线索

攻击者可访问主机标识、服务配置、证书、计划任务和潜在凭据材料，
为后续横向移动或提权提供情报。

### 阶段 C：在可写条件下实施持久化与系统篡改

若挂载权限为可写，攻击者可篡改关键配置（例如启动项、认证策略、服务配置），
从而实现长期驻留或进一步控制宿主机。

## 4. 容器逃逸关键节点分析

1. 高危根因是 `hostPath: /etc` 暴露给不可信容器。
2. 即便只读挂载，也可能造成高价值信息泄露。
3. 可写挂载会把风险升级为直接主机配置篡改。
4. 该类风险与镜像漏洞无关，本质是运行时部署策略失守。

## 5. 目录结构

```text
mount-host-etc/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 用于部署场景并验证读取能力。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
- cves/metarget/writeups_cnv/mount-host-etc/
