# 滥用 CAP_SYS_ADMIN 导致容器逃逸

## 1. 场景简介

该场景是典型高危能力配置问题：容器被授予 `CAP_SYS_ADMIN`。
该 capability 覆盖大量挂载、命名空间和系统管理相关操作，常被称为“近似 root 的万能能力”。

本目录基于 `cves/metarget/writeups_cnv/config-cap_sys_admin-container/` 场景定义（对应 README 为空）重组，并与脚本行为对齐。

## 2. 复现该场景的价值

- 验证平台是否错误放行 `CAP_SYS_ADMIN` 到业务容器。
- 验证容器侧 mount/chroot 等关键操作是否可被滥用。
- 验证准入与运行时策略对高危 capability 的阻断能力。

## 3. 作用机理（分阶段）

### 阶段 A：容器获得 `CAP_SYS_ADMIN`

容器启动后具备高级系统管理操作权限，
包括挂载文件系统、修改命名空间相关资源等。

### 阶段 B：构建宿主机资源可达路径

攻击者可利用挂载能力把目标文件系统（主机目录、设备分区或其他入口）接入容器，
形成对宿主机文件树的间接访问。

### 阶段 C：通过 `chroot`/命名空间操作实现边界突破

当宿主机根文件系统可达后，攻击者可切换执行上下文并操作宿主机关键文件，
从而形成实质逃逸。

## 4. 容器逃逸关键节点分析

1. `CAP_SYS_ADMIN` 是核心风险前提。
2. 需要存在可用的宿主机资源入口（挂载点、设备、hostPath 等）。
3. 一旦可挂载并切换到宿主机文件系统，上层容器隔离机制会被绕过。
4. 该类问题根因是配置错误，通常不依赖复杂内核漏洞。

## 5. 目录结构

```text
config-cap_sys_admin-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 会验证 capability 与基础挂载能力；完整逃逸步骤需在实验环境手工延伸。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://man7.org/linux/man-pages/man7/capabilities.7.html
- cves/metarget/writeups_cnv/config-cap_sys_admin-container/
