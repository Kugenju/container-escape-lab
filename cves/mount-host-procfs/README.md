# 挂载宿主机 Procfs 导致容器逃逸

## 1. 场景简介

该场景不是单一 CVE，而是高危错误配置：把宿主机 procfs（常见 `/proc` 或其子路径）挂载到容器。
当容器内攻击者能写入关键内核参数（如 `core_pattern`）时，可将容器内操作转化为宿主机命令执行。

本目录内容参考 `cves/metarget/writeups_cnv/mount-host-procfs/README.md`，并重组为脚本化场景。

## 2. 复现该场景的价值

- 验证“只挂载一个系统目录”是否已突破容器边界。
- 验证 K8s YAML 中 `hostPath` + 高权限容器组合的风险。
- 验证宿主机侧内核参数面（`/proc/sys`）是否可被容器间接控制。

## 3. 作用机理（分阶段）

### 阶段 A：容器获取宿主机 procfs 的读写通道

当宿主机 procfs 被挂入容器（如 `/host-proc`）且权限可写时，
容器内进程可以直接改写宿主机内核参数接口文件。

### 阶段 B：改写 `core_pattern` 将崩溃处理劫持为可执行命令

`/proc/sys/kernel/core_pattern` 支持以 `|` 开头的“管道模式”。
在该模式下，进程崩溃时内核会调用指定用户态程序处理 core dump。

攻击者可把该处理路径指向容器文件系统中实际映射到宿主机可达的脚本路径。

### 阶段 C：触发崩溃，内核在宿主机上下文执行攻击脚本

一旦触发任意崩溃进程，内核按 `core_pattern` 执行脚本，
执行上下文在宿主机侧，从而得到容器外执行能力并完成逃逸。

## 4. 容器逃逸关键节点分析

1. `hostPath` 暴露了宿主机 `/proc`（尤其 `/proc/sys`）给不可信容器。
2. 容器具备修改 `core_pattern` 的权限（通常与容器 root、能力集、挂载权限有关）。
3. 攻击者可定位容器文件在宿主机上的可达路径并构造可执行脚本。
4. 触发崩溃这一“合法系统行为”成为宿主机命令执行触发器。

## 5. 目录结构

```text
mount-host-procfs/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 主要完成场景部署与基础检查；完整逃逸步骤需手工执行 `core_pattern` 劫持链路。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- http://man7.org/linux/man-pages/man5/core.5.html
- cves/metarget/writeups_cnv/mount-host-procfs/README.md
