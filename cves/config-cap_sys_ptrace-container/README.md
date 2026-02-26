# 滥用 CAP_SYS_PTRACE + hostPID 导致容器逃逸

## 1. 场景简介

该场景属于组合配置风险：容器同时具备 `hostPID: true` 与 `CAP_SYS_PTRACE`。
这种组合会把宿主机进程暴露给容器，并允许对其进行调试级别的内存读写与执行流控制。

本目录优先参考 `cves/metarget/writeups_cnv/config-cap_sys_ptrace-container/` 场景定义（对应 README 为空），并与脚本行为对齐。

## 2. 复现该场景的价值

- 验证高危配置组合是否被准入策略阻断。
- 验证容器是否可直接观测并干预宿主机进程。
- 验证主机侧 ptrace 防护（如 Yama/LSM）在容器场景中的实际效果。

## 3. 作用机理（分阶段）

### 阶段 A：`hostPID` 暴露宿主机进程视图

容器加入宿主机 PID 命名空间后，可直接看到宿主机进程列表与 PID。

### 阶段 B：`CAP_SYS_PTRACE` 赋予调试控制能力

攻击者可对目标进程执行 `ptrace attach`、寄存器读写、内存读写等操作。
在满足条件时可进行代码注入或劫持执行流。

### 阶段 C：借宿主机进程上下文实现边界外执行

一旦注入成功，恶意代码在宿主机进程上下文运行，
可读取高权限数据、下发命令或建立持久化，从而形成容器逃逸。

## 4. 容器逃逸关键节点分析

1. 必须同时出现 `hostPID` 与 `CAP_SYS_PTRACE` 的高危组合。
2. 目标宿主机进程需可被附加（受 ptrace_scope、LSM、进程权限等影响）。
3. 攻击者具备注入工具链或自定义注入代码能力。
4. 一旦控制宿主机高权限进程，容器边界实际失守。

## 5. 目录结构

```text
config-cap_sys_ptrace-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 负责部署并验证进程可见性；完整 ptrace 注入步骤需在实验环境手工完成。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://man7.org/linux/man-pages/man2/ptrace.2.html
- https://man7.org/linux/man-pages/man7/capabilities.7.html
- cves/metarget/writeups_cnv/config-cap_sys_ptrace-container/
