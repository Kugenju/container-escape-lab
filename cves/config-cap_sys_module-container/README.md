# 滥用 CAP_SYS_MODULE 导致容器逃逸

## 1. 场景简介

该场景属于高危能力配置问题：容器被授予 `CAP_SYS_MODULE` 后，可加载内核模块。
由于容器与宿主机共享同一内核，模块一旦成功加载，代码执行位置就是宿主机内核态。

本目录内容参考 `cves/metarget/writeups_cnv/config-cap_sys_module-container/README.md`，并与当前脚本流程对齐。

## 2. 复现该场景的价值

- 验证是否存在会直接打穿内核边界的 capability 误配置。
- 验证平台是否阻断 `SYS_MODULE` 能力下发。
- 验证主机侧内核模块安全策略（签名、锁定模式）是否有效。

## 3. 作用机理（分阶段）

### 阶段 A：容器获得模块加载权限

`CAP_SYS_MODULE` 允许执行 `insmod/modprobe` 等模块操作。
在共享内核模型下，这并非“容器内局部行为”。

### 阶段 B：加载攻击者自定义恶意 `.ko`

攻击者在与目标内核版本匹配环境中编译模块，模块可在 `init` 函数中执行恶意逻辑，
例如调用 `call_usermodehelper()` 拉起反弹 shell 或执行宿主机命令。

### 阶段 C：恶意逻辑在宿主机内核上下文生效

模块加载成功后，攻击代码获得内核态影响力，可直接突破容器边界并接管宿主机。

## 4. 容器逃逸关键节点分析

1. `CAP_SYS_MODULE` 是核心危险前提。
2. 主机未启用或未严格执行模块签名/锁定策略，利用难度会明显降低。
3. 容器内可访问 `insmod/modprobe` 工具链（或等效加载路径）。
4. 一旦模块落地执行，容器隔离机制基本失效。

## 5. 目录结构

```text
config-cap_sys_module-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 用于场景部署与 capability/工具探测；完整逃逸需手工编写并加载恶意 `.ko`。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd
- cves/metarget/writeups_cnv/config-cap_sys_module-container/README.md
