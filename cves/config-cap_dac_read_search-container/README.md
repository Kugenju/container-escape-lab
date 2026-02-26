# 滥用 CAP_DAC_READ_SEARCH（Shocker）导致容器逃逸

## 1. 场景简介

该场景属于高危能力配置问题：容器被授予 `CAP_DAC_READ_SEARCH` 后，可调用 `open_by_handle_at()` 并绕过常规目录/文件读检查。
在容器与宿主机文件系统存在可关联路径时，攻击者可跨容器边界读取宿主机敏感文件。

本目录内容参考 `cves/metarget/writeups_cnv/config-cap_dac_read_search-container/README.md`，并与当前脚本流程对齐。

## 2. 复现该场景的价值

- 验证高危 capability（`CAP_DAC_READ_SEARCH`）是否被误授予业务容器。
- 验证容器对宿主机文件系统信息泄露的可行性与影响面。
- 验证平台策略（PSP/PSA/准入控制）是否拦截危险 capability 组合。

## 3. 作用机理（分阶段）

### 阶段 A：容器进程获得 `CAP_DAC_READ_SEARCH`

该 capability 允许绕过读/搜索权限检查，并允许调用 `open_by_handle_at()`。
这是 Shocker 攻击链的核心前提。

### 阶段 B：建立宿主机文件系统“句柄解释上下文”

`open_by_handle_at()` 需要一个同文件系统上的 `mount_fd`。
在容器中常可利用与宿主机同源挂载文件（如 `/etc/hosts`）作为入口 FD。

### 阶段 C：构造目标文件 `file_handle` 并跨边界读取

攻击者可通过已知 inode/句柄信息、枚举与爆破等方式构造目标文件句柄，
再调用 `open_by_handle_at()` 打开宿主机文件（如 `/etc/shadow`）并读取内容。

### 阶段 D：信息泄露升级为实质逃逸能力

读取宿主机口令哈希、密钥、配置和 token 后，可进一步实现横向移动、持久化或宿主机接管。

## 4. 容器逃逸关键节点分析

1. 容器必须被授予 `CAP_DAC_READ_SEARCH`。
2. 容器内需要能拿到可解释到宿主机文件系统的 `mount_fd` 入口。
3. 目标文件系统要支持句柄相关操作（并非所有 FS 都可同样利用）。
4. 一旦成功读取宿主机高敏信息，容器边界即失去安全意义。

## 5. 目录结构

```text
config-cap_dac_read_search-container/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 只部署场景并验证 capability；完整 Shocker 利用需手工准备 `open_by_handle_at` PoC。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://github.com/gabrtv/shocker/blob/master/shocker.c
- https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html
- https://man7.org/linux/man-pages/man7/capabilities.7.html
- cves/metarget/writeups_cnv/config-cap_dac_read_search-container/README.md
