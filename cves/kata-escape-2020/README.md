# Kata 容器逃逸（kata-escape-2020）

## 1. 场景简介

本目录用于记录 Kata Containers 在 2020 年前后披露的一类“虚拟化容器边界突破”问题的实验入口。
该类问题常涉及 guest 与 host 之间的挂载、路径解析、镜像/文件权限边界处理缺陷。

## 2. 复现该场景的价值

- 验证 VM 型容器（Kata）并非天然免疫容器逃逸。
- 验证 runtime 与 VMM 协同路径（挂载、teardown、hostPath）的安全边界。
- 验证版本治理对 Kata 运行时安全的重要性。

## 3. 作用机理（分阶段）

### 阶段 A：guest 侧获得可控输入点

攻击者可控容器镜像、挂载参数或 guest 内路径结构。

### 阶段 B：触发 runtime 与 host 交互缺陷

在受影响版本中，某些路径解析/挂载处理逻辑可能把 guest 输入映射到 host 非预期路径，
或让只读语义在 guest/host 边界不一致。

### 阶段 C：越界访问 host 资源并扩大影响

攻击者可读取/修改 host 侧文件、破坏 runtime 状态，
最终演化为拒绝服务或宿主机控制。

## 4. 容器逃逸关键节点分析

1. 关键在 guest-host 边界处理，而非单纯 Linux namespace。
2. runtime/VMM 版本差异显著影响可利用性。
3. 一旦 host 路径映射被劫持，Kata 隔离模型会被实质削弱。

## 5. 目录结构

```text
kata-escape-2020/
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 一键检查

```bash
bash run_poc.sh
```

说明：当前仓库未附带稳定公开 PoC，脚本仅做 `kata-runtime` 存在性与版本提示。

## 7. 参考

- https://nvd.nist.gov/vuln/detail/CVE-2020-2024
- https://nvd.nist.gov/vuln/detail/CVE-2020-2026
- https://nvd.nist.gov/vuln/detail/CVE-2020-28914
