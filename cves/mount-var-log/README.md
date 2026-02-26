# 挂载 /var/log 导致容器逃逸

## 1. 场景简介

该场景属于 Kubernetes 配置链路风险：Pod 以可写方式挂载宿主机 `/var/log`，
并且该 Pod 的 ServiceAccount 具备读取节点日志接口（`nodes/log`）的权限。
攻击者可借助符号链接与日志读取路径实现宿主机文件读取。

本目录内容参考 `cves/metarget/writeups_cnv/mount-var-log/README.md`，并与当前脚本流程对齐。

## 2. 复现该场景的价值

- 验证 `hostPath + RBAC` 组合是否形成可利用逃逸链。
- 验证 kubelet 日志读取路径在错误配置下的安全边界。
- 验证平台是否能识别并阻断可写 `/var/log` 挂载。

## 3. 作用机理（分阶段）

### 阶段 A：容器可写宿主机 `/var/log`

Pod 把宿主机 `/var/log` 挂载到容器内（本场景为 `/var/log/host`），
攻击者可在该目录下创建/修改文件与符号链接。

### 阶段 B：利用日志查询链路触发路径解析

`kubectl logs` 背后会走到 kubelet 的日志文件读取逻辑。
当读取路径经过攻击者构造的符号链接时，可能被导向宿主机任意目录。

### 阶段 C：读取宿主机任意文件/目录内容

借助已授予的 `nodes/log` 权限，请求可被扩展为读取宿主机敏感文件，
PoC 常以 `lsh/cath` 等包装命令简化该读取流程。

## 4. 容器逃逸关键节点分析

1. 必须存在可写 `hostPath` 挂载：宿主机 `/var/log`。
2. ServiceAccount 需要具备日志读取相关权限（如 `nodes/log`）。
3. kubelet 日志读取对符号链接路径的处理成为关键利用点。
4. 一旦宿主机敏感文件可读，后续凭据窃取与主机接管风险显著上升。

## 5. 目录结构

```text
mount-var-log/
|- scene.yaml
|- run_poc.sh
|- requirements.txt
`- README.md
```

## 6. 依赖与前置条件

见 `requirements.txt`。脚本层面需要：

- `kubectl`
- 可访问的 Kubernetes 集群

说明：`run_poc.sh` 会部署场景并尝试调用 `lsh/cath`；若镜像中未包含对应工具，会显示未找到。

## 7. 一键复现场景

```bash
bash run_poc.sh
```

## 8. 清理

```bash
bash run_poc.sh --cleanup
```

## 9. 参考

- https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts
- https://github.com/danielsagi/kube-pod-escape
- cves/metarget/writeups_cnv/mount-var-log/README.md
