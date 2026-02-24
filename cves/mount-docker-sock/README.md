# 挂载 docker.sock 导致容器逃逸

## 来源
- 原始目录: `cves/metarget/writeups_cnv/mount-docker-sock`
- 原始文档: `cves/metarget/writeups_cnv/mount-docker-sock/README.md`
- 状态: 原始 README 有复现步骤（已脚本化重组）

## 依赖
见 `requirements.txt`。

## 一键复现
```bash
bash run_poc.sh
```

## 清理
```bash
bash run_poc.sh --cleanup
```

## 说明
- 本目录不依赖 metarget 命令，直接通过 `kubectl apply scene.yaml` 搭建场景。
- 可在容器内安装 docker 客户端，通过该 socket 启动挂载 / 的特权容器。
