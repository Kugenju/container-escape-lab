# 滥用CAP_SYS_PTRACE + hostPID导致容器逃逸

## 来源
- 原始目录: `cves/metarget/writeups_cnv/config-cap_sys_ptrace-container`
- 原始文档: `cves/metarget/writeups_cnv/config-cap_sys_ptrace-container/README.md`
- 状态: 原始 README 为空（基于场景YAML重建）

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
- 可进一步对宿主机进程进行 ptrace 注入（实验环境内）。
