# 滥用CAP_SYS_ADMIN导致容器逃逸

## 来源
- 原始目录: `cves/metarget/writeups_cnv/config-cap_sys_admin-container`
- 原始文档: `cves/metarget/writeups_cnv/config-cap_sys_admin-container/README.md`
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
- 可继续按业务场景挂载宿主机目录并执行 chroot。
