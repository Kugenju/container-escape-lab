import json
from pathlib import Path
import re

# 高风险工具包（按发行版）
TOOLS_BY_DISTRO = {
    "alpine": [
        "socat", "curl", "wget", "netcat-openbsd", "strace",
        "procps", "iproute2", "lsof", "findutils", "bash", "less"
    ],
    "debian": [
        "socat", "curl", "wget", "netcat-traditional", "strace",
        "procps", "iproute2", "lsof", "findutils", "bash", "less"
    ]
}

def guess_base_image(name: str) -> str:
    name_lower = name.lower()
    if "alpine" in name_lower:
        return "alpine:latest"
    elif "ubuntu" in name_lower or "debian" in name_lower:
        return "debian:bookworm-slim"
    else:
        return "alpine:latest"

def detect_distro(base_image: str) -> str:
    if "alpine" in base_image:
        return "alpine"
    elif "debian" in base_image or "ubuntu" in base_image:
        return "debian"
    else:
        return "alpine"

def sanitize_service_name(name: str) -> str:
    # docker-compose service name must be valid DNS label
    return re.sub(r"[^a-z0-9\-_]", "_", name.lower())

def generate_dockerfile(record):
    name = record["name"]
    namespace = record["namespace"]
    description = record.get("description", "")
    full_name = f"{namespace}/{name}"

    base_image = guess_base_image(name)
    distro = detect_distro(base_image)
    tools = TOOLS_BY_DISTRO.get(distro, TOOLS_BY_DISTRO["alpine"])

    if distro == "alpine":
        install_cmd = "apk add --no-cache " + " ".join(tools)
    else:
        install_cmd = "apt-get update && apt-get install -y --no-install-recommends " + " ".join(tools) + " && rm -rf /var/lib/apt/lists/*"

    dockerfile_content = f"""# Escape target container (for research only)
# Based on: {full_name}
# Description: {description}

FROM {base_image}

LABEL org.security.dataset="container-escape-target"
LABEL source.image="{full_name}"

RUN {install_cmd}

# Add non-root user (but root remains default)
RUN adduser -D -s /bin/sh attacker 2>/dev/null || true

EXPOSE 8080

CMD ["sh", "-c", "while true; do echo 'HTTP/1.1 200 OK\\r\\n\\r\\nEscape Target Active' | nc -l -p 8080 -s 0.0.0.0 2>/dev/null; done"]
"""
    return dockerfile_content.strip()

def process_json_files(input_dir: Path, output_dir: Path):
    json_files = list(input_dir.glob("*.json"))
    if not json_files:
        print("⚠️ 未找到任何 .json 文件")
        return []

    all_records = []
    for json_file in json_files:
        print(f"处理文件: {json_file}")
        with open(json_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"❌ 跳过无效 JSON: {json_file} ({e})")
                continue

        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "").strip()
            namespace = item.get("namespace", "").strip()
            if not name or not namespace:
                continue
            record = {
                "name": name,
                "namespace": namespace,
                "description": item.get("description", ""),
                "source_file": json_file.name
            }
            all_records.append(record)

    # 去重（避免重复镜像）
    seen = set()
    unique_records = []
    for r in all_records:
        key = (r["namespace"], r["name"])
        if key not in seen:
            seen.add(key)
            unique_records.append(r)

    # 生成 Dockerfile
    service_info_list = []
    for record in unique_records:
        safe_name = f"{record['namespace']}_{record['name']}".replace("/", "_").replace(":", "_").replace(".", "_")
        dockerfile_path = output_dir / f"Dockerfile.{safe_name}"
        with open(dockerfile_path, 'w', encoding='utf-8') as f:
            f.write(generate_dockerfile(record))

        service_name = sanitize_service_name(safe_name)
        service_info_list.append({
            "service_name": service_name,
            "dockerfile": f"Dockerfile.{safe_name}",
            "container_name": f"escape-target-{safe_name}"
        })
        print(f"✅ 生成: {dockerfile_path}")

    return service_info_list

def generate_docker_compose(service_info_list, output_dir: Path):
    compose_content = "services:\n"
    for info in service_info_list:
        compose_content += f"""  {info['service_name']}:
    build:
      context: .
      dockerfile: {info['dockerfile']}
    container_name: {info['container_name']}
    privileged: false
    cap_add:
      - SYS_PTRACE
      - DAC_READ_SEARCH
    security_opt:
      - apparmor:unconfined
      - seccomp:unconfined
    volumes:
      - /:/host:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    network_mode: bridge
    ports:
      - "8080"
    restart: unless-stopped
    stdin_open: true
    tty: true
"""
    compose_path = output_dir / "docker-compose.escape-targets.yml"
    with open(compose_path, 'w', encoding='utf-8') as f:
        f.write(compose_content)
    print(f"\n✅ 已生成 docker-compose 文件: {compose_path}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="生成容器逃逸靶机数据集（含 Dockerfile + docker-compose）")
    parser.add_argument("--input_dir", type=str,  default="./docker_hub_metadata",required=True, help="包含容器元数据 JSON 的目录")
    parser.add_argument("--output_dir", type=str, default="./escape_targets", help="输出目录")
    args = parser.parse_args()

    input_path = Path(args.input_dir)
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        raise FileNotFoundError(f"输入目录不存在: {input_path}")

    service_info_list = process_json_files(input_path, output_path)
    if service_info_list:
        generate_docker_compose(service_info_list, output_path)
        print(f"\n🎉 共生成 {len(service_info_list)} 个逃逸靶机，位于: {output_path.absolute()}")
        print("\n▶️ 使用方法:")
        print(f"   cd {output_path}")
        print("   docker compose -f docker-compose.escape-targets.yml up -d")
    else:
        print("❌ 未生成任何服务")

if __name__ == "__main__":
    main()