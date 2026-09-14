"""Экспорт нод в формат V2Ray (hysteria2:// ссылки)."""

import json
import urllib.parse


def generate_v2ray_links(outbounds: list[dict]) -> list[str]:
    """Конвертирует список outbounds в список v2ray-ссылок."""
    v2ray_links: list[str] = []
    for outbound in outbounds:
        tag = outbound.get("tag", "node")
        server = outbound.get("server", "")
        port = outbound.get("server_port", 443)
        password = outbound.get("password", "")
        sni = outbound.get("tls", {}).get("server_name", "")
        up_mbps = outbound.get("up_mbps", 20)
        down_mbps = outbound.get("down_mbps", 20)

        # Формируем ссылку hysteria2://password@server:port?sni=xxx&up=20&down=20#tag
        query_params = urllib.parse.urlencode({
            "sni": sni,
            "security": "tls",
            "up": up_mbps,
            "down": down_mbps,
        })
        fragment = urllib.parse.quote(tag)
        netloc = f"{server}:{port}"
        v2ray_link = f"hysteria2://{urllib.parse.quote(password, safe='')}@{netloc}?{query_params}#{fragment}"
        v2ray_links.append(v2ray_link)

    return v2ray_links


def export_v2ray(outbounds: list[dict], output_file: str = "hy2-v2ray.txt") -> int:
    """Экспортирует ноды в файл в формате V2Ray."""
    v2ray_links = generate_v2ray_links(outbounds)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(v2ray_links))
    print(f"✅ Successfully exported {len(v2ray_links)} nodes to {output_file}")
    return len(v2ray_links)
