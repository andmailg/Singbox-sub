"""Универсальный экспорт нод в формат V2Ray (ссылки)."""

import urllib.parse


def _generate_hy2_links(outbounds: list[dict]) -> list[str]:
    """Конвертирует Hysteria2 ноды в v2ray-ссылки."""
    links: list[str] = []
    for o in outbounds:
        if o.get("type") != "hysteria2":
            continue
        tag = o.get("tag", "node")
        server = o.get("server", "")
        port = o.get("server_port", 443)
        password = o.get("password", "")
        sni = o.get("tls", {}).get("server_name", "")
        up_mbps = o.get("up_mbps", 20)
        down_mbps = o.get("down_mbps", 20)

        query_params = urllib.parse.urlencode({
            "sni": sni,
            "security": "tls",
            "up": up_mbps,
            "down": down_mbps,
        })
        fragment = urllib.parse.quote(tag)
        netloc = f"{server}:{port}"
        link = f"hysteria2://{urllib.parse.quote(password, safe='')}@{netloc}?{query_params}#{fragment}"
        links.append(link)
    return links


def _generate_vless_grpc_links(outbounds: list[dict]) -> list[str]:
    """Конвертирует VLESS gRPC ноды в v2ray-ссылки."""
    links: list[str] = []
    for o in outbounds:
        if o.get("type") != "vless":
            continue
        transport = o.get("transport", {})
        if transport.get("type") != "grpc":
            continue
        uuid = o.get("uuid", "")
        server = o.get("server", "")
        port = o.get("server_port", 8443)
        sni = o.get("tls", {}).get("server_name", "")
        service_name = transport.get("service_name", "")
        tag = o.get("tag", "VLESS-Node")
        packet_encoding = o.get("packet_encoding", "xudp")

        params = urllib.parse.urlencode({
            "encryption": "none",
            "security": "tls",
            "sni": sni,
            "type": "grpc",
            "serviceName": service_name,
            "packetEncoding": packet_encoding,
        })
        link = f"vless://{uuid}@{server}:{port}?{params}#{tag}"
        links.append(link)
    return links


def _generate_vless_reality_links(outbounds: list[dict]) -> list[str]:
    """Конвертирует VLESS Reality ноды в v2ray-ссылки."""
    links: list[str] = []
    for o in outbounds:
        if o.get("type") != "vless":
            continue
        tls = o.get("tls", {})
        reality = tls.get("reality", {})
        if not reality.get("enabled"):
            continue
        tag = o.get("tag", "node")
        server = o.get("server", "")
        server_port = o.get("server_port", 443)
        uuid = o.get("uuid", "")
        sni = tls.get("server_name", "")
        pbk = reality.get("public_key", "")
        sid = reality.get("short_id", "")
        fp = tls.get("utls", {}).get("fingerprint", "")

        params = {
            "sni": sni,
            "pbk": pbk,
            "fp": fp,
            "security": "reality",
        }
        if sid:
            params["sid"] = sid

        query = urllib.parse.urlencode(params)
        fragment = urllib.parse.quote(tag)
        link = f"vless://{uuid}@{server}:{server_port}?{query}#{fragment}"
        links.append(link)
    return links


def export_v2ray(outbounds: list[dict], output_file: str = "output.txt") -> int:
    """Экспортирует ноды в файл в формате V2Ray (все типы)."""
    all_links = (
        _generate_hy2_links(outbounds)
        + _generate_vless_grpc_links(outbounds)
        + _generate_vless_reality_links(outbounds)
    )
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))
    print(f"✅ Successfully exported {len(all_links)} nodes to {output_file}")
    return len(all_links)


def export_v2ray_by_type(outbounds: list[dict], output_file: str = "output.txt") -> dict:
    """Экспортирует ноды по типам в отдельные файлы.
    
    Возвращает словарь: {"hy2.txt": count, "vless-grpc.txt": count, "vless-reality.txt": count}
    """
    hy2_links = _generate_hy2_links(outbounds)
    grpc_links = _generate_vless_grpc_links(outbounds)
    reality_links = _generate_vless_reality_links(outbounds)

    result = {}

    if hy2_links:
        path = f"{output_file}"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(hy2_links))
        result["hy2.txt"] = len(hy2_links)
        print(f"✅ Exported {len(hy2_links)} Hysteria2 nodes to {path}")

    if grpc_links:
        path = f"{output_file}"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(grpc_links))
        result["vless-grpc.txt"] = len(grpc_links)
        print(f"✅ Exported {len(grpc_links)} VLESS gRPC nodes to {path}")

    if reality_links:
        path = f"{output_file}"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(reality_links))
        result["vless-reality.txt"] = len(reality_links)
        print(f"✅ Exported {len(reality_links)} VLESS Reality nodes to {path}")

    total = sum(result.values())
    print(f"Total: {total} nodes exported.")
    return result
