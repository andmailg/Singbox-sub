"""Парсинг и фильтрация ссылок VLESS with gRPC (без reality)."""

import urllib.parse

from src.common import (
    RU_ZONES,
    is_valid_domain,
    is_valid_server,
)


def should_accept_outbound(outbound: dict, seen_servers: set[str]) -> bool:
    """Быстрая фильтрация ноды после парсинга."""
    if not outbound:
        return False
    # Фильтр: только порт 8443
    if outbound.get("server_port") != 8443:
        return False
    tls_opts = outbound.get("tls")
    if not isinstance(tls_opts, dict) or not tls_opts.get("enabled"):
        return False
    # Отсекаем reality — только gRPC без reality
    if outbound.get("type") == "vless":
        reality_opts = tls_opts.get("reality")
        if isinstance(reality_opts, dict) and reality_opts.get("enabled"):
            return False
    server_name = tls_opts.get("server_name")
    if not server_name or not isinstance(server_name, str) or not server_name.strip():
        return False
    node_tag = str(outbound.get("tag", "")).lower()
    if "ru" in node_tag or "russia" in node_tag:
        return False
    server_address = str(outbound.get("server", "")).lower()
    if server_address.lower().endswith(RU_ZONES) or any(f"{z}:" in server_address for z in RU_ZONES):
        return False
    if server_address in seen_servers:
        return False
    seen_servers.add(server_address)
    return True


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата VLESS with gRPC (без reality)."""
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        parsed = urllib.parse.urlparse(link)
        hostname = parsed.hostname
        if not hostname:
            return None
        hostname = hostname.strip("[]")
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    # Фильтр: Только VLESS
    if scheme != "vless":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Обработка портов
    try:
        port = parsed.port
    except ValueError:
        port_part = parsed.netloc.rsplit(":", 1)[-1].split("?")[0].split("#")[0]
        first_port = port_part.split("-")[0]
        port = int(first_port) if first_port.isdigit() else None

    if not port or port != 8443:
        return None

    # 2. Извлечение UUID (пароля для VLESS)
    uuid = parsed.username

    if not uuid and "@" in parsed.netloc:
        user_part = parsed.netloc.split("@")[0]
        uuid = user_part.split(":", 1)[-1] if ":" in user_part else user_part

    if not uuid:
        return None

    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-Node"
    )

    # 3. Обработка SNI (serverName)
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    # SNI обязателен для TLS
    if not sni:
        return None

    # 4. Сборка TLS options (без reality)
    tls_opts = {
        "enabled": True,
        "server_name": sni,
    }

    # 5. Обработка транспорта (network) — только gRPC
    network = params.get("type", [None])[0] or params.get("network", [None])[0]
    if not network or network.lower() != "grpc":
        return None

    # 6. Сборка объекта outbound для sing-box
    packet_encoding = params.get("packetEncoding", [None])[0]
    if packet_encoding and packet_encoding.lower() not in ("xudp", "udp"):
        return None

    # gRPC параметры
    grpc_service_name = params.get("serviceName", [None])[0] or ""

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": urllib.parse.unquote(uuid),
        "tls": tls_opts,
        "transport": {
            "type": "grpc",
            "service_name": grpc_service_name,
        },
    }
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding

    # Глобальные проверки (SERVER, SNI)
    if not is_valid_server(outbound["server"]):
        return None

    sni_val = sni.lower()
    if not is_valid_domain(sni_val):
        return None

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение VLESS ноды к спецификации sing-box."""
    return outbound


def outbound_to_v2ray_link(outbound: dict) -> str:
    """Конвертирует объект ноды обратно в VLESS URI для V2Ray."""
    if not outbound:
        return ""
    uuid = outbound.get("uuid", "")
    server = outbound.get("server", "")
    port = outbound.get("server_port", 8443)
    sni = outbound.get("tls", {}).get("server_name", "")
    service_name = outbound.get("transport", {}).get("service_name", "")
    tag = outbound.get("tag", "VLESS-Node")
    packet_encoding = outbound.get("packet_encoding", "xudp")

    params = urllib.parse.urlencode({
        "encryption": "none",
        "security": "tls",
        "sni": sni,
        "type": "grpc",
        "serviceName": service_name,
        "packetEncoding": packet_encoding,
    })
    return f"vless://{uuid}@{server}:{port}?{params}#{tag}"
