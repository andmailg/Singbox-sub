"""Парсинг и фильтрация ссылок VMess."""

import base64
import functools
import json
import urllib.parse

from src.common import (
    RU_ZONES,
    is_valid_domain,
    is_valid_ip,
    is_valid_server,
)


@functools.lru_cache(maxsize=4096)
def _is_valid_uuid(s: str) -> bool:
    """Проверяет валидность UUID (32 hex chars with optional dashes)."""
    if not s or len(s) not in (32, 36):
        return False
    try:
        int(s.replace("-", ""), 16)
        return True
    except ValueError:
        return False


def _decode_vmess_json(link: str) -> dict | None:
    """Декодирует base64 JSON из vmess:// ссылки."""
    # Убираем префикс vmess://
    b64data = link.replace("vmess://", "", 1)
    try:
        # base64url -> base64
        b64data = b64data.replace("-", "+").replace("_", "/")
        # Добавляем padding
        b64data += "=" * (-len(b64data) % 4)
        decoded = base64.b64decode(b64data).decode("utf-8", errors="ignore")
        return json.loads(decoded)
    except Exception:
        return None


def should_accept_outbound(outbound: dict, seen_fingerprints: set[str]) -> bool:
    """Фильтрация: RU домены + дедупликация по fingerprint (server:port:uuid:path)."""
    if not outbound:
        return False

    node_tag = str(outbound.get("tag", "")).lower()
    if any(f"-{z}" in node_tag or f".{z}" in node_tag or f" {z}" in node_tag or node_tag.endswith(z) for z in ("ru", "russia")):
        return False
    server_val = str(outbound.get("server", "")).lower()
    if server_val.endswith(RU_ZONES) or any(f"{z}:" in server_val for z in RU_ZONES):
        return False

    port_val = str(outbound.get("server_port", "80"))
    uuid_val = str(outbound.get("uuid", "")).lower()
    path_val = str(outbound.get("transport", {}).get("path", "/")).lower()
    fingerprint = f"{server_val}:{port_val}:{uuid_val}:{path_val}"

    if fingerprint in seen_fingerprints:
        return False
    seen_fingerprints.add(fingerprint)
    return True


def parse_proxy_link(link: str) -> dict | None:
    """
    Парсит VMess ссылку формата vmess://base64json.
    
    Возвращает outbound в формате sing-box.
    """
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    # 1. Декодирование JSON
    vmess_data = _decode_vmess_json(link)
    if not vmess_data:
        return None

    # 2. Обязательные поля
    uuid = vmess_data.get("id") or vmess_data.get("id")
    if not uuid:
        return None
    if not _is_valid_uuid(uuid):
        return None

    server = vmess_data.get("add") or vmess_data.get("server")
    if not server:
        return None

    port = vmess_data.get("port") or vmess_data.get("tcp-port")
    if not port:
        return None
    try:
        port = int(port)
    except (ValueError, TypeError):
        return None

    # 3. Tag (alias)
    tag = vmess_data.get("ps") or vmess_data.get("remarks") or "VMess-Node"
    tag = str(tag)

    # 4. AlterID и security
    aid = vmess_data.get("aid") or vmess_data.get("alterId")
    try:
        aid = int(aid) if aid is not None else 0
    except (ValueError, TypeError):
        aid = 0

    # Security
    security = vmess_data.get("scy") or vmess_data.get("security") or "auto"

    # 5. TLS
    tls_val = vmess_data.get("tls")
    tls_str = str(tls_val).lower() if tls_val else ""
    has_tls = tls_str == "tls"

    # 6. Network type
    net = (vmess_data.get("net") or vmess_data.get("type") or "tcp").lower()

    # 7. Transport config
    transport: dict = {"type": net}

    # Host (SNI для ws/h2, Host header для ws)
    host = vmess_data.get("host") or vmess_data.get("sni", "")

    # Path
    path = vmess_data.get("path") or ""

    # SNI
    sni = vmess_data.get("sni") or host

    # Fingerprint
    fp = (vmess_data.get("fp") or vmess_data.get("pbk") or "").lower()

    # ObfsParam (для v2ray-ng plugin)
    obfs_param = vmess_data.get("obfsParam") or ""

    # WebSocket
    ws_extra: dict = {}
    if net in ("ws", "websocket"):
        if path:
            transport["path"] = path
        # Check for early data support (H2 compatible)
        early_data = vmess_data.get("ed") or 0
        try:
            early_data = int(early_data)
        except (ValueError, TypeError):
            early_data = 0
        if early_data > 0:
            transport["max_early_data"] = early_data
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            transport["headers"] = {"Host": host}

    # HTTP/2
    if net in ("h2", "http", "httpupgrade"):
        if path:
            transport["path"] = path
        if host:
            transport["host"] = host
        transport["method"] = "GET"

    # TCP gRPC
    if net == "grpc":
        service_name = vmess_data.get("serviceName") or vmess_data.get("serviceId") or ""
        transport["service_name"] = service_name
        transport["idle_timeout"] = 30
        transport["ping_timeout"] = 30
        transport["permit_without_stream"] = False

    # TCP with header (fake http)
    if net == "tcp":
        tcp_header = (vmess_data.get("type") or "none").lower()
        if tcp_header and tcp_header != "none":
            transport["type"] = "http"
            # For fake HTTP, we may need to set up request
        else:
            transport["type"] = "tcp"

    # 8. Сборка TLS
    tls_opts: dict | None = None
    if has_tls:
        tls_opts = {
            "enabled": True,
            "server_name": sni or server,
            "insecure": False,
        }
        if fp and fp in ("chrome", "firefox", "safari", "ios", "android", "edge", "1password", "xtls"):
            tls_opts["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

    # 9. Сборка outbound
    outbound = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": security if security != "auto" else "auto",
        "transport": transport,
    }

    if tls_opts:
        outbound["tls"] = tls_opts

    # 10. Валидация
    if not is_valid_server(outbound["server"]):
        return None

    sni_val = (sni or server).lower()
    if not is_valid_domain(sni_val) and not is_valid_ip(sni_val):
        return None

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и приведение VMess ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "vmess":
        return None

    transport = outbound.get("transport", {})
    net_type = transport.get("type", "tcp")

    # Валидация transport
    valid_networks = ("tcp", "ws", "h2", "http", "grpc", "httpupgrade")
    if net_type not in valid_networks:
        return None

    return outbound
