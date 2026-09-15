"""Парсинг и фильтрация ссылок VLESS with TCP + HTTP header."""

import urllib.parse

from src.common import (
    is_valid_host,
)


def parse_proxy_link(link: str) -> dict | None:
    """Парсит VLESS TCP+HTTP ссылку."""
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
    if scheme != "vless":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # Проверка: security = none
    security = params.get("security", ["none"])[0].lower()
    if security not in ["", "none"]:
        return None

    # Проверка: encryption = none
    encryption = params.get("encryption", ["none"])[0].lower()
    if encryption != "none":
        return None

    # Проверка: network = tcp
    net_type = params.get("type", ["tcp"])[0].lower()
    if net_type != "tcp":
        return None

    # Проверка: headerType = http
    header_type = params.get("headerType", [""])[0].lower()
    if header_type != "http":
        return None

    # Извлечение UUID
    uuid_str = parsed.username
    if not uuid_str and "@" in parsed.netloc:
        uuid_str = parsed.netloc.split("@")[0]
    if not uuid_str:
        return None

    # Проверка host
    host = params.get("host", [""])[0].strip()
    if not host or not is_valid_host(host):
        return None

    # Фильтр google.com в host
    if "google.com" in host.lower():
        return None

    port = parsed.port or 80
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-HTTP-Node"

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": uuid_str,
        "transport": {
            "type": "http",
            "host": [host],
        },
    }
    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация VLESS HTTP ноды под спецификацию sing-box."""
    if not outbound:
        return None
    if outbound.get("type") == "vless":
        transport = outbound.get("transport", {})
        if transport.get("type") == "http":
            hosts = transport.get("host")
            if not hosts or not isinstance(hosts, list) or len(hosts) == 0:
                return None
            if not is_valid_host(str(hosts[0]).strip()):
                return None
        outbound.pop("tls", None)
    return outbound
