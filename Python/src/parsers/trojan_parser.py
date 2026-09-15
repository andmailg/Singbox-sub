"""Парсинг и фильтрация ссылок Trojan."""

import urllib.parse

from src.common import is_valid_host, is_valid_ip, is_valid_domain


def has_workers_dev(outbound: dict) -> bool:
    """Проверяет, содержит ли нода 'workers.dev'."""
    target = "workers.dev"

    server = outbound.get("server", "").lower()
    if target in server:
        return True

    tls = outbound.get("tls", {})
    if isinstance(tls, dict):
        server_name = tls.get("server_name", "").lower()
        if target in server_name:
            return True

    transport = outbound.get("transport", {})
    if isinstance(transport, dict):
        headers = transport.get("headers", {})
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k.lower() == "host" and target in str(v).lower():
                    return True

        hosts = transport.get("host", [])
        if isinstance(hosts, list):
            if any(target in str(h).lower() for h in hosts):
                return True
        elif isinstance(hosts, str) and target in hosts.lower():
            return True

    return False


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата Trojan."""
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        parsed = urllib.parse.urlparse(link)
        hostname = parsed.hostname
        if not hostname:
            return None
        hostname = hostname.strip("[]")

        try:
            port = parsed.port
        except ValueError:
            return None

    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme != "trojan":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    password = parsed.username
    if not password and "@" in parsed.netloc:
        password = parsed.netloc.split("@")[0]
    if not password:
        return None

    security = params.get("security", ["tls"])[0].lower()
    tls_enabled = security not in ["", "none"]

    port = port or (443 if tls_enabled else 80)

    # Фильтр: порт 443 не нужен
    if port == 443:
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Trojan-Node"

    host_raw = params.get("host", [""])[0].strip()
    sni_raw = params.get("sni", [""])[0].strip() or params.get("peer", [""])[0].strip()

    host = host_raw.split(":")[0].strip() if host_raw else ""
    sni = sni_raw.split(":")[0].strip() if sni_raw else ""

    if host and not is_valid_host(host):
        return None

    outbound = {
        "type": "trojan",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "password": password,
    }

    if tls_enabled:
        tls_config = {"enabled": True}
        server_name = sni or host
        if server_name:
            if not is_valid_domain(server_name):
                return None
            tls_config["server_name"] = server_name

        insecure = (
            params.get("allowInsecure", ["0"])[0] in ["1", "true"]
            or params.get("insecure", ["0"])[0] in ["1", "true"]
        )
        if insecure:
            tls_config["insecure"] = True

        outbound["tls"] = tls_config

    net_type = (
        params.get("type", [""])[0].lower()
        or params.get("net", [""])[0].lower()
        or params.get("headerType", [""])[0].lower()
    )

    # Фильтр запрещённых типов транспорта
    if net_type in ["xhttp", "splithttp"] or (net_type and net_type not in ["tcp", "ws", "http", "grpc", "httpupgrade", "quic"]):
        return None

    if net_type and net_type != "tcp":
        transport_config = {"type": net_type}

        path = params.get("path", [""])[0]
        if path and net_type in ["ws", "http", "httpupgrade"]:
            transport_config["path"] = path

        if host:
            if net_type == "http":
                transport_config["host"] = [host]
            elif net_type in ["ws", "httpupgrade"]:
                transport_config["headers"] = {"Host": host}

        service_name = params.get("serviceName", [""])[0] or params.get("service_name", [""])[0]
        if service_name and net_type == "grpc":
            transport_config["service_name"] = service_name

        outbound["transport"] = transport_config

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и валидация Trojan ноды под спецификацию sing-box."""
    if not outbound:
        return None

    if has_workers_dev(outbound):
        return None

    # Проверка TLS
    tls_config = outbound.get("tls")
    if tls_config:
        if tls_config.get("insecure") is True:
            return None
        if not tls_config.get("server_name"):
            return None

    if outbound.get("type") == "trojan":
        if outbound.get("server_port") == 443:
            return None

        transport = outbound.get("transport")
        if transport:
            net_type = transport.get("type")
            if not net_type or net_type not in ["ws", "http", "grpc", "httpupgrade", "quic"]:
                return None

            if net_type not in ["ws", "http", "httpupgrade"]:
                transport.pop("path", None)

            if net_type in ["ws", "httpupgrade"]:
                raw_host = transport.pop("host", None)
                if raw_host and "headers" not in transport:
                    h_val = raw_host[0] if isinstance(raw_host, list) else raw_host
                    if is_valid_host(str(h_val)):
                        transport["headers"] = {"Host": str(h_val)}

                headers = transport.get("headers", {})
                ws_host = headers.get("Host") or headers.get("host")
                if ws_host and not is_valid_host(str(ws_host).strip()):
                    return None

            elif net_type == "http":
                hosts = transport.get("host")
                if hosts:
                    first_host = hosts[0] if isinstance(hosts, list) else hosts
                    if not is_valid_host(str(first_host).strip()):
                        return None

    return outbound
