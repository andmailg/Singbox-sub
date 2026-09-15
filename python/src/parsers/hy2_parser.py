"""Парсинг и фильтрация ссылок Hysteria2."""

import urllib.parse

from src.common import (
    FAKE_DOMAINS,
    RU_ZONES,
    is_valid_domain,
    is_valid_server,
)


def should_accept_outbound(outbound: dict, seen_fingerprints: set[str]) -> bool:
    """Быстрая фильтрация ноды после парсинга."""
    if not outbound:
        return False
    tls_opts = outbound.get("tls")
    if not isinstance(tls_opts, dict) or not tls_opts.get("enabled"):
        return False
    server_name = tls_opts.get("server_name")
    if not server_name or not isinstance(server_name, str) or not server_name.strip():
        return False
    if any(d in server_name.lower() for d in FAKE_DOMAINS):
        return False
    node_tag = str(outbound.get("tag", "")).lower()
    if any(f"-{z}" in node_tag or f".{z}" in node_tag or f" {z}" in node_tag or node_tag.endswith(z) for z in ("ru", "russia")):
        return False
    server_val = str(outbound.get("server", "")).lower()
    if server_val.endswith(RU_ZONES) or any(f"{z}:" in server_val for z in RU_ZONES):
        return False
    if any(d in server_val for d in FAKE_DOMAINS):
        return False
    fingerprint = f"{server_val}:{outbound.get('server_port')}:{outbound.get('password')}"
    if fingerprint in seen_fingerprints:
        return False
    seen_fingerprints.add(fingerprint)
    return True


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата Hysteria2."""
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

    # Фильтр: Только Hysteria2
    if scheme not in ["hysteria2", "hy2"]:
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Фильтрация небезопасных узлов
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        return None

    # 2. Обработка портов: первое число из диапазона или удаление узла, если порт не указан
    try:
        port = parsed.port
    except ValueError:
        # В случае диапазона портов (например, 21000-21199) извлекаем первое число
        port_part = parsed.netloc.rsplit(":", 1)[-1].split("?")[0].split("#")[0]
        first_port = port_part.split("-")[0]
        port = int(first_port) if first_port.isdigit() else None

    # Если порт не указан в ссылке или не определен, пропускаем узел
    if not port:
        return None

    # 3. Извлечение пароля
    netloc = parsed.netloc
    password = parsed.username

    if not password and "@" in netloc:
        user_part = netloc.split("@")[0]
        password = (
            user_part.split(":", 1)[-1] if ":" in user_part else user_part
        )

    if not password:
        return None

    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"
    )

    # 4. Обработка SNI
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    # Переопределение server_host значением SNI (если они различаются)
    server_host = hostname
    if sni and hostname.lower() != sni.lower():
        server_host = sni

    # SNI обязателен для TLS
    if not sni:
        return None

    tls_opts = {
        "enabled": True,
        "server_name": sni
    }

    # 5. Сборка объекта outbound для sing-box
    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": server_host,
        "server_port": port,
        "password": urllib.parse.unquote(password),
        "tls": tls_opts,
    }

    # Глобальные проверки (SERVER, SNI, RU DOMAINS)
    if not is_valid_server(outbound["server"]):
        return None

    if sni:
        sni_val = sni.lower()
        if not is_valid_domain(sni_val):
            return None

        if sni_val.lower().endswith(RU_ZONES) or any(f"{z}:" in sni_val for z in RU_ZONES):
            return None

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение Hysteria2 ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        # Очищаем неиспользуемый блок reality для hysteria2
        tls_opts.pop("reality", None)

    return outbound
