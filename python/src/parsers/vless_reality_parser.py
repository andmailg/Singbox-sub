"""Парсинг и фильтрация ссылок VLESS with Reality."""

import base64
import functools
import re
import urllib.parse

from src.common import (
    RU_ZONES,
    is_valid_domain,
    is_valid_server,
)


@functools.lru_cache(maxsize=4096)
def _is_valid_reality_public_key(s: str) -> bool:
    """Проверяет валидность public_key для reality."""
    if not s:
        return False
    # Проверяем что это не служебное слово
    if s.lower() in ("enabled", "none", "null", "true", "false"):
        return False
    # X25519 public key в base64url всегда 43 символа (+ padding =)
    # 32 байта -> base64url = ceil(32/3)*4 = 44 символа, но обычно без padding = 43
    if len(s) not in (43, 44):
        return False
    # Конвертируем base64url в base64
    normalized = s.replace('-', '+').replace('_', '/')
    # Добавляем padding если нужно
    padded = normalized + '=' * (-len(normalized) % 4)
    # Строгая валидация base64
    try:
        decoded = base64.b64decode(padded, validate=True)
        return len(decoded) == 32  # X25519 public key = 32 байта
    except Exception:
        return False


@functools.lru_cache(maxsize=4096)
def _is_valid_hex(s: str) -> bool:
    """Проверяет, является ли строка валидным hex."""
    if not s:
        return True  # short_id может быть пустым
    return bool(re.fullmatch(r'[0-9a-fA-F]+', s)) and len(s) <= 16


VALID_FINGERPRINTS = (
    "chrome", "firefox", "safari", "ios", "android",
    "edge", "360", "qq", "random", "randomized"
)


def should_accept_outbound(outbound: dict, seen_fingerprints: set[str]) -> bool:
    """Быстрая фильтрация ноды после парсинга."""
    if not outbound:
        return False
    tls_opts = outbound.get("tls")
    if not isinstance(tls_opts, dict) or not tls_opts.get("enabled"):
        return False
    # Проверяем reality для VLESS
    if outbound.get("type") == "vless":
        reality_opts = tls_opts.get("reality")
        if not isinstance(reality_opts, dict) or not reality_opts.get("enabled"):
            return False
    server_name = tls_opts.get("server_name")
    if not server_name or not isinstance(server_name, str) or not server_name.strip():
        return False
    node_tag = str(outbound.get("tag", "")).lower()
    if any(f"-{z}" in node_tag or f".{z}" in node_tag or f" {z}" in node_tag or node_tag.endswith(z) for z in ("ru", "russia")):
        return False
    server_val = str(outbound.get("server", "")).lower()
    if server_val.endswith(RU_ZONES) or any(f"{z}:" in server_val for z in RU_ZONES):
        return False
    port_val = str(outbound.get("server_port", "80"))
    uuid_val = str(outbound.get("uuid", "")).lower()
    fingerprint = f"{server_val}:{port_val}:{uuid_val}"
    if fingerprint in seen_fingerprints:
        return False
    seen_fingerprints.add(fingerprint)
    return True


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата VLESS with Reality."""
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

    # 4. Сборка TLS options для reality
    pbk = params.get("pbk", [None])[0]
    sid = params.get("sid", [None])[0] or ""

    # Универсальная валидация полей reality
    if not pbk or not _is_valid_reality_public_key(pbk):
        return None
    if not _is_valid_hex(sid):
        return None

    # Читаем fp (fingerprint) из URL
    fp = params.get("fp", [None])[0]
    if not fp:
        return None

    # Валидация fingerprint
    if fp.lower() not in VALID_FINGERPRINTS:
        return None

    # Проверяем что security = reality
    security = params.get("security", [None])[0]
    if security and security.lower() != "reality":
        return None

    tls_opts = {
        "enabled": True,
        "server_name": sni,
        "utls": {
            "enabled": True,
            "fingerprint": fp
        },
        "reality": {
            "enabled": True,
            "public_key": pbk,
            "short_id": sid,
        }
    }

    # 5. Обработка транспорта (network)
    network = params.get("type", [None])[0] or params.get("network", [None])[0]
    if not network or network.lower() != "tcp":
        return None

    # 6. Сборка объекта outbound для sing-box
    packet_encoding = params.get("packetEncoding", [None])[0]
    if packet_encoding and packet_encoding.lower() not in ("xudp", "udp"):
        return None

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": urllib.parse.unquote(uuid),
        "tls": tls_opts,
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
    if not outbound or outbound.get("type") != "vless":
        return outbound

    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        reality_opts = tls_opts.get("reality", {})
        # Очищаем пустой short_id если не указан
        if reality_opts and not reality_opts.get("short_id"):
            reality_opts.pop("short_id", None)

    return outbound


def encode_vless_link(outbound: dict) -> str:
    """Кодирует outbound обратно в VLESS URL для V2Ray-клиентов."""
    tag = outbound.get("tag", "node")
    server = outbound["server"]
    server_port = outbound["server_port"]
    uuid = outbound["uuid"]
    tls = outbound["tls"]
    sni = tls.get("server_name", "")
    pbk = tls.get("reality", {}).get("public_key", "")
    sid = tls.get("reality", {}).get("short_id", "")
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
    return link
