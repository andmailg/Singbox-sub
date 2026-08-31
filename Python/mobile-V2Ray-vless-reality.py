import base64
import functools
import ipaddress
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests# Инициализация сессии для повторного использования соединений
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})


@functools.lru_cache(maxsize=4096)
def is_valid_ip(address: str) -> bool:
    """Проверяет, является ли строка валидным IPv4 или IPv6 адресом."""
    try:
        ipaddress.ip_address(address.strip("[]"))
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=4096)
def is_valid_domain(domain: str) -> bool:
    """Проверяет, является ли строка валидным доменным именем (не IP-адресом)."""
    if not domain or is_valid_ip(domain):
        return False
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))


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


# Зоны, узлы которых блокируются глобально
RU_ZONES = (".ru", ".su", ".рф")


def _is_ru_zone(hostname: str) -> bool:
    """Проверяет, относится ли хост к заблокированным зонам."""
    h = hostname.lower()
    return h.endswith(RU_ZONES) or any(f"{z}:" in h for z in RU_ZONES)


def should_accept_outbound(outbound: dict, seen_servers: set[str]) -> bool:
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
    if "ru" in node_tag or "russia" in node_tag:
        return False
    server_address = str(outbound.get("server", "")).lower()
    if _is_ru_zone(server_address):
        return False
    if server_address in seen_servers:
        return False
    seen_servers.add(server_address)
    return True


def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server."""
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]")
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)


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

    if not port:
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
    VALID_FINGERPRINTS = (
        "chrome", "firefox", "safari", "ios", "android",
        "edge", "1password", "xtls"
    )
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

    # 5. Сборка объекта outbound для sing-box
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


def fetch_subscription(url: str) -> list[str]:
    """Скачивает и декодирует отдельную подписку."""
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code != 200:
            return []

        content = resp.text.strip()
        try:
            content_padded = content + "=" * (-len(content) % 4)
            decoded_content = base64.b64decode(content_padded).decode("utf-8", errors="ignore")
            return decoded_content.splitlines()
        except Exception:
            return content.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []


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


def main():
    SOURCES_JSON_URL = "https://github.com/andmailg/Singbox-sub/raw/refs/heads/main/Python/src/sub_urls.json"

    print(f"Fetching subscription sources from {SOURCES_JSON_URL}...")
    try:
        sources_resp = session.get(SOURCES_JSON_URL, timeout=15)
        sources_resp.raise_for_status()

        try:
            sub_urls = sources_resp.json()
        except Exception:
            sub_urls = json.loads(sources_resp.text)

        if isinstance(sub_urls, dict):
            sub_urls = list(sub_urls.values())

        if not isinstance(sub_urls, list):
            raise ValueError(f"Expected list or dict, got {type(sub_urls)}")

        print(f"✅ Successfully loaded {len(sub_urls)} subscription sources.")

    except Exception as e:
        print(f"❌ Error fetching sources JSON: {e}")
        return

    # --- ШАГ 1: Ленивый парсинг, фильтрация и дедупликация в одном проходе ---
    seen_servers: set[str] = set()
    outbounds: list[dict] = []

    print("Downloading and parsing links in parallel...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        for lines in executor.map(fetch_subscription, sub_urls):
            for link in lines:
                outbound = parse_proxy_link(link)
                if not should_accept_outbound(outbound, seen_servers):
                    continue
                outbound = clean_outbound(outbound)
                if not outbound:
                    continue
                # Single-pass tagging
                outbound["tag"] = f"node-{len(outbounds) + 1}"
                outbounds.append(outbound)

    if not outbounds:
        print("Error: No valid proxy nodes left after filtration!")
        return

    # --- ШАГ 2: Экспорт в V2Ray-формат (VLESS URL) ---
    vless_links = [encode_vless_link(o) for o in outbounds]

    output_file = "vless-reality-v2ray.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(vless_links) + "\n")

    print(f"Successfully generated {output_file} with {len(vless_links)} nodes.")


if __name__ == "__main__":
    main()
