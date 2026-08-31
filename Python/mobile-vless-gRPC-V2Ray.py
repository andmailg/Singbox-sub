import base64
import functools
import ipaddress
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests  # Инициализация сессии для повторного использования соединений
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
    """Очистка и приведение VLESS ноды к формату V2Ray (URI-ссылка)."""
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

    # --- ШАГ 3: ВЫВОД В ФОРМАТЕ V2RAY (VLESS URI, по одной на строку) ---
    v2ray_links = [outbound_to_v2ray_link(o) for o in outbounds]

    with open("vless-grpc-v2ray.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(v2ray_links) + "\n")

    print(f"Successfully generated vless-grpc-v2ray.txt with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
