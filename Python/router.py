import base64
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests

# Инициализация сессии для повторного использования соединений
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})


def is_valid_ip(address: str) -> bool:
    """Проверяет, является ли строка валидным IPv4 или IPv6 адресом."""
    try:
        ipaddress.ip_address(address.strip("[]"))
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Проверяет, является ли строка валидным доменным именем (не IP-адресом)."""
    if not domain or is_valid_ip(domain):
        return False
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))


def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server."""
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]")
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)


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
        "up_mbps": 100,
        "down_mbps": 100,
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

        RU_ZONES = (".ru", ".su", ".рф")
        if sni_val.endswith(RU_ZONES) or any(
            f"{zone}:" in sni_val for zone in RU_ZONES
        ):
            return None

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение Hysteria2 ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    outbound.setdefault("up_mbps", 10)
    outbound.setdefault("down_mbps", 10)

    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        # Очищаем неиспользуемый блок reality для hysteria2
        tls_opts.pop("reality", None)

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

    # Параллельное скачивание содержимого всех подписок
    links = []
    print("Downloading subscription links in parallel...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(fetch_subscription, sub_urls)
        for lines in results:
            links.extend(lines)

    print(f"Total raw lines collected: {len(links)}")

    outbounds = []
    seen_servers = set()
    pre_parsed_nodes = []

    # --- ШАГ 1: Парсинг и фильтрация ---
    print(f"Parsing and deduplicating {len(links)} links...")
    for link in links:
        outbound = parse_proxy_link(link)
        if outbound:
            outbound = clean_outbound(outbound)
            if not outbound:
                continue

            tls_opts = outbound.get("tls", {})
            if not isinstance(tls_opts, dict) or not tls_opts.get("enabled"):
                continue

            server_name = tls_opts.get("server_name")
            if not server_name or not isinstance(server_name, str) or not server_name.strip():
                continue

            node_tag = str(outbound.get("tag", "")).lower()
            if "ru" in node_tag or "russia" in node_tag:
                continue

            server_address = str(outbound.get("server", "")).lower()
            if server_address.endswith(".ru") or ".ru:" in server_address:
                continue

            if server_address in seen_servers:
                continue
            seen_servers.add(server_address)

            pre_parsed_nodes.append(outbound)

    outbounds = list(pre_parsed_nodes)
    print(f"Всего выбрано {len(outbounds)} валидных Hysteria2 узлов.")

    # --- ШАГ 2: УНИКАЛИЗАЦИЯ ТЕГОВ ---
    for idx, outbound in enumerate(outbounds, start=1):
        outbound["tag"] = f"node-{idx}"

    node_tags = [o["tag"] for o in outbounds]

    if not node_tags:
        print("Error: No valid proxy nodes left after filtration!")
        return

    selector_outbound = {
        "type": "selector",
        "tag": "proxy-out",
        "outbounds": ["auto"] + node_tags,
        "default": "auto",
    }

    urltest_outbound = {
        "type": "urltest",
        "tag": "auto",
        "outbounds": node_tags,
        "url": "https://connectivitycheck.gstatic.com/generate_204",
        "interval": "10m",
        "tolerance": 50,
    }

    # --- ШАГ 3: СБОРКА ИТОГОВОГО КОНФИГА SING-BOX ---
    singbox_config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": 1080,
              "tcp_fast_open": True
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"},
            selector_outbound,
            urltest_outbound,
            *outbounds
        ],
  "route": {
    "final": "proxy-out",
    "auto_detect_interface": True
  },
  "experimental": {
    "cache_file": {
      "enabled": True,
      "path": "/opt/etc/sing-box/cache"
    },
      
        "clash_api": {
            "external_controller": "192.168.1.1:9090",
            "external_ui": "/opt/etc/sing-box/ui",
            "external_ui_download_detour": "direct-out",
            "access_control_allow_private_network": True
        }
    }
}

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated config.json with {len(outbounds)} nodes.")

if __name__ == "__main__":
    main()
