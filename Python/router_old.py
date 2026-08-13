import ipaddress  # Встроенный модуль для работы с IP и подсетями
from concurrent.futures import ThreadPoolExecutor
import base64
import json
import os
import socket
import urllib.parse
import requests
import re

# Для работы с локальной базой GeoIP
try:
    import maxminddb
except ImportError:
    # Заглушка на случай запуска вне среды с установленной библиотекой
    maxminddb = None

def is_valid_ip(address: str) -> bool:
    """Проверяет, является ли строка валидным IPv4 или IPv6 адресом."""
    try:
        ipaddress.ip_address(address.strip("[]"))
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """
    Проверяет, является ли строка валидным доменным именем (не IP-адресом).
    """
    if not domain or is_valid_ip(domain):
        return False
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))

def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server (не содержит '@', является валидным домена или IP)."""
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]")
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)

def parse_proxy_link(link: str) -> dict | None:
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
        print(f"Skipping malformed URL: {link[:30]}...")
        return None

    scheme = parsed.scheme.lower()
    
    # -------------------------------------------------------------------------
    # ЖЕСТКИЙ ФИЛЬТР: Пропускаем ТОЛЬКО Hysteria2
    # -------------------------------------------------------------------------
    if scheme not in ["hysteria2", "hy2"]:
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Фильтрация по insecure
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        print(f"Skipping insecure node: {link[:30]}...")
        return None

    # 2. Фильтрация по портам (оставляем только 443 и 8443)
    port = parsed.port or 443
    if port not in [443, 8443]:
        print(f"Skipping Hy2 node: invalid port ({port})")
        return None

    # 3. Извлечение пароля
    netloc = parsed.netloc
    password = parsed.username

    if not password and "@" in netloc:
        user_part = netloc.split("@")[0]
        password = user_part.split(":", 1)[-1] if ":" in user_part else user_part

    if not password:
        print(f"Skipping Hy2 node: missing password")
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"

    # 4. Обработка SNI
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    server_host = hostname
    if sni and hostname.lower() != sni.lower():
        server_host = sni

    tls_opts = {"enabled": True}
    if sni:
        tls_opts["server_name"] = sni

    # 5. Сборка объекта outbound для sing-box
    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": server_host,
        "server_port": port,
        "up_mbps": 20,
        "down_mbps": 20,
        "password": urllib.parse.unquote(password),
        "tls": tls_opts
    }

    # =========================================================================
    # ГЛОБАЛЬНЫЕ ПРОВЕРКИ (SERVER, SNI, RU DOMAINS)
    # =========================================================================

    # Проверка корректности адреса сервера
    if not is_valid_server(outbound["server"]):
        print(f"Skipping node '{tag}': invalid 'server' field ('{outbound['server']}')")
        return None

    # Валидация SNI (если задан)
    if sni:
        sni_val = sni.lower()
        if not is_valid_domain(sni_val):
            print(f"Skipping node '{tag}': invalid SNI ('{sni_val}')")
            return None

        # Запрет российских доменов в SNI
        RU_ZONES = (".ru", ".su", ".рф")
        if sni_val.endswith(RU_ZONES) or any(f"{zone}:" in sni_val for zone in RU_ZONES):
            print(f"Skipping node '{tag}': forbidden Russian domain in SNI ('{sni_val}')")
            return None

    return outbound

def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение Hysteria2 ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    # Безопасный перенос fingerprint из reality (если он там случайно оказался) в utls
    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        reality_opts = tls_opts.get("reality", {})
        fp_from_reality = reality_opts.pop("fingerprint", None)
        
        if fp_from_reality:
            utls_opts = tls_opts.setdefault("utls", {"enabled": True})
            if "fingerprint" not in utls_opts:
                utls_opts["fingerprint"] = fp_from_reality

        # Если блок reality оказался пустым — удаляем его
        if not reality_opts:
            tls_opts.pop("reality", None)

    return outbound

def clean_urltest(outbound: dict) -> dict:
    """Удаление lru и timeout из urltest."""
    if outbound.get("type") == "urltest":
        outbound.pop("lru", None)
        outbound.pop("timeout", None)
    return outbound

def main():
    sub_url = os.environ.get("XRAY_SUBSCRIPTION_URL")
    if not sub_url:
        print("Error: XRAY_SUBSCRIPTION_URL environment variable is missing.")
        return

    print("Fetching subscription...")
    try:
        resp = requests.get(sub_url, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error fetching subscription: {e}")
        return

    content = resp.text.strip()

    try:
        content_padded = content + "=" * (-len(content) % 4)
        decoded_content = base64.b64decode(content_padded).decode("utf-8")
        links = decoded_content.splitlines()
    except Exception:
        links = content.splitlines()

    # --- СКАЧИВАНИЕ БАЗЫ GEOIP ---
    mmdb_path = "GeoLite2-Country.mmdb"
    if not os.path.exists(mmdb_path):
        print("Downloading local GeoIP database...")
        db_url = "https://git.io/GeoLite2-Country.mmdb"
        try:
            db_resp = requests.get(db_url, timeout=30)
            if db_resp.status_code == 200:
                with open(mmdb_path, "wb") as db_file:
                    db_file.write(db_resp.content)
                print("Local GeoIP database downloaded successfully.")
        except Exception as e:
            print(f"Error downloading GeoIP database: {e}")

    # --- СКАЧИВАНИЕ И СБОРКА ЧЕРНОГО СПИСКА CIDR РКН ---
    blocked_networks = []
    print("Downloading RKN blocked CIDR list...")
    # Используем raw-ссылку на файл для скачивания чистого текста
    rkn_url = "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst"
    try:
        rkn_resp = requests.get(rkn_url, timeout=15)
        if rkn_resp.status_code == 200:
            lines = rkn_resp.text.splitlines()
            for line in lines:
                line = line.strip()
                # Пропускаем комментарии и пустые строки
                if not line or line.startswith("#"):
                    continue
                try:
                    # Преобразуем строку подсети (напр. '198.23.57.168/32') в объект IPv4Network
                    net_obj = ipaddress.ip_network(line, strict=False)
                    blocked_networks.append(net_obj)
                except ValueError:
                    continue
            print(f"Successfully loaded {len(blocked_networks)} blocked networks from RKN list.")
        else:
            print(f"Failed to download RKN list. Status code: {rkn_resp.status_code}")
    except Exception as e:
        print(f"Error loading RKN blacklist: {e}")

    outbounds = []
    seen_servers = set()
    servers_to_resolve = set()
    pre_parsed_nodes = []

    # Разрешенные страны (Европа + США)
    EUROPE_COUNTRIES = {"NL", "DE", "FI", "PL", "FR", "GB", "EE", "LV", "LT", "SE", "CH", "AT", "US", "SG", "JP", "HK", "TR"}

    # --- ШАГ 1: Быстрый предварительный парсинг ---
    print(f"Parsing and deduplicating {len(links)} links...")
    for link in links:
        outbound = parse_proxy_link(link)
        if outbound:
            outbound = clean_outbound(outbound)
            if not outbound:
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
            # Собираем все домены/IP для резолвинга
            if server_address:
                servers_to_resolve.add(server_address)

    # --- ШАГ 2: Параллельный DNS-резолвинг ---
    server_to_ip_map = {}

    def resolve_dns(host):
        try:
            return host, socket.gethostbyname(host)
        except Exception:
            return host, None

    print(f"Resolving DNS for {len(servers_to_resolve)} domains...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        dns_results = executor.map(resolve_dns, servers_to_resolve)
        for host, ip in dns_results:
            if ip:
                server_to_ip_map[host] = ip

    # --- ШАГ 3: МГНОВЕННАЯ ГЕО-ФИЛЬТРАЦИЯ + ФИЛЬТРАЦИЯ БЛОКИРОВОК РКН ---
    filtered_nodes = []
    
    # Открываем базу MaxMind
    mmdb_accessible = os.path.exists(mmdb_path) and maxminddb
    reader = maxminddb.open_database(mmdb_path) if mmdb_accessible else None

    try:
        for outbound in pre_parsed_nodes:
            server_address = str(outbound.get("server", "")).lower()
            # Получаем чистый IP-адрес (из DNS-карты или напрямую)
            ip_addr = server_to_ip_map.get(server_address) or server_address

            # --- ПРОВЕРКА НА БЛОКИРОВКУ В CIDR РКН ---
            if blocked_networks:
                try:
                    # Преобразуем IP ноды в объект IPv4Address для проверки
                    ip_obj = ipaddress.ip_address(ip_addr)
                    is_blocked = False
                    
                    # Проверяем, входит ли IP в какую-либо заблокированную подсеть
                    for network in blocked_networks:
                        if ip_obj in network:
                            is_blocked = True
                            break
                    
                    if is_blocked:
                        print(f"Skipping node '{outbound.get('tag')}': IP {ip_addr} is blocked by RKN CIDR.")
                        continue # Выкидываем ноду из списка
                except ValueError:
                    # Если адрес не является валидным IP (не отрезолвился домен), пропускаем проверку CIDR
                    pass

            # --- ГЕО-ФИЛЬТРАЦИЯ ДЛЯ VLESS ---
            if outbound.get("type") == "vless" and reader:
                try:
                    geo_info = reader.get(ip_addr)
                    country_code = geo_info["country"].get("iso_code", "").upper() if geo_info and "country" in geo_info else "UNKNOWN"
                except Exception:
                    country_code = "UNKNOWN"
                
                if country_code not in EUROPE_COUNTRIES:
                    continue

            filtered_nodes.append(outbound)
    finally:
        if reader:
            reader.close()

    # --- ШАГ 4: УМНЫЙ РАЗБРОС ---
    MAX_NODES_LIMIT = 5000
    total_found = len(filtered_nodes)

    if total_found > MAX_NODES_LIMIT:
        print(f"Всего найдено уникальных европейских узлов: {total_found}. Выбираем {MAX_NODES_LIMIT} с равномерным разбросом...")
        sampled_outbounds = []
        for i in range(MAX_NODES_LIMIT):
            index = int(i * (total_found - 1) / (MAX_NODES_LIMIT - 1))
            sampled_outbounds.append(filtered_nodes[index])
        outbounds = sampled_outbounds
    else:
        print(f"Найдено {total_found} узлов (меньше лимита в {MAX_NODES_LIMIT}). Берем все.")
        outbounds = filtered_nodes

    # --- ШАГ 5: ЖЕСТКАЯ УНИКАЛИЗАЦИЯ ТЕГОВ СТРОГО ДЛЯ ФИНАЛЬНОГО СПИСКА ---
    seen_tags = {}
    for outbound in outbounds:
        base_tag = outbound.get("tag", "Node")
        if base_tag in seen_tags:
            seen_tags[base_tag] += 1
            outbound["tag"] = f"{base_tag} #{seen_tags[base_tag]}"
        else:
            seen_tags[base_tag] = 0
            outbound["tag"] = base_tag

    # Перегенерация списка тегов для селекторов (теперь тут будет ровно до 200 элементов)
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
        "url": "https://www.gstatic.com/generate_204",
        "interval": "10m",
        "tolerance": 50
    }
    urltest_outbound = clean_urltest(urltest_outbound)

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
