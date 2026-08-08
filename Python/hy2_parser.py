import os
import re
import json
import base64
import socket
import ipaddress
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import requests

try:
    import maxminddb
except ImportError:
    maxminddb = None

# =========================================================================
# 1. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ВАЛИДАЦИИ И ПАРСИНГА HYSTERIA2
# =========================================================================

def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address.strip("[]"))
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    if not domain or is_valid_ip(domain):
        return False
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))

def is_valid_server(server: str) -> bool:
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]")
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)

def parse_proxy_link(link: str) -> dict | None:
    """Парсинг ссылки. Пропускает ТОЛЬКО hysteria2 / hy2."""
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
    
    # Жесткий фильтр только по Hy2
    if scheme not in ["hysteria2", "hy2"]:
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Фильтрация allowInsecure
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        return None

    # 2. Фильтрация портов (только 443 и 8443)
    port = parsed.port or 443
    if port not in [443, 8443]:
        return None

    # 3. Авторизация
    netloc = parsed.netloc
    password = parsed.username

    if not password and "@" in netloc:
        user_part = netloc.split("@")[0]
        password = user_part.split(":", 1)[-1] if ":" in user_part else user_part

    if not password:
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"

    # 4. SNI
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    server_host = hostname
    if sni and hostname.lower() != sni.lower():
        server_host = sni

    tls_opts = {"enabled": True}
    if sni:
        tls_opts["server_name"] = sni

    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": server_host,
        "server_port": port,
        "up_mbps": 10,
        "down_mbps": 10,
        "password": urllib.parse.unquote(password),
        "tls": tls_opts
    }

    # 5. Проверки адреса и SNI (включая .ru зоны)
    if not is_valid_server(outbound["server"]):
        return None

    if sni:
        sni_val = sni.lower()
        if not is_valid_domain(sni_val):
            return None

        RU_ZONES = (".ru", ".su", ".рф")
        if sni_val.endswith(RU_ZONES) or any(f"{zone}:" in sni_val for zone in RU_ZONES):
            return None

    return outbound

def clean_outbound(outbound: dict) -> dict:
    """Нормализация Hysteria2 структуры для sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    outbound.setdefault("up_mbps", 10)
    outbound.setdefault("down_mbps", 10)

    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        reality_opts = tls_opts.get("reality", {})
        fp_from_reality = reality_opts.pop("fingerprint", None)
        
        if fp_from_reality:
            utls_opts = tls_opts.setdefault("utls", {"enabled": True})
            if "fingerprint" not in utls_opts:
                utls_opts["fingerprint"] = fp_from_reality

        if not reality_opts:
            tls_opts.pop("reality", None)

    return outbound

# =========================================================================
# 2. ОСНОВНАЯ ФУНКЦИЯ ОБРАБОТКИ
# =========================================================================

def main():
    # Формируем список из 25 ссылок
    sub_urls = [
        f"https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/{i}.txt"
        for i in range(1, 26)
    ]

    links = []
    print(f"Fetching subscriptions from {len(sub_urls)} sources...")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    for url in sub_urls:
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code != 200:
                continue
            
            content = resp.text.strip()
            # Проверка и декодирование Base64 (если список зашифрован целиком)
            try:
                content_padded = content + "=" * (-len(content) % 4)
                decoded_content = base64.b64decode(content_padded).decode("utf-8", errors="ignore")
                fetched_lines = decoded_content.splitlines()
            except Exception:
                fetched_lines = content.splitlines()

            links.extend(fetched_lines)
        except Exception as e:
            print(f"Error fetching {url}: {e}")

    print(f"Total raw lines collected: {len(links)}")

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
    rkn_url = "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst"
    try:
        rkn_resp = requests.get(rkn_url, timeout=15)
        if rkn_resp.status_code == 200:
            lines = rkn_resp.text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
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

    # Разрешенные страны (Европа + США + Азия)
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
            if server_address.endswith((".ru", ".su", ".рф")) or ".ru:" in server_address:
                continue

            # Уникализация по сочетанию server:port:password
            node_key = f"{server_address}:{outbound.get('server_port')}:{outbound.get('password')}"
            if node_key in seen_servers:
                continue
            seen_servers.add(node_key)

            pre_parsed_nodes.append(outbound)
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
    
    mmdb_accessible = os.path.exists(mmdb_path) and maxminddb is not None
    reader = maxminddb.open_database(mmdb_path) if mmdb_accessible else None

    try:
        for outbound in pre_parsed_nodes:
            server_address = str(outbound.get("server", "")).lower()
            ip_addr = server_to_ip_map.get(server_address) or server_address

            # --- ПРОВЕРКА НА БЛОКИРОВКУ В CIDR РКН ---
            if blocked_networks:
                try:
                    ip_obj = ipaddress.ip_address(ip_addr)
                    is_blocked = False
                    
                    for network in blocked_networks:
                        if ip_obj in network:
                            is_blocked = True
                            break
                    
                    if is_blocked:
                        continue  # Отбрасываем ноду
                except ValueError:
                    pass

            # --- ГЕО-ФИЛЬТРАЦИЯ (Hysteria2) ---
            if reader:
                try:
                    geo_info = reader.get(ip_addr)
                    country_code = geo_info["country"].get("iso_code", "").upper() if geo_info and "country" in geo_info else "UNKNOWN"
                except Exception:
                    country_code = "UNKNOWN"
                
                # Если локация определена и ее нет в белом списке — пропускаем
                if country_code != "UNKNOWN" and country_code not in EUROPE_COUNTRIES:
                    continue

            filtered_nodes.append(outbound)
    finally:
        if reader:
            reader.close()

    # --- ШАГ 4: УМНЫЙ РАЗБРОС ---
    MAX_NODES_LIMIT = 5000
    total_found = len(filtered_nodes)

    if total_found > MAX_NODES_LIMIT:
        print(f"Всего найдено уникальных целевых узлов: {total_found}. Выбираем {MAX_NODES_LIMIT} с равномерным разбросом...")
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
        base_tag = outbound.get("tag", "Hy2-Node")
        if base_tag in seen_tags:
            seen_tags[base_tag] += 1
            outbound["tag"] = f"{base_tag} #{seen_tags[base_tag]}"
        else:
            seen_tags[base_tag] = 0
            outbound["tag"] = base_tag

    node_tags = [o["tag"] for o in outbounds]

    if not node_tags:
        print("Error: No valid proxy nodes left after filtration!")
        return

    # --- СОХРАНЕНИЕ В ФАЙЛ ---
    output_filename = "sing_box_hy2_outbounds.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(outbounds, f, ensure_ascii=False, indent=2)

    print(f"Успешно обработано! {len(outbounds)} Hysteria2 нод сохранено в '{output_filename}'.")

if __name__ == "__main__":
    main()
