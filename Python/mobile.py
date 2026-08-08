import ipaddress  # Встроенный модуль для работы с IP и подсетями
from concurrent.futures import ThreadPoolExecutor
import base64
import json
import os
import socket
import urllib.parse
import requests

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
    params = urllib.parse.parse_qs(parsed.query)

    # Исправлена синтаксическая ошибка при получении типа сети
    raw_net = params.get("type") or params.get("net") or [""]
    net_type = raw_net[0].lower().strip()

    # Фильтрация insecure
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        print(f"Skipping insecure node: {link[:30]}...")
        return None

    # Фильтрация WebSocket (ws)
    if net_type == "ws":
        print(f"Skipping WebSocket node: {link[:30]}...")
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Node"
    outbound = None

    def build_transport(net: str) -> dict | None:
        # Для TCP transport не создаем по правилам sing-box
        if not net or net == "tcp":
            return None
        t_opts = {"type": net}
        path_param = params.get("path", [None])[0]
        host_param = params.get("host", [None])[0]
        service_param = params.get("serviceName", [None])[0]

        if path_param:
            t_opts["path"] = path_param.strip()
        if host_param:
            t_opts["headers"] = {"Host": host_param.strip()}
        if service_param:
            t_opts["service_name"] = service_param.strip()
        return t_opts

    # --- 1. VLESS ---
    if scheme == "vless":
        # --- Фильтрация по портам 443 и 8443 ---
        port = parsed.port or 443
        if port not in [443, 8443]:
            print(f"Skipping VLESS node '{tag}': invalid port ({port})")
            return None

        flow = params.get("flow", [""])[0].strip().lower()
        security = params.get("security", ["none"])[0].strip().lower()

        # Исключаем Reality
        if security == "reality":
            return None

        if flow != "xtls-rprx-vision":
            return None

        sni_param = params.get("sni", [None])[0]
        sni = sni_param.strip() if sni_param else None

        server_host = hostname
        if security in ["tls", "none"] and sni:
            if hostname.lower() != sni.lower():
                server_host = sni

        outbound = {
            "type": "vless",
            "tag": tag,
            "server": server_host,
            "server_port": port,
            "uuid": parsed.username,
            "flow": "xtls-rprx-vision"
        }

        tls_opts = {"enabled": True}
        if sni:
            tls_opts["server_name"] = sni

        fp_param = params.get("fp", [None])[0]
        if fp_param:
            tls_opts["utls"] = {"enabled": True, "fingerprint": fp_param.strip()}

        outbound["tls"] = tls_opts

        transport = build_transport(net_type)
        if transport:
            outbound["transport"] = transport

    # --- 2. VMESS ---
    elif scheme == "vmess":
        try:
            b64_data = parsed.netloc
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8")
            data = json.loads(decoded)

            net = data.get("net", "tcp").lower()
            if net == "ws":
                return None

            vmess_security = str(data.get("scy", "auto")).lower().strip()
            if vmess_security in ["auto", ""]:
                return None

            outbound = {
                "type": "vmess",
                "tag": data.get("ps", tag),
                "server": str(data.get("add", "")).strip("[]"),
                "server_port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "security": vmess_security,
            }

            # Транспорт создаем только если это НЕ tcp
            if net and net != "tcp":
                t_opts = {"type": net}
                if data.get("path"):
                    t_opts["path"] = data.get("path")
                if data.get("host"):
                    t_opts["headers"] = {"Host": data.get("host")}
                outbound["transport"] = t_opts

            if data.get("tls") == "tls":
                tls_opts = {"enabled": True}
                if data.get("sni"):
                    tls_opts["server_name"] = data.get("sni")
                if data.get("fp"):
                    tls_opts["utls"] = {"enabled": True, "fingerprint": data.get("fp")}
                outbound["tls"] = tls_opts
        except Exception:
            return None

    # --- 3. TROJAN ---
    elif scheme == "trojan":
        security = params.get("security", ["tls"])[0].lower()
        if security == "reality":
            return None

        sni_param = params.get("sni", [None])[0]
        sni = sni_param.strip() if sni_param else None

        server_host = hostname
        if sni and hostname.lower() != sni.lower():
            server_host = sni

        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": server_host,
            "server_port": parsed.port or 443,
            "password": parsed.username,
        }

        tls_opts = {"enabled": True}
        if sni:
            tls_opts["server_name"] = sni.split(":")[0].strip()

        fp_param = params.get("fp", [None])[0]
        if fp_param:
            tls_opts["utls"] = {"enabled": True, "fingerprint": fp_param.strip()}

        outbound["tls"] = tls_opts

        transport = build_transport(net_type)
        if transport:
            outbound["transport"] = transport

    # --- 4. HYSTERIA2 / HY2 ---
    elif scheme in ["hysteria2", "hy2"]:
        # Фильтрация по портам 443 и 8443
        port = parsed.port or 443
        if port not in [443, 8443]:
            print(f"Skipping Hysteria2 node '{tag}': invalid port ({port})")
            return None

        netloc = parsed.netloc
        password = parsed.username

        if not password and "@" in netloc:
            user_part = netloc.split("@")[0]
            password = user_part.split(":", 1)[-1] if ":" in user_part else user_part

        if not password:
            return None

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

    # --- 5. SHADOWSOCKS ---
    elif scheme == "ss":
        try:
            port = parsed.port
            if not port or not ((port == 443) or (10000 <= port <= 99999)):
                return None

            userinfo = parsed.username
            if not userinfo and parsed.netloc:
                userinfo = parsed.netloc.split("@")[0] if "@" in parsed.netloc else None

            method, password = None, None
            if userinfo:
                userinfo_padded = userinfo + "=" * (-len(userinfo) % 4)
                try:
                    decoded_userinfo = base64.b64decode(userinfo_padded).decode("utf-8")
                    if ":" in decoded_userinfo:
                        method, password = decoded_userinfo.rsplit(":", 1)
                except Exception:
                    pass

            if not method or not password:
                method = parsed.username
                password = parsed.password

            if not method or not password:
                return None

            method = str(method).lower().strip()
            ALLOWED_2022_METHODS = [
                "2022-blake3-aes-128-gcm", 
                "2022-blake3-aes-256-gcm", 
                "2022-blake3-chacha20-poly1305"
            ]
            if method not in ALLOWED_2022_METHODS:
                return None

            outbound = {
                "type": "shadowsocks",
                "tag": tag,
                "server": hostname,
                "server_port": port,
                "method": method,
                "password": password,
            }
        except Exception:
            return None

    # =========================================================================
    # ГЛОБАЛЬНЫЕ ФИЛЬТРЫ И ВАЛИДАЦИЯ (TLS, SNI, SERVER, RU DMN)
    # =========================================================================
    if not outbound:
        return None

    # 1. Проверка поля server на корректность
    server_val = str(outbound.get("server", ""))
    if not is_valid_server(server_val):
        print(f"Skipping node '{tag}': invalid 'server' field ('{server_val}')")
        return None

    # 2. Исключение для Shadowsocks: разрешаем узлы без TLS
    if outbound.get("type") == "shadowsocks":
        return outbound

    # 3. Обязательное наличие блока TLS для остальных протоколов
    tls_config = outbound.get("tls")
    if not tls_config or not tls_config.get("enabled"):
        print(f"Skipping node '{tag}': TLS is missing or disabled")
        return None

    # 4. Валидация SNI (server_name)
    sni_val = str(tls_config.get("server_name", "")).strip().lower()
    
    if not is_valid_domain(sni_val):
        print(f"Skipping node '{tag}': invalid or missing SNI ('{sni_val}')")
        return None

    # 5. Запрет российских доменов в SNI
    RU_ZONES = (".ru", ".su", ".рф")
    if sni_val.endswith(RU_ZONES) or any(f"{zone}:" in sni_val for zone in RU_ZONES):
        print(f"Skipping node '{tag}': forbidden Russian domain in SNI ('{sni_val}')")
        return None

    return outbound
    
def clean_outbound(outbound: dict) -> dict:
    """Применение исправлений для sing-box."""

    # 1. Валидация и очистка транспорта (Transport)
    transport = outbound.get("transport", {})
    if transport:
        # Список транспортов, которые официально поддерживает Sing-Box
        ALLOWED_TRANSPORTS = ["http", "ws", "grpc", "quic", "httpupgrade"]
        current_type = transport.get("type", "").lower()

        # Если транспорт tcp или неизвестный — полностью удаляем блок
        if current_type not in ALLOWED_TRANSPORTS or current_type == "tcp":
            if current_type and current_type != "tcp":
                print(
                    f"Fixing outbound: Unknown transport '{current_type}' removed for node '{outbound.get('tag')}'"
                )
            outbound.pop("transport", None)
            outbound.pop("packet_encoding", None)
        else:
            # Специфичное исправление для транспорта HTTP
            if current_type == "http":
                # В Sing-Box для http нужен массив "host": ["example.com"], а не объект "headers"
                if "headers" in transport and isinstance(
                    transport["headers"], dict
                ):
                    host_val = transport["headers"].get(
                        "Host"
                    ) or transport["headers"].get("host")
                    if host_val:
                        transport["host"] = (
                            [host_val] if isinstance(host_val, str) else host_val
                        )

                # Удаляем недопустимые для HTTP поля
                transport.pop("headers", None)
                transport.pop("path", None)
                transport.pop("service_name", None)

            # Очистка для других типов транспорта
            else:
                # Поле 'path' разрешено ТОЛЬКО для 'ws' и 'httpupgrade'
                if current_type not in ["ws", "httpupgrade"]:
                    transport.pop("path", None)

                # Поле 'headers' разрешено ТОЛЬКО для 'ws' и 'httpupgrade'
                if current_type not in ["ws", "httpupgrade"]:
                    transport.pop("headers", None)

                # Поле 'service_name' разрешено ТОЛЬКО для 'grpc'
                if current_type != "grpc":
                    transport.pop("service_name", None)

    # 2. Очистка REALITY (fingerprint переносится в utls)
    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        reality_opts = tls_opts.get("reality", {})
        if "fingerprint" in reality_opts:
            fp = reality_opts.pop("fingerprint")
            utls_opts = tls_opts.setdefault("utls", {"enabled": True})
            utls_opts["fingerprint"] = fp

    # 3. Удаление alterId: 0 у VMess
    if outbound.get("type") == "vmess":
        if "alterId" in outbound and outbound.get("alterId") == 0:
            outbound.pop("alterId", None)

    # 4. Валидация методов шифрования для Shadowsocks
    if outbound.get("type") == "shadowsocks":
        ALLOWED_METHODS = [
            "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
            "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305", "none"
        ]

        current_method = outbound.get("method")
        
        # Строгая проверка на None, пустые строки и не-строковые типы
        if current_method is None or not isinstance(current_method, str) or not current_method.strip():
            current_method = "aes-256-gcm"
        else:
            current_method = current_method.lower().strip()

        # Если метод не распознан Sing-Box — принудительно ставим рабочий дефолт
        if current_method not in ALLOWED_METHODS:
            print(f"Fixing shadowsocks method: '{current_method}' replaced with 'aes-256-gcm' for node '{outbound.get('tag')}'")
            current_method = "aes-256-gcm"

        outbound["method"] = current_method

        # Защита пароля
        if not outbound.get("password"):
            outbound["password"] = "password"

    # 5. Исправление поля flow для VLESS
    if outbound.get("type") == "vless":
        flow = outbound.get("flow")
        if flow and isinstance(flow, str):
            flow = flow.lower().strip()
            # Если в значении flow присутствует стандартный vision-поток, принудительно очищаем его от мусора
            if "xtls-rprx-vision" in flow:
                outbound["flow"] = "xtls-rprx-vision"
            # Если там записан устаревший или неподдерживаемый поток (например, xtls-rprx-direct)
            elif flow not in ["xtls-rprx-vision"]:
                print(f"Removing unsupported flow '{flow}' for VLESS node '{outbound.get('tag')}'")
                outbound.pop("flow", None)

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
        "url": "https://connectivitycheck.gstatic.com/generate_204",
        "interval": "10m",
        "tolerance": 50,
    }
    urltest_outbound = clean_urltest(urltest_outbound)

    singbox_config = {
        "log": {
            "level": "warn",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "tag": "dns-local",
                    "server": "1.1.1.1",
                    "tls": {
                        "enabled": True,
                        "server_name": "cloudflare-dns.com"
                    }
                },
                {
                    "type": "https",
                    "tag": "dns-remote",
                    "server": "1.1.1.1",
                    "detour": "proxy-out",
                    "tls": {
                        "enabled": True,
                        "server_name": "cloudflare-dns.com"
                    }
                },
                {
                    "type": "fakeip",
                    "tag": "fakeip",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                },
                {
                    "type": "local",
                    "tag": "local"
                }
            ],
            "rules": [
                {
                    "rule_set": [
                        "geosite-category-ru",
                        "geoip-ru"
                    ],
                    "server": "dns-local"
                },
                {
                    "query_type": [
                        "HTTPS",
                        "SVCB"
                    ],
                    "action": "predefined",
                    "rcode": "REFUSED"
                },
                {
                    "rule_set": [
                        "db-category-ai-chat",
                        "geosite-category-media-ru-blocked"
                    ],
                    "server": "fakeip"
                }
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
            "cache_capacity": 2048
        },
        "endpoints": [
            {
                "type": "wireguard",
                "tag": "warp-ep",
                "detour": "auto",
                "address": [
                "172.28.0.2/32",
                "2606:4700:110:8f2e:80bb:e73d:fdae:cd83/128"
                ],
                "private_key": "PqU93Guwb0FKUZdJ7XUOxbe/cn37e/GxWhjOjNZdSiQ=",
                "mtu": 1280,
                "peers": [
                    {
                        "address": "162.159.192.1",
                        "port": 2408,
                        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "allowed_ips": [
                            "0.0.0.0/0",
                            "::/0"
                            ],
                        "reserved": [0, 0, 0]
                    }
                    ]
                }
        ],
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "mtu": 1500,
                "address": "172.19.0.1/30",
                "auto_route": True,
                "route_exclude_address": [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.0.0/16",
                    "224.0.0.0/4",
                    "255.255.255.255/32",
                    "fc00::/7"
                  ]
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct-out"
            },
            selector_outbound,
            urltest_outbound,
            *outbounds
        ],
  "route": {
    "rules": [
        {
            "action": "sniff"
        },
        {
            "protocol": "dns",
            "action": "hijack-dns"
        },
        {
            "rule_set": [
                "geosite-category-media-ru-blocked",
                "db-category-ai-chat"
            ],
            "outbound": "proxy-out"
        },
        {
            "rule_set": [
                "geosite-category-ru",
                "geoip-ru"
            ],
            "outbound": "direct-out"
        }
    ],
    "rule_set": [
        {
            "type": "remote",
            "tag": "db-github",
            "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-github.srs",
            "download_detour": "direct-out"
        },
        {
            "type": "remote",
            "tag": "geosite-category-media-ru-blocked",
            "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-media-ru-blocked.srs",
            "download_detour": "direct-out"
        },
        {
            "type": "remote",
            "tag": "geosite-category-ru",
            "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ru.srs",
            "download_detour": "direct-out"
        },
        {
            "type": "remote",
            "tag": "geoip-ru",
            "url": "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-ru.srs",
            "download_detour": "direct-out"
        },
        {
            "type": "remote",
            "tag": "db-antizapret",
            "url": "https://github.com/savely-krasovsky/antizapret-sing-box/releases/latest/download/antizapret.srs",
            "download_detour": "direct-out"
        },
        {
            "type": "remote",
            "tag": "db-category-ai-chat",
            "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ai-!cn.srs",
            "download_detour": "direct-out"
        }
    ],
    "final": "proxy-out",
    "auto_detect_interface": True,
    "override_android_vpn": True,
    "default_domain_resolver": "dns-local"
  },
  "experimental": {
    "cache_file": {
      "enabled": True
    }
  }
}

    with open("sing-box.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated sing-box.json with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
