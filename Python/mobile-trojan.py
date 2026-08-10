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

try:
    import maxminddb
except ImportError:
    maxminddb = None


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
    # Удаляем двоеточие с портом, если они случайно попали в домен
    clean_domain = domain.split(":")[0].strip()
    
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(clean_domain))


def is_valid_host(host_str: str) -> bool:
    """Проверяет, является ли host строго валидным доменным именем.
    IP-адреса, пути (/path) и рекламный мусор отбраковываются.
    """
    if not host_str or not isinstance(host_str, str):
        return False
    
    # Очищаем от пробелов, скобок IPv6 и возможного порта в конце (domain.com:443 -> domain.com)
    clean_host = host_str.strip().strip("[]").split(":")[0].strip()
    
    # Отбрасываем, если строка начинается с '/' (это path, а не host)
    if clean_host.startswith("/"):
        return False

    # host НЕ должен быть IP-адресом
    if is_valid_ip(clean_host):
        return False

    # Проверяем строго на доменное имя
    return is_valid_domain(clean_host)


def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server (не содержит '@', является валидным домена или IP)."""
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]")
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)


def is_valid_domain(domain: str) -> bool:
    """Проверяет, является ли строка валидным доменным именем (не IP-адресом)."""
    if not domain or is_valid_ip(domain):
        return False
    # Удаляем двоеточие с портом, если они случайно попали в домен
    clean_domain = domain.split(":")[0].strip()
    
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(clean_domain))


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
        
        # Безопасно извлекаем порт, защищаясь от корявых IPv6/мусора в URL
        try:
            port = parsed.port
        except ValueError:
            return None

    except Exception:
        print(f"Skipping malformed URL: {link[:30]}...")
        return None

    scheme = parsed.scheme.lower()

    if scheme != "trojan":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Извлечение пароля
    password = parsed.username
    if not password and "@" in parsed.netloc:
        password = parsed.netloc.split("@")[0]

    if not password:
        return None

    # 2. Определяем TLS
    security = params.get("security", ["tls"])[0].lower()
    tls_enabled = security not in ["", "none"]

    port = port or (443 if tls_enabled else 80)

    # Исключаем порт 443
    if port == 443:
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Trojan-Node"

    # 3. Извлекаем host и sni, ОЧИЩАЯ ИХ от порта (например, 'domain.com:443' -> 'domain.com')
    host_raw = params.get("host", [""])[0].strip()
    sni_raw = params.get("sni", [""])[0].strip() or params.get("peer", [""])[0].strip()

    host = host_raw.split(":")[0].strip() if host_raw else ""
    sni = sni_raw.split(":")[0].strip() if sni_raw else ""

    # Если задан host, проверяем его строго на домен
    if host and not is_valid_host(host):
        return None

    # 4. Сборка объекта outbound для sing-box
    outbound = {
        "type": "trojan",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "password": password
    }

    # Настройка TLS блока, если он включен
    if tls_enabled:
        tls_config = {"enabled": True}
        
        server_name = sni or host
        if server_name:
            if not is_valid_domain(server_name):
                return None
            tls_config["server_name"] = server_name

        insecure = params.get("allowInsecure", ["0"])[0] in ["1", "true"] or params.get("insecure", ["0"])[0] in ["1", "true"]
        if insecure:
            tls_config["insecure"] = True

        outbound["tls"] = tls_config

    # 5. Настройка транспорта (ws, http, grpc и т.д.)
    net_type = params.get("type", [""])[0].lower() or params.get("net", [""])[0].lower()
    if net_type and net_type != "tcp":
        transport_config = {"type": net_type}

        # 'path' допустим ТОЛЬКО для ws, http и httpupgrade
        path = params.get("path", [""])[0]
        if path and net_type in ["ws", "http", "httpupgrade"]:
            transport_config["path"] = path

        # Обработка host / headers
        if host:
            if net_type == "http":
                transport_config["host"] = [host]
            elif net_type in ["ws", "httpupgrade"]:
                transport_config["headers"] = {"Host": host}

        # Для gRPC используется service_name (без path!)
        service_name = params.get("serviceName", [""])[0] or params.get("service_name", [""])[0]
        if service_name and net_type == "grpc":
            transport_config["service_name"] = service_name

        outbound["transport"] = transport_config

    # ГЛОБАЛЬНЫЕ ПРОВЕРКИ (SERVER)
    if not is_valid_server(outbound["server"]):
        return None

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и валидация Trojan ноды под спецификацию sing-box."""
    if not outbound:
        return None

    if outbound.get("type") == "trojan":
        if outbound.get("server_port") == 443:
            return None

        transport = outbound.get("transport", {})
        net_type = transport.get("type")

        if net_type:
            # 1. Если это не ws/http/httpupgrade — удаляем 'path'
            if net_type not in ["ws", "http", "httpupgrade"]:
                transport.pop("path", None)

            # 2. Очистка и проверка для WebSocket / HTTPUpgrade
            if net_type in ["ws", "httpupgrade"]:
                # Удаляем случайно попавший на верхний уровень 'host'
                raw_host = transport.pop("host", None)
                if raw_host and "headers" not in transport:
                    h_val = raw_host[0] if isinstance(raw_host, list) else raw_host
                    if is_valid_host(str(h_val)):
                        transport["headers"] = {"Host": str(h_val)}

                headers = transport.get("headers", {})
                ws_host = headers.get("Host") or headers.get("host")
                if ws_host and not is_valid_host(str(ws_host).strip()):
                    return None

            # 3. Очистка и проверка для HTTP
            elif net_type == "http":
                hosts = transport.get("host")
                if hosts:
                    first_host = hosts[0] if isinstance(hosts, list) else hosts
                    if not is_valid_host(str(first_host).strip()):
                        return None

            # 4. Очистка для TCP (если случайно создался)
            elif net_type == "tcp":
                outbound.pop("transport", None)

    return outbound


def clean_urltest(outbound: dict) -> dict:
    """Удаление lru и timeout из urltest."""
    if outbound.get("type") == "urltest":
        outbound.pop("lru", None)
        outbound.pop("timeout", None)
    return outbound


def main():
    SOURCES_JSON_URL = "https://github.com/andmailg/Singbox-sub/raw/refs/heads/main/Python/src/sub_urls.json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    sources_resp = None
    print(f"Fetching subscription sources from {SOURCES_JSON_URL}...")
    try:
        sources_resp = requests.get(SOURCES_JSON_URL, headers=headers, timeout=15)
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
        preview = sources_resp.text[:200] if sources_resp is not None else "No response"
        print(f"Raw content response preview: {preview}")
        return

    links = []
    for url in sub_urls:
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code != 200:
                continue
            
            content = resp.text.strip()
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
    raw_blocked_networks = []
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
                    raw_blocked_networks.append(net_obj)
                except ValueError:
                    continue
            
            blocked_networks = list(ipaddress.collapse_addresses(raw_blocked_networks))
            print(f"Successfully loaded and collapsed {len(blocked_networks)} blocked networks from RKN list.")
        else:
            blocked_networks = []
            print(f"Failed to download RKN list. Status code: {rkn_resp.status_code}")
    except Exception as e:
        blocked_networks = []
        print(f"Error loading RKN blacklist: {e}")

    seen_servers = set()
    servers_to_resolve = set()
    pre_parsed_nodes = []

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

    # --- ШАГ 3: ФОРМИРОВАНИЕ ИТОГОВОГО СПИСКА УЗЛОВ И ФИЛЬТРАЦИЯ ПО РКН ---
    filtered_nodes = []

    for outbound in pre_parsed_nodes:
        server = outbound.get("server", "").strip("[]")
        
        node_ip_str = server_to_ip_map.get(server) if not is_valid_ip(server) else server

        if not node_ip_str:
            continue

        try:
            ip_obj = ipaddress.ip_address(node_ip_str)
        except ValueError:
            continue

        is_blocked = any(ip_obj in net for net in blocked_networks)

        if is_blocked:
            print(f"Skipping node '{outbound.get('tag')}': IP {node_ip_str} is in RKN blocked subnet.")
            continue

        filtered_nodes.append(outbound)

    outbounds = filtered_nodes
    print(f"Всего выбрано {len(outbounds)} валидных Trojan узлов (порт != 443).")

    # --- ШАГ 4: УНИКАЛИЗАЦИЯ ТЕГОВ ---
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
                        "geosite-category-media-ru-blocked",
                        "db-antizapret"
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
                "detour": "proxy-out",
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
                "mtu": 1420,
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
                        "db-category-ai-chat",
                        "db-antizapret"
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

    output_filename = "sing-box-trojan.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated {output_filename} with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
