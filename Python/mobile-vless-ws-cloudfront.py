import base64
import ipaddress  # Встроенный модуль для работы с IP и подсетями
import json
import os
import re
import socket
import sys
import urllib.parse
import requests

# Для работы с локальной базой GeoIP
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
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_regex.match(clean_domain))


def is_valid_host(host_str: str) -> bool:
    """Проверяет, является ли host валидным доменным именем или IP (для Cloudfront/CDN)."""
    if not host_str or not isinstance(host_str, str):
        return False

    clean_host = host_str.strip().strip("[]").split(":")[0].strip()
    if clean_host.startswith("/"):
        return False

    return is_valid_domain(clean_host) or is_valid_ip(clean_host)


def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server (может быть IP или домен вроде cloudfront.net)."""
    if not server or "@" in server:
        return False
    clean_server = server.strip().strip("[]").split(":")[0].strip()
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
    # ЖЕСТКИЙ ФИЛЬТР: Пропускаем ТОЛЬКО VLESS
    # -------------------------------------------------------------------------
    if scheme != "vless":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Проверка типа сети
    net_type = params.get("type", [""])[0].lower()
    if net_type != "ws":
        return None

    # 2. Извлечение параметров host и path для ws
    host = params.get("host", [""])[0].strip()
    path = params.get("path", ["/"])[0].strip()

    # 3. ФИЛЬТР CLOUDFRONT: server ИЛИ host должны содержать cloudfront.net
    has_cloudfront = (
        "cloudfront.net" in hostname.lower() or "cloudfront.net" in host.lower()
    )
    if not has_cloudfront:
        return None

    # 4. Извлечение UUID (user)
    uuid_str = parsed.username
    if not uuid_str and "@" in parsed.netloc:
        uuid_str = parsed.netloc.split("@")[0]
    if not uuid_str:
        print("Skipping VLESS node: missing UUID")
        return None

    port = parsed.port or 80
    tag = (
        urllib.parse.unquote(parsed.fragment)
        if parsed.fragment
        else "VLESS-WS-Node"
    )

    # 5. Сборка объекта outbound для sing-box (Современный WS-транспорт)
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": uuid_str,
        "transport": {"type": "ws", "path": path},
    }

    if host:
        # Для sing-box 1.10+ передается внутри объекта headers
        outbound["transport"]["headers"] = {"Host": host}

    # 6. Динамическая настройка шифрования
    security = params.get("security", ["none"])[0].lower()
    if security in ["tls", "reality"]:
        outbound["tls"] = {
            "enabled": True,
            "server_name": host if host else hostname,
            "insecure": False,
        }
        if security == "reality":
            pbk = params.get("pbk", [""])[0].strip()
            sid = params.get("sid", [""])[0].strip()
            if pbk:
                outbound["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": pbk,
                    "short_id": sid,
                }

    # 7. ГЛОБАЛЬНЫЕ ПРОВЕРКИ СЕРВЕРА
    if not is_valid_server(outbound["server"]):
        print(
            f"Skipping node '{tag}': 'server' is not valid ('{outbound['server']}')"
        )
        return None

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и валидация VLESS WS ноды под спецификацию sing-box."""
    if not outbound:
        return None
    if outbound.get("type") == "vless":
        transport = outbound.get("transport", {})
        if transport.get("type") != "ws":
            return None
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
        sources_resp = requests.get(
            SOURCES_JSON_URL, headers=headers, timeout=15
        )
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
        preview = (
            sources_resp.text[:200] if sources_resp is not None else "No response"
        )
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
                decoded_content = (
                    base64.b64decode(content_padded)
                    .decode("utf-8", errors="ignore")
                )
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
                    cidr_str = line.split()[0]
                    net_obj = ipaddress.ip_network(cidr_str, strict=False)
                    raw_blocked_networks.append(net_obj)
                except (ValueError, IndexError):
                    continue

            blocked_networks = list(
                ipaddress.collapse_addresses(raw_blocked_networks)
            )
            print(
                f"Successfully loaded and collapsed {len(blocked_networks)} blocked networks from RKN list."
            )
        else:
            blocked_networks = []
            print(
                f"Failed to download RKN list. Status code: {rkn_resp.status_code}"
            )
    except Exception as e:
        blocked_networks = []
        print(f"Error loading RKN blacklist: {e}")

    # --- ШАГ 1: ПАРСИНГ И ДЕДУПЛИКАЦИЯ С УЧЕТОМ UUID ---
    seen_nodes_fingerprints = set()
    pre_parsed_nodes = []

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

            # ИЗМЕНЕНО: уникальность проверяется по комбинации server + port + uuid + path
            server_val = str(outbound.get("server", "")).lower()
            port_val = str(outbound.get("server_port", "80"))
            uuid_val = str(outbound.get("uuid", "")).lower()
            path_val = str(outbound.get("transport", {}).get("path", "/")).lower()
            fingerprint = f"{server_val}:{port_val}:{uuid_val}:{path_val}"
            if fingerprint in seen_nodes_fingerprints:
                continue
            seen_nodes_fingerprints.add(fingerprint)
            pre_parsed_nodes.append(outbound)

    # --- Инициализация ридера GeoIP ---
    reader = None
    if maxminddb and os.path.exists(mmdb_path):
        try:
            reader = maxminddb.open_database(mmdb_path)
            print("GeoIP database loaded successfully for geolocation filtering.")
        except Exception as e:
            print(f"Error opening GeoIP database: {e}")

    # --- ШАГ 2: ФИЛЬТРАЦИЯ ПО РКН И ГЕОЛОКАЦИИ (GeoIP) ---
    filtered_nodes = []
    for outbound in pre_parsed_nodes:
        node_server = outbound.get("server", "").strip("[]")
        node_ip_str = node_server
        if not is_valid_ip(node_server):
            try:
                node_ip_str = socket.gethostbyname(node_server)
            except socket.gaierror:
                continue

        try:
            ip_obj = ipaddress.ip_address(node_ip_str)
            # 1. Проверка на блокировку в подсетях РКН
            is_blocked = any(ip_obj in net for net in blocked_networks)
            if is_blocked:
                print(
                    f"Skipping node '{outbound.get('tag')}': "
                    f"IP {node_ip_str} ({node_server}) is in RKN blocked subnet."
                )
                continue

            # 2. Использование GeoLite2: Исключение серверов из РФ
            if reader:
                try:
                    geo_data = reader.get(node_ip_str)
                    if geo_data and "country" in geo_data:
                        country_iso = geo_data["country"].get("iso_code", "")
                        if country_iso == "RU":
                            print(
                                f"Skipping node '{outbound.get('tag')}': "
                                f"IP {node_ip_str} ({node_server}) is located in Russia (GeoIP)."
                            )
                            continue
                except Exception:
                    pass
        except ValueError:
            pass

        filtered_nodes.append(outbound)

    if reader:
        reader.close()

    outbounds = filtered_nodes
    print(
        f"Всего выбрано {len(outbounds)} валидных VLESS WS узлов после всех этапов фильтрации."
    )

    if not outbounds:
        print("Error: No valid proxy nodes left after filtration!")
        return

    # --- ШАГ 3: ПРИСВОЕНИЕ УНИКАЛЬНЫХ ТЕГОВ С НУЛЯ (Исключает ошибку дублирования) ---
    for idx, outbound in enumerate(outbounds, start=1):
        outbound["tag"] = f"node-{idx}"
    node_tags = [o["tag"] for o in outbounds]

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
                        "geosite-category-ru"
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
        "http_clients": [
            {
                "tag": "rules-downloader"
                //"detour": "direct-out"
            }
        ],
        "route": {
            "default_http_client": "rules-downloader",
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
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-github.srs"
                },
                {
                    "type": "remote",
                    "tag": "geosite-category-media-ru-blocked",
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-media-ru-blocked.srs"
                },
                {
                    "type": "remote",
                    "tag": "geosite-category-ru",
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ru.srs"
                },
                {
                    "type": "remote",
                    "tag": "geoip-ru",
                    "url": "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-ru.srs"
                },
                {
                    "type": "remote",
                    "tag": "db-antizapret",
                    "url": "https://github.com/savely-krasovsky/antizapret-sing-box/releases/latest/download/antizapret.srs"
                },
                {
                    "type": "remote",
                    "tag": "db-category-ai-chat",
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ai-!cn.srs"
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

    output_filename = "sing-box-vless-ws.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)
    print(
        f"Successfully generated {output_filename} with {len(outbounds)} nodes."
    )


if __name__ == "__main__":
    main()
