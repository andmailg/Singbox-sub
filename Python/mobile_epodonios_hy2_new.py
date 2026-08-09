import base64
import ipaddress  # Встроенный модуль для работы с IP и подсетями
import json
import os
import re
import socket
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
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

    # 2. Фильтрация по портам (оставляем только 443)
    port = parsed.port or 443
    if port != 443:
        print(f"Skipping Hy2 node: invalid port ({port})")
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
        print("Skipping Hy2 node: missing password")
        return None

    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"
    )

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
        "up_mbps": 10,
        "down_mbps": 10,
        "password": urllib.parse.unquote(password),
        "tls": tls_opts,
    }

    # =========================================================================
    # ГЛОБАЛЬНЫЕ ПРОВЕРКИ (SERVER, SNI, RU DOMAINS)
    # =========================================================================

    # Проверка корректности адреса сервера
    if not is_valid_server(outbound["server"]):
        print(
            f"Skipping node '{tag}': invalid 'server' field ('{outbound['server']}')"
        )
        return None

    # Валидация SNI (если задан)
    if sni:
        sni_val = sni.lower()
        if not is_valid_domain(sni_val):
            print(f"Skipping node '{tag}': invalid SNI ('{sni_val}')")
            return None

        # Запрет российских доменов в SNI
        RU_ZONES = (".ru", ".su", ".рф")
        if sni_val.endswith(RU_ZONES) or any(
            f"{zone}:" in sni_val for zone in RU_ZONES
        ):
            print(
                f"Skipping node '{tag}': forbidden Russian domain in SNI ('{sni_val}')"
            )
            return None

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение Hysteria2 ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    # Убеждаемся в наличии фиксированных скоростей
    outbound.setdefault("up_mbps", 10)
    outbound.setdefault("down_mbps", 10)

    # Безопасный перенос fingerprint из reality в utls
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
    # --- НОВЫЙ ИСТОЧНИК ПОДПИСОК ИЗ ВНЕШНЕГО JSON ---
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

    outbounds = []
    seen_servers = set()
    servers_to_resolve = set()
    pre_parsed_nodes = []

    # Разрешенные страны (Европа + США + Азия)
    EUROPE_COUNTRIES = {
        "NL", "DE", "FI", "PL", "FR", "GB", "EE", "LV", "LT", "SE", "CH", "AT",
        "US", "SG", "JP", "HK", "TR"
    }

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

    # --- ШАГ 3: ПРОПУСК УЗЛОВ БЕЗ ФИЛЬТРАЦИИ ---
    filtered_nodes = list(pre_parsed_nodes)

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

    # --- ШАГ 5: УНИКАЛИЗАЦИЯ ТЕГОВ ---
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

    with open("sing-box-epodonios-hy2-new.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated sing-box-epodonios-hy2-new.json with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
