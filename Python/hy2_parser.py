import os
import re
import sys
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
# 1. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ВАЛИДАЦИИ И ОЧИСТКИ
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

def clean_urltest(urltest_dict: dict) -> dict:
    urltest_dict.pop("lru", None)
    urltest_dict.pop("timeout", None)
    return urltest_dict

def clean_outbound(outbound: dict) -> dict | None:
    if not outbound or outbound.get("type") != "hysteria2":
        return None

    tls_opts = outbound.get("tls", {})
    server_name = tls_opts.get("server_name")
    if not server_name or not str(server_name).strip():
        return None

    outbound.setdefault("up_mbps", 10)
    outbound.setdefault("down_mbps", 10)

    if tls_opts.get("enabled"):
        reality_opts = tls_opts.get("reality", {})
        fp_from_reality = reality_opts.pop("fingerprint", None)
        
        if fp_from_reality:
            utls_opts = tls_opts.setdefault("utls", {"enabled": True})
            if "fingerprint" not in utls_opts:
                utls_opts["fingerprint"] = fp_from_reality

        if not reality_opts:
            tls_opts.pop("reality", None)

    return outbound

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
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ["hysteria2", "hy2"]:
        return None

    params = urllib.parse.parse_qs(parsed.query)

    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        return None

    port = parsed.port or 443
    if port not in [443, 8443]:
        return None

    netloc = parsed.netloc
    password = parsed.username

    if not password and "@" in netloc:
        user_part = netloc.split("@")[0]
        password = user_part.split(":", 1)[-1] if ":" in user_part else user_part

    if not password:
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"

    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    # Жесткий фильтр: отсутствие SNI отбраковывает ноду
    if not sni:
        return None

    server_host = hostname
    if hostname.lower() != sni.lower():
        server_host = sni

    tls_opts = {
        "enabled": True,
        "server_name": sni
    }

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

    if not is_valid_server(outbound["server"]):
        return None

    sni_val = sni.lower()
    if not is_valid_domain(sni_val):
        return None

    RU_ZONES = (".ru", ".su", ".рф")
    if sni_val.endswith(RU_ZONES) or any(f"{zone}:" in sni_val for zone in RU_ZONES):
        return None

    return outbound

# =========================================================================
# 2. ОСНОВНАЯ ЛОГИКА
# =========================================================================

def main():
    # --- ОБЪЯВЛЯЕМ ПЕРЕМЕННЫЕ ---
    SOURCES_JSON_URL = "https://github.com/andmailg/Singbox-sub/raw/refs/heads/main/Python/src/sub_urls.json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    # --- ЗАГРУЗКА ИСТОЧНИКОВ ИЗ JSON (С РЕЗЕРВНЫМ ПАРСИНГОМ) ---
    print(f"Fetching subscription sources from {SOURCES_JSON_URL}...")
    try:
        sources_resp = requests.get(SOURCES_JSON_URL, headers=headers, timeout=15)
        sources_resp.raise_for_status()
        
        # Пробуем распарсить стандартным методом
        try:
            sub_urls = sources_resp.json()
        except Exception:
            # Если ctype не json или внутри обычный json string
            sub_urls = json.loads(sources_resp.text)

        # Если файл пришел как словарь { "urls": [...] }, извлекаем список
        if isinstance(sub_urls, dict):
            sub_urls = sub_urls.get("urls", list(sub_urls.values())[0])

        if not isinstance(sub_urls, list):
            raise ValueError(f"Expected list, got {type(sub_urls)}")

        print(f"✅ Successfully loaded {len(sub_urls)} subscription sources.")

    except Exception as e:
        print(f"❌ Error fetching sources JSON: {e}")
        print(f"Raw content response preview: {sources_resp.text[:200] if 'sources_resp' in locals() else 'No response'}")
        sys.exit(1)

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

    mmdb_path = "GeoLite2-Country.mmdb"
    if not os.path.exists(mmdb_path):
        print("Downloading local GeoIP database...")
        db_url = "https://git.io/GeoLite2-Country.mmdb"
        try:
            db_resp = requests.get(db_url, timeout=30)
            if db_resp.status_code == 200:
                with open(mmdb_path, "wb") as db_file:
                    db_file.write(db_resp.content)
        except Exception as e:
            print(f"Warning: GeoIP download failed: {e}")

    blocked_networks = []
    rkn_url = "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst"
    try:
        rkn_resp = requests.get(rkn_url, timeout=15)
        if rkn_resp.status_code == 200:
            for line in rkn_resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    blocked_networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    pass
    except Exception as e:
        print(f"Warning: RKN list failed: {e}")

    seen_servers = set()
    servers_to_resolve = set()
    pre_parsed_nodes = []

    EUROPE_COUNTRIES = {"NL", "DE", "FI", "PL", "FR", "GB", "EE", "LV", "LT", "SE", "CH", "AT", "US", "SG", "JP", "HK", "TR"}

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

            node_key = f"{server_address}:{outbound.get('server_port')}:{outbound.get('password')}"
            if node_key in seen_servers:
                continue
            seen_servers.add(node_key)

            pre_parsed_nodes.append(outbound)
            if server_address:
                servers_to_resolve.add(server_address)

    server_to_ip_map = {}
    def resolve_dns(host):
        try:
            return host, socket.gethostbyname(host)
        except Exception:
            return host, None

    with ThreadPoolExecutor(max_workers=100) as executor:
        dns_results = executor.map(resolve_dns, servers_to_resolve)
        for host, ip in dns_results:
            if ip:
                server_to_ip_map[host] = ip

    filtered_nodes = []
    mmdb_accessible = os.path.exists(mmdb_path) and maxminddb is not None
    reader = maxminddb.open_database(mmdb_path) if mmdb_accessible else None

    try:
        for outbound in pre_parsed_nodes:
            server_address = str(outbound.get("server", "")).lower()
            ip_addr = server_to_ip_map.get(server_address) or server_address

            if blocked_networks:
                try:
                    ip_obj = ipaddress.ip_address(ip_addr)
                    if any(ip_obj in network for network in blocked_networks):
                        continue
                except ValueError:
                    pass

            if reader:
                try:
                    geo_info = reader.get(ip_addr)
                    country_code = geo_info["country"].get("iso_code", "").upper() if geo_info and "country" in geo_info else "UNKNOWN"
                except Exception:
                    country_code = "UNKNOWN"
                
                if country_code != "UNKNOWN" and country_code not in EUROPE_COUNTRIES:
                    continue

            filtered_nodes.append(outbound)
    finally:
        if reader:
            reader.close()

    MAX_NODES_LIMIT = 5000
    total_found = len(filtered_nodes)
    if total_found > MAX_NODES_LIMIT:
        outbounds = [filtered_nodes[int(i * (total_found - 1) / (MAX_NODES_LIMIT - 1))] for i in range(MAX_NODES_LIMIT)]
    else:
        outbounds = filtered_nodes

    # Переименование и нумерация
    PREFIX = "Hy2"
    for idx, outbound in enumerate(outbounds, start=1):
        outbound["tag"] = f"{PREFIX}-{idx:03d}"

    node_tags = [o["tag"] for o in outbounds]

    # ЕСЛИ НОД НЕТ — АВАРИЙНО ЗАВЕРШАЕМ С КРИТИЧЕСКОЙ ОШИБКОЙ
    if not node_tags:
        print("❌ CRITICAL ERROR: No valid proxy nodes left after filtration!")
        sys.exit(1)

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
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "tag": "dns-local",
                    "server": "1.1.1.1",
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}
                },
                {
                    "type": "https",
                    "tag": "dns-remote",
                    "server": "1.1.1.1",
                    "detour": "proxy-out",
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}
                },
                {
                    "type": "fakeip",
                    "tag": "fakeip",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                },
                {"type": "local", "tag": "local"}
            ],
            "rules": [
                {"rule_set": ["geosite-category-ru", "geoip-ru"], "server": "dns-local"},
                {"query_type": ["HTTPS", "SVCB"], "action": "predefined", "rcode": "REFUSED"},
                {"rule_set": ["db-category-ai-chat", "geosite-category-media-ru-blocked"], "server": "fakeip"}
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
                "address": ["172.28.0.2/32", "2606:4700:110:8f2e:80bb:e73d:fdae:cd83/128"],
                "private_key": "PqU93Guwb0FKUZdJ7XUOxbe/cn37e/GxWhjOjNZdSiQ=",
                "mtu": 1280,
                "peers": [
                    {
                        "address": "162.159.192.1",
                        "port": 2408,
                        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "allowed_ips": ["0.0.0.0/0", "::/0"],
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
                    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                    "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fc00::/7"
                ]
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"},
            selector_outbound,
            urltest_outbound,
            *outbounds
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"rule_set": ["geosite-category-media-ru-blocked", "db-category-ai-chat"], "outbound": "proxy-out"},
                {"rule_set": ["geosite-category-ru", "geoip-ru"], "outbound": "direct-out"}
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
            "cache_file": {"enabled": True}
        }
    }

    # Гарантированное определение КОРНЯ репозитория для записи
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(script_dir, ".."))
    output_filename = os.path.join(root_dir, "sing-box-hy2.json")

    print(f"Writing config to: {output_filename}")
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"✅ SUCCESS! Generated file at '{output_filename}'")

if __name__ == "__main__":
    main()
