import base64
import bisect
import ipaddress
import json
import os
import re
import socket
import urllib.parse
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
    clean_domain = domain.split(":")[0].strip()
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(clean_domain))

def is_valid_host(host_str: str) -> bool:
    """Проверяет, является ли host строго валидным доменным именем."""
    if not host_str or not isinstance(host_str, str):
        return False
    clean_host = host_str.strip().strip("[]").split(":")[0].strip()
    if clean_host.startswith("/"):
        return False
    if is_valid_ip(clean_host):
        return False
    return is_valid_domain(clean_host)

def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server (содержит strictly IP-адрес или домен)."""
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]").split(":")[0].strip()
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)

def is_russian_node(server_str: str, mmdb_path: str = "GeoLite2-Country.mmdb") -> bool:
    """
    Проверяет, относится ли сервер (IP или домен) к Российской Федерации.
    Использует базу maxminddb. Если это домен, сначала резолвит его в IP.
    """
    if not maxminddb:
        return False
        
    clean_server = server_str.strip("[]").split(":")[0].strip()
    ip_to_check = None
    
    if is_valid_ip(clean_server):
        ip_to_check = clean_server
    elif is_valid_domain(clean_server):
        try:
            ip_to_check = socket.gethostbyname(clean_server)
        except Exception:
            return False
    else:
        return False

    try:
        if os.path.exists(mmdb_path):
            with maxminddb.open_database(mmdb_path) as reader:
                record = reader.get(ip_to_check)
                if record and isinstance(record, dict):
                    country_iso = record.get("country", {}).get("iso_code")
                    return country_iso == "RU"
    except Exception as e:
        print(f"Error checking GeoIP for {ip_to_check}: {e}")
        
    return False

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
    if scheme != "vless":
        return None
        
    params = urllib.parse.parse_qs(parsed.query)
    security = params.get("security", ["none"])[0].lower()
    if security not in ["", "none"]:
        return None
        
    encryption = params.get("encryption", ["none"])[0].lower()
    if encryption != "none":
        return None
        
    net_type = params.get("type", ["tcp"])[0].lower()
    if net_type != "tcp":
        return None
        
    header_type = params.get("headerType", [""])[0].lower()
    if header_type != "http":
        return None
        
    uuid_str = parsed.username
    if not uuid_str and "@" in parsed.netloc:
        uuid_str = parsed.netloc.split("@")[0]
    if not uuid_str:
        print("Skipping VLESS node: missing UUID")
        return None
        
    host = params.get("host", [""])[0].strip()
    if not host or not is_valid_host(host):
        print(f"Skipping VLESS node: invalid or missing 'host' domain ('{host[:30]}...')")
        return None
        
    if "google.com" in host.lower():
        print(f"Skipping VLESS node: 'host' contains google.com ('{host}')")
        return None
        
    port = parsed.port or 80
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-HTTP-Node"
    
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": uuid_str,
        "transport": {
            "type": "http",
            "host": [host]
        }
    }
    return outbound

def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и валидация VLESS HTTP ноды под спецификацию sing-box."""
    if not outbound:
        return None
    if outbound.get("type") == "vless":
        transport = outbound.get("transport", {})
        if transport.get("type") == "http":
            hosts = transport.get("host")
            if not hosts or not isinstance(hosts, list) or len(hosts) == 0:
                return None
            if not is_valid_host(str(hosts[0]).strip()):
                return None
        outbound.pop("tls", None)
    return outbound

def main():
    # Укажите вашу ссылку на JSON-список подписок
    SOURCES_JSON_URL = "https://github.com/andmailg/Singbox-sub/raw/refs/heads/main/Python/src/sub_urls.json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    print(f"Fetching subscription sources from {SOURCES_JSON_URL}...")
    try:
        sources_resp = requests.get(SOURCES_JSON_URL, headers=headers, timeout=15)
        sources_resp.raise_for_status()
        sub_urls = sources_resp.json()
        if isinstance(sub_urls, dict):
            sub_urls = list(sub_urls.values())
        if not isinstance(sub_urls, list):
            raise ValueError(f"Expected list or dict, got {type(sub_urls)}")
        print(f" Successfully loaded {len(sub_urls)} subscription sources.")
    except Exception as e:
        print(f" Error fetching sources JSON: {e}")
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
            db_resp = requests.get(db_url, timeout=45)
            if db_resp.status_code == 200:
                with open(mmdb_path, "wb") as db_file:
                    db_file.write(db_resp.content)
                print("Local GeoIP database downloaded successfully.")
        except Exception as e:
            print(f"Error downloading GeoIP database: {e}")

    # --- СКАЧИВАНИЕ И ПОДГОТОВКА ЧЕРНОГО СПИСКА CIDR РКН ---
    print("Downloading RKN blocked CIDR list...")
    rkn_url = "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst"
    
    rkn_ranges_v4 = []
    rkn_ranges_v6 = []
    try:
        rkn_resp = requests.get(rkn_url, timeout=15)
        if rkn_resp.status_code == 200:
            raw_blocked_networks = []
            for line in rkn_resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    # В оригинальном dump.csv от zapret-info подсети разделены ';'
                    # Парсим первый элемент строки на наличие валидных сетей
                    parts = line.split(';')
                    if not parts:
                        continue
                    cidr_candidates = parts[0].split(',') # Бывают перечисления через запятую
                    for candidate in cidr_candidates:
                        candidate = candidate.strip()
                        if '/' in candidate:
                            net_obj = ipaddress.ip_network(candidate, strict=False)
                            raw_blocked_networks.append(net_obj)
                except (ValueError, IndexError):
                    continue
            
            blocked_networks = list(ipaddress.collapse_addresses(raw_blocked_networks))
            
            for net in blocked_networks:
                if net.version == 4:
                    rkn_ranges_v4.append((int(net.network_address), int(net.broadcast_address)))
                else:
                    rkn_ranges_v6.append((int(net.network_address), int(net.broadcast_address)))
            
            rkn_ranges_v4.sort(key=lambda x: x[0])
            rkn_ranges_v6.sort(key=lambda x: x[0])
            print(f"Successfully loaded and optimized {len(blocked_networks)} networks from RKN list.")
        else:
            print(f"Failed to download RKN list. Status code: {rkn_resp.status_code}")
    except Exception as e:
        print(f"Error loading RKN blacklist: {e}")

    # Создаем плоские списки стартовых адресов для бинарного поиска
    starts_v4 = [r[0] for r in rkn_ranges_v4]
    starts_v6 = [r[0] for r in rkn_ranges_v6]

    def is_ip_blocked(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ip_int = int(ip_obj)
        except ValueError:
            return False

        if ip_obj.version == 4:
            idx = bisect.bisect_right(starts_v4, ip_int) - 1
            if idx >= 0 and rkn_ranges_v4[idx][0] <= ip_int <= rkn_ranges_v4[idx][1]:
                return True
        else:
            idx = bisect.bisect_right(starts_v6, ip_int) - 1
            if idx >= 0 and rkn_ranges_v6[idx][0] <= ip_int <= rkn_ranges_v6[idx][1]:
                return True
        return False

    seen_servers = set()
    pre_parsed_nodes = []
    print(f"Parsing, deduplicating and geo-filtering {len(links)} links...")

    for link in links:
        outbound = parse_proxy_link(link)
        if outbound:
            outbound = clean_outbound(outbound)
            if not outbound:
                continue

            node_tag = str(outbound.get("tag", "")).lower()
            server_address = str(outbound.get("server", "")).strip().lower()

            # --- СТРОГАЯ ФИЛЬТРАЦИЯ РФ (Тег + База GeoIP) ---
            if "ru" in node_tag or "russia" in node_tag:
                continue

            if is_russian_node(server_address, mmdb_path):
                print(f"Skipping node '{outbound.get('tag')}': Server {server_address} is physically located in RU.")
                continue

            if server_address in seen_servers:
                continue
            seen_servers.add(server_address)
            pre_parsed_nodes.append(outbound)

    # --- ВТОРОЙ ЭТАП: ФИЛЬТРАЦИЯ ПО КЛАДБИЩУ IP РКН ---
    filtered_nodes = []
    for outbound in pre_parsed_nodes:
        node_ip_str = outbound.get("server", "").strip("[]")

        # Если в server домен — резолвим его в IP для сверки с подсетями РКН
        if not is_valid_ip(node_ip_str):
            try:
                node_ip_str = socket.gethostbyname(node_ip_str)
            except Exception:
                pass  # Если не резолвится, оставляем как есть

        if is_ip_blocked(node_ip_str):
            print(f"Skipping node '{outbound.get('tag')}': IP {node_ip_str} is in RKN blocked subnet.")
            continue
        filtered_nodes.append(outbound)

    valid_nodes = filtered_nodes
    print(f"Всего выбрано {len(valid_nodes)} валидных VLESS HTTP узлов (после очистки).")

    for idx, outbound in enumerate(valid_nodes, start=1):
        outbound["tag"] = f"node-{idx}"

    node_tags = [o["tag"] for o in valid_nodes]
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

    # Синтаксически корректные правила и remote-ссылки для srs-наборов sing-box
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
                        "geosite-ru",
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
                        "antizapret"
                    ],
                    "server": "fakeip"
                }
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
            "cache_capacity": 2048
        },
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
            *valid_nodes
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
                        "antizapret"
                    ],
                    "outbound": "proxy-out"
                },
                {
                    "rule_set": [
                        "geosite-ru",
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
            "final": "direct-out",
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

    output_filename = "sing-box-vless-http.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)
    print(f"Successfully generated {output_filename} with {len(valid_nodes)} nodes.")


if __name__ == "__main__":
    main()
