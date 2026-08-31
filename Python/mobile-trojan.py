import base64
import ipaddress
import json
import os
import re
import urllib.parse
import requests


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
    """Проверяет корректность поля server."""
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]")
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)


def has_workers_dev(outbound: dict) -> bool:
    """Проверяет, содержит ли нода 'workers.dev'."""
    target = "workers.dev"

    server = outbound.get("server", "").lower()
    if target in server:
        return True

    tls = outbound.get("tls", {})
    if isinstance(tls, dict):
        server_name = tls.get("server_name", "").lower()
        if target in server_name:
            return True

    transport = outbound.get("transport", {})
    if isinstance(transport, dict):
        headers = transport.get("headers", {})
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k.lower() == "host" and target in str(v).lower():
                    return True

        hosts = transport.get("host", [])
        if isinstance(hosts, list):
            if any(target in str(h).lower() for h in hosts):
                return True
        elif isinstance(hosts, str) and target in hosts.lower():
            return True

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

    password = parsed.username
    if not password and "@" in parsed.netloc:
        password = parsed.netloc.split("@")[0]

    if not password:
        return None

    security = params.get("security", ["tls"])[0].lower()
    tls_enabled = security not in ["", "none"]

    port = port or (443 if tls_enabled else 80)

    if port == 443:
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Trojan-Node"

    host_raw = params.get("host", [""])[0].strip()
    sni_raw = params.get("sni", [""])[0].strip() or params.get("peer", [""])[0].strip()

    host = host_raw.split(":")[0].strip() if host_raw else ""
    sni = sni_raw.split(":")[0].strip() if sni_raw else ""

    if host and not is_valid_host(host):
        return None

    outbound = {
        "type": "trojan",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "password": password
    }

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

    net_type = (
        params.get("type", [""])[0].lower() 
        or params.get("net", [""])[0].lower()
        or params.get("headerType", [""])[0].lower()
    )
    
    if net_type in ["xhttp", "splithttp"] or (net_type and net_type not in ["tcp", "ws", "http", "grpc", "httpupgrade", "quic"]):
        return None

    # Сохраняем значения для фильтрации
    path_for_filter = params.get("path", [""])[0]
    service_name_for_filter = params.get("serviceName", [""])[0] or params.get("service_name", [""])[0]

    if net_type and net_type != "tcp":
        transport_config = {"type": net_type}

        path = params.get("path", [""])[0]
        if path and net_type in ["ws", "http", "httpupgrade"]:
            transport_config["path"] = path

        if host:
            if net_type == "http":
                transport_config["host"] = [host]
            elif net_type in ["ws", "httpupgrade"]:
                transport_config["headers"] = {"Host": host}

        service_name = params.get("serviceName", [""])[0] or params.get("service_name", [""])[0]
        if service_name and net_type == "grpc":
            transport_config["service_name"] = service_name

        outbound["transport"] = transport_config

    if not is_valid_server(outbound["server"]):
        return None

    # Финальная фильтрация нод с "BanV2ray" в любом из полей
    banv2ray_lower = "banv2ray"
    if (
        banv2ray_lower in password.lower()
        or banv2ray_lower in str(path_for_filter).lower()
        or banv2ray_lower in str(service_name_for_filter).lower()
    ):
        return None

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    if not outbound:
        return None

    if has_workers_dev(outbound):
        return None

    # --- ПРОВЕРКА БЛОКА TLS ---
    tls_config = outbound.get("tls")
    if tls_config:
        # Исключаем ноды с insecure: true
        if tls_config.get("insecure") is True:
            return None
        # Исключаем ноды, у которых TLS включен, но отсутствует server_name
        if not tls_config.get("server_name"):
            return None

    if outbound.get("type") == "trojan":
        if outbound.get("server_port") == 443:
            return None

        transport = outbound.get("transport")
        
        if transport:
            net_type = transport.get("type")

            if not net_type or net_type in ["xhttp", "splithttp"] or net_type not in ["ws", "http", "grpc", "httpupgrade", "quic"]:
                return None

            if net_type not in ["ws", "http", "httpupgrade"]:
                transport.pop("path", None)

            if net_type in ["ws", "httpupgrade"]:
                raw_host = transport.pop("host", None)
                if raw_host and "headers" not in transport:
                    h_val = raw_host[0] if isinstance(raw_host, list) else raw_host
                    if is_valid_host(str(h_val)):
                        transport["headers"] = {"Host": str(h_val)}

                headers = transport.get("headers", {})
                ws_host = headers.get("Host") or headers.get("host")
                if ws_host and not is_valid_host(str(ws_host).strip()):
                    return None

            elif net_type == "http":
                hosts = transport.get("host")
                if hosts:
                    first_host = hosts[0] if isinstance(hosts, list) else hosts
                    if not is_valid_host(str(first_host).strip()):
                        return None

    return outbound


def clean_urltest(outbound: dict) -> dict:
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
            
            blocked_networks = list(ipaddress.collapse_addresses(raw_blocked_networks))
            print(f"Successfully loaded and collapsed {len(blocked_networks)} blocked networks from RKN list.")
        else:
            blocked_networks = []
            print(f"Failed to download RKN list. Status code: {rkn_resp.status_code}")
    except Exception as e:
        blocked_networks = []
        print(f"Error loading RKN blacklist: {e}")

    seen_servers = set()
    filtered_nodes = []

    print(f"Parsing, filtering and deduplicating {len(links)} links...")
    for link in links:
        outbound = parse_proxy_link(link)
        if not outbound:
            continue

        outbound = clean_outbound(outbound)
        if not outbound:
            continue

        server = str(outbound.get("server", "")).strip("[]")

        # 1. Фильтр: только IP-адреса
        if not is_valid_ip(server):
            continue

        # 2. Исключаем RU ноды по тегу или домену
        node_tag = str(outbound.get("tag", "")).lower()
        if "ru" in node_tag or "russia" in node_tag:
            continue

        # 3. Дедупликация по IP
        if server in seen_servers:
            continue

        # 4. Проверка по черному списку РКН
        try:
            ip_obj = ipaddress.ip_address(server)
            if any(ip_obj in net for net in blocked_networks):
                print(f"Skipping node '{outbound.get('tag')}': IP {server} is in RKN blocked subnet.")
                continue
        except ValueError:
            continue

        seen_servers.add(server)
        filtered_nodes.append(outbound)

    outbounds = filtered_nodes
    print(f"Всего выбрано {len(outbounds)} валидных Trojan узлов с IP-адресами (порт != 443).")

    # --- УНИКАЛИЗАЦИЯ ТЕГОВ ---
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

    output_filename = "sing-box-trojan.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated {output_filename} with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
