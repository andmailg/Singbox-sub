import base64
import ipaddress
import json
import os
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import requests

try:
    import maxminddb
except ImportError:
    maxminddb = None


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
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_regex.match(domain))


def is_valid_server(server: str) -> bool:
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
        return None

    scheme = parsed.scheme.lower()
    
    # Оставляем ТОЛЬКО Hysteria2
    if scheme not in ["hysteria2", "hy2"]:
        return None

    params = urllib.parse.parse_qs(parsed.query)

    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure in ["1", "true", "True"]:
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
        "tls": tls_opts,
    }

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
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    outbound.setdefault("up_mbps", 10)
    outbound.setdefault("down_mbps", 10)
    return outbound


def clean_urltest(outbound: dict) -> dict:
    # Очистка urltest по вашим правилам
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
            print(f"Error downloading GeoIP database: {e}")

    blocked_networks = []
    rkn_url = "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst"
    try:
        rkn_resp = requests.get(rkn_url, timeout=15)
        if rkn_resp.status_code == 200:
            for line in rkn_resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                raw_cidr = line.split()[0]
                try:
                    blocked_networks.append(
                        ipaddress.ip_network(raw_cidr, strict=False)
                    )
                except ValueError:
                    continue
    except Exception as e:
        print(f"Error loading RKN blacklist: {e}")

    seen_nodes = set()
    servers_to_resolve = set()
    pre_parsed_nodes = []

    ALLOWED_COUNTRIES = {
        "NL", "DE", "FI", "PL", "FR", "GB", "EE", "LV", "LT", "SE", "CH", "AT", "US", "SG", "JP", "HK", "TR"
    }

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

            # Уникальный ключ по хосту, порту и паролю
            node_key = (server_address, outbound.get("server_port"), outbound.get("password"))
            if node_key in seen_nodes:
                continue
            seen_nodes.add(node_key)

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
    reader = (
        maxminddb.open_database(mmdb_path)
        if (os.path.exists(mmdb_path) and maxminddb)
        else None
    )

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
                    country_code = (
                        geo_info["country"].get("iso_code", "").upper()
                        if geo_info and "country" in geo_info
                        else "UNKNOWN"
                    )
                except Exception:
                    country_code = "UNKNOWN"

                if country_code not in ALLOWED_COUNTRIES:
                    continue

            filtered_nodes.append(outbound)
    finally:
        if reader:
            reader.close()

    # Формируем теги
    seen_tags = {}
    for outbound in filtered_nodes:
        base_tag = outbound.get("tag", "Node")
        if base_tag in seen_tags:
            seen_tags[base_tag] += 1
            outbound["tag"] = f"{base_tag} #{seen_tags[base_tag]}"
        else:
            seen_tags[base_tag] = 0
            outbound["tag"] = base_tag

    node_tags = [o["tag"] for o in filtered_nodes]
    if not node_tags:
        print("Error: No valid Hy2 proxy nodes left after filtration!")
        return

    # Формирование итогового JSON в строгом соответствии с old.json
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
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                },
                {
                    "type": "https",
                    "tag": "dns-remote",
                    "server": "1.1.1.1",
                    "detour": "proxy-out",
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                },
                {
                    "type": "fakeip",
                    "tag": "fakeip",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18",
                },
                {"type": "local", "tag": "local"},
            ],
            "rules": [
                {
                    "rule_set": ["geosite-category-ru", "geoip-ru"],
                    "server": "dns-local",
                },
                {
                    "query_type": ["HTTPS", "SVCB"],
                    "action": "predefined",
                    "rcode": "REFUSED",
                },
                {
                    "rule_set": [
                        "db-category-ai-chat",
                        "geosite-category-media-ru-blocked",
                    ],
                    "server": "fakeip",
                },
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
            "cache_capacity": 2048,
        },
        "endpoints": [
            {
                "type": "wireguard",
                "tag": "warp-ep",
                "detour": "auto",
                "address": [
                    "172.28.0.2/32",
                    "2606:4700:110:8f2e:80bb:e73d:fdae:cd83/128",
                ],
                "private_key": os.environ.get(
                    "WARP_PRIVATE_KEY",
                    "PqU93Guwb0FKUZdJ7XUOxbe/cn37e/GxWhjOjNZdSiQ=",
                ),
                "mtu": 1280,
                "peers": [
                    {
                        "address": "162.159.192.1",
                        "port": 2408,
                        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "allowed_ips": ["0.0.0.0/0", "::/0"],
                        "reserved": [0, 0, 0],
                    }
                ],
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
                    "fc00::/7",
                ],
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"},
            selector_outbound,
            urltest_outbound,
            *filtered_nodes,
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"rule_set": ["db-category-ai-chat"], "outbound": "warp-ep"},
                {
                    "rule_set": ["geosite-category-media-ru-blocked"],
                    "outbound": "proxy-out",
                },
                {
                    "rule_set": ["geosite-category-ru", "geoip-ru"],
                    "outbound": "direct-out",
                },
            ],
            "rule_set": [
                {
                    "type": "remote",
                    "tag": "db-github",
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-github.srs",
                    "download_detour": "direct-out",
                },
                {
                    "type": "remote",
                    "tag": "geosite-category-media-ru-blocked",
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-media-ru-blocked.srs",
                    "download_detour": "direct-out",
                },
                {
                    "type": "remote",
                    "tag": "geosite-category-ru",
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ru.srs",
                    "download_detour": "direct-out",
                },
                {
                    "type": "remote",
                    "tag": "geoip-ru",
                    "url": "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-ru.srs",
                    "download_detour": "direct-out",
                },
                {
                    "type": "remote",
                    "tag": "db-antizapret",
                    "url": "https://github.com/savely-krasovsky/antizapret-sing-box/releases/latest/download/antizapret.srs",
                    "download_detour": "direct-out",
                },
                {
                    "type": "remote",
                    "tag": "db-category-ai-chat",
                    "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ai-!cn.srs",
                    "download_detour": "direct-out",
                },
            ],
            "final": "proxy-out",
            "auto_detect_interface": True,
            "override_android_vpn": True,
            "default_domain_resolver": "dns-local",
        },
        "experimental": {"cache_file": {"enabled": True}},
    }

    with open("sing-box.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(
        f"Successfully generated sing-box.json with {len(filtered_nodes)} Hysteria2 nodes."
    )


if __name__ == "__main__":
    main()
