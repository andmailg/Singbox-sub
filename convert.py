import base64
import json
import os
import urllib.parse
import requests


def parse_proxy_link(link: str) -> dict | None:
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    parsed = urllib.parse.urlparse(link)
    scheme = parsed.scheme.lower()
    params = urllib.parse.parse_qs(parsed.query)

    # Исключаем транспорт xhttp
    net_type = params.get("type", params.get("net", [""]))[0].lower()
    header_type = params.get("headerType", [""])[0].lower()
    if net_type in ["xhttp", "httpget"] or header_type in ["xhttp", "httpget"]:
        print(f"Skipping unsupported xhttp node: {link[:30]}...")
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Node"

    # --- 1. VLESS ---
    if scheme == "vless":
        outbound = {
            "type": "vless",
            "tag": tag,
            "server": parsed.hostname,
            "server_port": parsed.port,
            "uuid": parsed.username,
        }

        flow = params.get("flow", [None])[0]
        if flow:
            outbound["flow"] = flow

        security = params.get("security", ["none"])[0]
        if security in ["tls", "reality"]:
            tls_opts = {"enabled": True}
            sni = params.get("sni", [None])[0]
            if sni:
                tls_opts["server_name"] = sni

            fp = params.get("fp", [None])[0]
            if fp:
                tls_opts["utls"] = {"enabled": True, "fingerprint": fp}

            if security == "reality":
                pbk = params.get("pbk", [None])[0]
                sid = params.get("sid", [None])[0]
                reality_opts = {}
                if pbk:
                    reality_opts["public_key"] = pbk
                if sid:
                    reality_opts["short_id"] = sid
                tls_opts["reality"] = reality_opts

            outbound["tls"] = tls_opts

        net = net_type or "tcp"
        if net != "tcp":
            transport = {"type": net}
            path = params.get("path", [None])[0]
            host = params.get("host", [None])[0]
            service_name = params.get("serviceName", [None])[0]
            if path:
                transport["path"] = path
            if host:
                transport["headers"] = {"Host": host}
            if service_name:
                transport["service_name"] = service_name
            outbound["transport"] = transport

        return outbound

    # --- 2. VMESS ---
    elif scheme == "vmess":
        try:
            b64_data = parsed.netloc
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8")
            data = json.loads(decoded)

            net = data.get("net", "tcp").lower()
            if net in ["xhttp", "httpget"] or data.get("type", "").lower() in ["xhttp", "httpget"]:
                print(f"Skipping unsupported xhttp VMess node: {data.get('ps')}")
                return None

            outbound = {
                "type": "vmess",
                "tag": data.get("ps", tag),
                "server": data.get("add"),
                "server_port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "security": data.get("scy", "auto"),
            }

            if net != "tcp":
                transport = {"type": net}
                if data.get("path"):
                    transport["path"] = data.get("path")
                if data.get("host"):
                    transport["headers"] = {"Host": data.get("host")}
                outbound["transport"] = transport

            if data.get("tls") == "tls":
                tls_opts = {"enabled": True}
                if data.get("sni"):
                    tls_opts["server_name"] = data.get("sni")
                if data.get("fp"):
                    tls_opts["utls"] = {
                        "enabled": True,
                        "fingerprint": data.get("fp"),
                    }
                outbound["tls"] = tls_opts

            return outbound
        except Exception:
            return None

    # --- 3. TROJAN ---
    elif scheme == "trojan":
        password = parsed.username
        server = parsed.hostname
        port = parsed.port

        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": password,
        }

        security = params.get("security", ["tls"])[0]
        if security in ["tls", "reality"]:
            tls_opts = {"enabled": True}
            sni = params.get("sni", [None])[0]
            if sni:
                tls_opts["server_name"] = sni.split(":")[0]

            fp = params.get("fp", [None])[0]
            if fp:
                tls_opts["utls"] = {"enabled": True, "fingerprint": fp}

            insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
            if insecure == "1":
                tls_opts["insecure"] = True

            if security == "reality":
                pbk = params.get("pbk", [None])[0]
                sid = params.get("sid", [None])[0]
                reality_opts = {}
                if pbk:
                    reality_opts["public_key"] = pbk
                if sid:
                    reality_opts["short_id"] = sid
                tls_opts["reality"] = reality_opts

            outbound["tls"] = tls_opts

        net = net_type or "tcp"
        if net != "tcp":
            transport = {"type": net}
            path = params.get("path", [None])[0]
            host = params.get("host", [None])[0]
            service_name = params.get("serviceName", [None])[0]

            if path:
                transport["path"] = path
            if host:
                transport["headers"] = {"Host": host}
            if service_name:
                transport["service_name"] = service_name

            outbound["transport"] = transport

        return outbound

    # --- 4. HYSTERIA2 / HY2 ---
    elif scheme in ["hysteria2", "hy2"]:
        password = parsed.username
        server = parsed.hostname
        port = parsed.port

        outbound = {
            "type": "hysteria2",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": password,
        }

        tls_opts = {"enabled": True}
        sni = params.get("sni", [None])[0]
        if sni:
            tls_opts["server_name"] = sni

        insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
        if insecure == "1":
            tls_opts["insecure"] = True

        outbound["tls"] = tls_opts

        return outbound

    # --- 5. SHADOWSOCKS ---
    elif scheme == "ss":
        try:
            userinfo = parsed.username
            if not userinfo and parsed.netloc:
                userinfo = parsed.netloc.split("@")[0]

            method, password = None, None
            if userinfo:
                userinfo += "=" * (-len(userinfo) % 4)
                try:
                    decoded_userinfo = base64.b64decode(userinfo).decode("utf-8")
                    method, password = decoded_userinfo.split(":", 1)
                except Exception:
                    method = parsed.username
                    password = parsed.password

            return {
                "type": "shadowsocks",
                "tag": tag,
                "server": parsed.hostname,
                "server_port": parsed.port,
                "method": method,
                "password": password,
            }
        except Exception:
            return None

    return None


def clean_outbound(outbound: dict) -> dict:
    """Применение исправлений для sing-box."""
    # 1. Удаление transport/packet_encoding для TCP
    transport = outbound.get("transport", {})
    if transport.get("type") == "tcp":
        outbound.pop("transport", None)
        outbound.pop("packet_encoding", None)

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
        if outbound.get("alterId") == 0:
            outbound.pop("alterId", None)

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
    resp = requests.get(sub_url, timeout=15)
    resp.raise_for_status()

    content = resp.text.strip()

    try:
        content_padded = content + "=" * (-len(content) % 4)
        decoded_content = base64.b64decode(content_padded).decode("utf-8")
        links = decoded_content.splitlines()
    except Exception:
        links = content.splitlines()

    outbounds = []
    seen_tags = {}

    for link in links:
        outbound = parse_proxy_link(link)
        if outbound:
            outbound = clean_outbound(outbound)

            # Обеспечиваем уникальность тегов
            base_tag = outbound["tag"]
            if base_tag in seen_tags:
                seen_tags[base_tag] += 1
                outbound["tag"] = f"{base_tag} #{seen_tags[base_tag]}"
            else:
                seen_tags[base_tag] = 0

            outbounds.append(outbound)

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
        "url": "https://www.gstatic.com/generate_204",
        "interval": "10m",
        "tolerance": 50,
    }
    urltest_outbound = clean_urltest(urltest_outbound)

    singbox_config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": "dns-local", "server": "1.1.1.1"},
                {"type": "https", "tag": "doh-8", "server": "8.8.8.8"},
                {
                    "type": "https",
                    "tag": "doh-comss",
                    "domain_resolver": "dns-local",
                    "server": "dns.comss.one",
                    "detour": "proxy-out",
                },
                {
                    "type": "https",
                    "tag": "doh-xbox",
                    "domain_resolver": "dns-local",
                    "server": "xbox-dns.ru",
                    "detour": "proxy-out",
                },
                {
                    "type": "https",
                    "tag": "doh-geohide",
                    "domain_resolver": "dns-local",
                    "server": "dns.geohide.ru",
                    "server_port": 444,
                    "detour": "proxy-out",
                },
                {
                    "type": "https",
                    "tag": "doh-nullproxy",
                    "domain_resolver": "dns-local",
                    "server": "dns.nullsproxy.com",
                    "detour": "proxy-out",
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
                    "rule_set": "db-category-ai-chat",
                    "server": "doh-geohide",
                },
                {"query_type": ["A", "AAAA"], "server": "dns-local"},
            ],
            "final": "dns-local",
            "strategy": "prefer_ipv4",
            "cache_capacity": 2048,
        },
        "inbounds": [
            {
                "type": "tun",
                "mtu": 1420,
                "address": "172.19.0.0/30",
                "auto_route": False
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-out", "network_strategy": "hybrid"},
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
        "ip_cidr": [
          "1.1.1.1",
          "8.8.8.8",
          "192.168.0.0/16",
          "172.19.0.0/30"
        ],
        "outbound": "direct-out"
      },
      {
        "rule_set": [
          "db-antizapret",
          "db-category-ai-chat"
        ],
        "outbound": "proxy-out"
      },
      {
        "rule_set": "geosite-category-ru",
        "outbound": "direct-out"
      },
      {
        "protocol": "quic",
        "outbound": "proxy-out"
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
        "tag": "db-google",
        "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-google.srs",
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
    "auto_detect_interface": False,
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
