import base64
import json
import os
import urllib.parse
import requests


def parse_proxy_link(link: str) -> dict | None:
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    # ОСТАВЛЯЕМ: Защита от критического падения скрипта при битых URL
    try:
        parsed = urllib.parse.urlparse(link)
        _ = parsed.hostname  # Провоцируем проверку парсера
    except ValueError:
        print(f"Skipping malformed URL: {link[:30]}...")
        return None

    scheme = parsed.scheme.lower()
    params = urllib.parse.parse_qs(parsed.query)

    net_type = params.get("type", params.get("net", [""]))[0].lower()

    # ОСТАВЛЯЕМ: Фильтрация небезопасных соединений по вашему желанию
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        print(f"Skipping insecure node: {link[:30]}...")
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

        # Нам больше не нужны проверки "if net != 'tcp'". Пишем как есть.
        # Если транспорт окажется кривым (kcp, tcpconfigprxy) — clean_outbound всё исправит.
        if net_type:
            outbound["transport"] = {
                "type": net_type,
                "path": params.get("path", [None])[0],
                "headers": {"Host": params.get("host", [None])[0]} if params.get("host", [None])[0] else None,
                "service_name": params.get("serviceName", [None])[0]
            }

        return outbound

    # --- 2. VMESS ---
    elif scheme == "vmess":
        try:
            b64_data = parsed.netloc
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8")
            data = json.loads(decoded)

            outbound = {
                "type": "vmess",
                "tag": data.get("ps", tag),
                "server": data.get("add"),
                "server_port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "security": data.get("scy", "auto"),
            }

            if data.get("net"):
                outbound["transport"] = {
                    "type": data.get("net").lower(),
                    "path": data.get("path"),
                    "headers": {"Host": data.get("host")} if data.get("host") else None
                }

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
        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": parsed.hostname,
            "server_port": parsed.port,
            "password": parsed.username,
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

        if net_type:
            outbound["transport"] = {
                "type": net_type,
                "path": params.get("path", [None])[0],
                "headers": {"Host": params.get("host", [None])[0]} if params.get("host", [None])[0] else None,
                "service_name": params.get("serviceName", [None])[0]
            }

        return outbound

    # --- 4. HYSTERIA2 / HY2 ---
    elif scheme in ["hysteria2", "hy2"]:
        outbound = {
            "type": "hysteria2",
            "tag": tag,
            "server": parsed.hostname,
            "server_port": parsed.port,
            "password": parsed.username,
            "tls": {"enabled": True}
        }
        sni = params.get("sni", [None])[0]
        if sni:
            outbound["tls"]["server_name"] = sni

        return outbound

    # --- 5. SHADOWSOCKS ---
    elif scheme == "ss":
        try:
            # Извлекаем userinfo (все что до знака @)
            userinfo = parsed.username
            if not userinfo and parsed.netloc:
                userinfo = parsed.netloc.split("@")[0] if "@" in parsed.netloc else None

            method, password = None, None
            if userinfo:
                # Паддинг для Base64
                userinfo += "=" * (-len(userinfo) % 4)
                try:
                    decoded_userinfo = base64.b64decode(userinfo).decode("utf-8")
                    # Делим с правого края, так как пароль всегда последний, а в методе могут быть двоеточия
                    if ":" in decoded_userinfo:
                        method, password = decoded_userinfo.rsplit(":", 1)
                except Exception:
                    pass

            # Если base64 не сработал, пробуем стандартные свойства URL
            if not method or not password:
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
                "db-category-ai-chat",
                "geosite-category-media-ru-blocked"
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

    with open("sing-box-white.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated sing-box-white.json with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
