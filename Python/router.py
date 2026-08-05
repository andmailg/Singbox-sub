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
            userinfo = parsed.username or (parsed.netloc.split("@")[0] if "@" in parsed.netloc else None)
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
    
    # 1. Валидация и очистка транспорта (Transport)
    transport = outbound.get("transport", {})
    if transport:
        # Список транспортов, которые официально поддерживает Sing-Box
        ALLOWED_TRANSPORTS = ["http", "ws", "grpc", "quic", "httpupgrade"]
        current_type = transport.get("type", "").lower()
        
        # Если транспорт tcp, tcpconfigprxy, kcp или любой другой неизвестный
        if current_type not in ALLOWED_TRANSPORTS or current_type == "tcp":
            if current_type and current_type != "tcp":
                print(f"Fixing outbound: Unknown transport '{current_type}' removed for node '{outbound.get('tag')}'")
            outbound.pop("transport", None)
            outbound.pop("packet_encoding", None)
        else:
            # --- ИСПРАВЛЕНИЕ ОШИБКИ С ЭКРАНА ---
            # Поле 'path' разрешено ТОЛЬКО для 'ws' и 'httpupgrade'
            if current_type not in ["ws", "httpupgrade"]:
                if "path" in transport:
                    print(f"Removing invalid field 'path' from transport '{current_type}' for node '{outbound.get('tag')}'")
                    transport.pop("path", None)

            # Поле 'service_name' разрешено ТОЛЬКО для 'grpc'
            if current_type != "grpc":
                if "service_name" in transport:
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
        # Добавлена безопасная проверка на случай отсутствия ключа alterId
        if "alterId" in outbound and outbound.get("alterId") == 0:
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
        "url": "https://ipv6.google.com/generate_204",
        "interval": "10m",
        "tolerance": 50
    }
    urltest_outbound = clean_urltest(urltest_outbound)

    singbox_config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": 1080,
              "tcp_fast_open": True
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"},
            selector_outbound,
            urltest_outbound,
            *outbounds
        ],
  "route": {
    "final": "proxy-out",
    "auto_detect_interface": True
  },
  "experimental": {
    "cache_file": {
      "enabled": True,
      "path": "/opt/etc/sing-box/cache"
    },
      
        "clash_api": {
            "external_controller": "192.168.1.1:9090",
            "external_ui": "/opt/etc/sing-box/ui",
            "external_ui_download_detour": "direct-out",
            "access_control_allow_private_network": True
        }
    }
}

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated config.json with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
