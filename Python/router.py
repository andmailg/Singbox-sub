import base64
import json
import os
import urllib.parse
import requests


def parse_proxy_link(link: str) -> dict | None:
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    # Защита от критического падения скрипта при битых URL (Invalid IPv6 URL и др.)
    try:
        parsed = urllib.parse.urlparse(link)
        _ = parsed.hostname  # Провоцируем внутреннюю проверку парсера
    except ValueError:
        print(f"Skipping malformed URL: {link[:30]}...")
        return None

    scheme = parsed.scheme.lower()
    params = urllib.parse.parse_qs(parsed.query)

    # Извлекаем тип транспорта
    net_type = params.get("type", params.get("net", [""]))[0].lower()

    # Фильтрация небезопасных соединений
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        print(f"Skipping insecure node: {link[:30]}...")
        return None

    # Фильтрация транспорта WS (WebSocket) на корню
    if net_type == "ws":
        print(f"Skipping WebSocket (ws) node: {link[:30]}...")
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Node"
    outbound = None  # Переменная для сохранения результата парсинга

    # --- 1. VLESS ---
    if scheme == "vless":
        # Фильтрация по портам (Строго 443 или 8443)
        port = parsed.port
        if port not in [443, 8443]:
            print(f"Skipping VLESS node: invalid port {port} (Only 443/8443 allowed) for tag '{tag}'")
            return None

        # Безопасно достаем параметры
        flow_param = params.get("flow", [""])
        flow = flow_param[0].strip().lower() if flow_param else ""

        security_param = params.get("security", ["none"])
        security = security_param[0].strip().lower() if security_param else "none"

        is_vision = (flow == "xtls-rprx-vision")
        is_reality = (security == "reality")

        # Критерий: Обязательное наличие xtls-rprx-vision
        if not is_vision:
            print(f"Skipping VLESS node: missing or invalid flow (Got flow='{flow}', security='{security}') for tag '{tag}'")
            return None

        outbound = {
            "type": "vless",
            "tag": tag,
            "server": parsed.hostname,
            "server_port": port,
            "uuid": parsed.username,
            "flow": "xtls-rprx-vision"
        }

        if security in ["tls", "reality"] or is_vision:
            tls_opts = {"enabled": True}
            
            sni_param = params.get("sni", [None])[0]
            if sni_param:
                tls_opts["server_name"] = sni_param.strip()

            fp_param = params.get("fp", [None])[0]
            if fp_param:
                tls_opts["utls"] = {"enabled": True, "fingerprint": fp_param.strip()}

            if is_reality:
                pbk_param = params.get("pbk", [None])[0]
                sid_param = params.get("sid", [None])[0]
                reality_opts = {}
                if pbk_param:
                    reality_opts["public_key"] = pbk_param.strip()
                if sid_param:
                    reality_opts["short_id"] = sid_param.strip()
                tls_opts["reality"] = reality_opts

            outbound["tls"] = tls_opts

        if net_type:
            path_param = params.get("path", [None])[0]
            host_param = params.get("host", [None])[0]
            service_param = params.get("serviceName", [None])[0]

            transport_opts = {"type": net_type}
            if path_param:
                transport_opts["path"] = path_param.strip()
            if host_param:
                transport_opts["headers"] = {"Host": host_param.strip()}
            if service_param:
                transport_opts["service_name"] = service_param.strip()
            outbound["transport"] = transport_opts

    # --- 2. VMESS ---
    elif scheme == "vmess":
        try:
            b64_data = parsed.netloc
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8")
            data = json.loads(decoded)

            net = data.get("net", "tcp").lower()
            if net == "ws":
                print(f"Skipping VMess WebSocket node: {data.get('ps', 'Node')}")
                return None

            vmess_security = str(data.get("scy", "auto")).lower().strip()
            if vmess_security == "auto" or vmess_security == "":
                print(f"Skipping standard VMess (security='auto'): {data.get('ps', 'Node')}")
                return None

            outbound = {
                "type": "vmess",
                "tag": data.get("ps", tag),
                "server": data.get("add"),
                "server_port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "security": vmess_security,
            }

            if data.get("net"):
                transport_opts = {"type": net}
                if data.get("path"):
                    transport_opts["path"] = data.get("path")
                if data.get("host"):
                    transport_opts["headers"] = {"Host": data.get("host")}
                outbound["transport"] = transport_opts

            if data.get("tls") == "tls":
                tls_opts = {"enabled": True}
                if data.get("sni"):
                    tls_opts["server_name"] = data.get("sni")
                if data.get("fp"):
                    tls_opts["utls"] = {"enabled": True, "fingerprint": data.get("fp")}
                outbound["tls"] = tls_opts
        except Exception:
            return None

    # --- 3. TROJAN ---
    elif scheme == "trojan":
        security = params.get("security", ["tls"])[0].lower()
        if security != "reality":
            print(f"Skipping standard Trojan (No Reality): {tag}")
            return None

        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": parsed.hostname,
            "server_port": parsed.port,
            "password": parsed.username,
        }

        tls_opts = {"enabled": True}
        sni_param = params.get("sni", [None])[0]
        if sni_param:
            tls_opts["server_name"] = sni_param.split(":")[0]

        fp_param = params.get("fp", [None])[0]
        if fp_param:
            tls_opts["utls"] = {"enabled": True, "fingerprint": fp_param.strip()}

        pbk_param = params.get("pbk", [None])[0]
        sid_param = params.get("sid", [None])[0]
        reality_opts = {}
        if pbk_param:
            reality_opts["public_key"] = pbk_param.strip()
        if sid_param:
            reality_opts["short_id"] = sid_param.strip()
        tls_opts["reality"] = reality_opts
        outbound["tls"] = tls_opts

        if net_type:
            path_param = params.get("path", [None])[0]
            host_param = params.get("host", [None])[0]
            service_param = params.get("serviceName", [None])[0]

            transport_opts = {"type": net_type}
            if path_param:
                transport_opts["path"] = path_param.strip()
            if host_param:
                transport_opts["headers"] = {"Host": host_param.strip()}
            if service_param:
                transport_opts["service_name"] = service_param.strip()
            outbound["transport"] = transport_opts

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
        sni_param = params.get("sni", [None])[0]
        if sni_param:
            outbound["tls"]["server_name"] = sni_param.strip()

    # --- 5. SHADOWSOCKS ---
    elif scheme == "ss":
        try:
            port = parsed.port
            if not port or not ((port == 443) or (10000 <= port <= 99999)):
                print(f"Skipping SS node: invalid port {port} for tag '{tag}'")
                return None

            userinfo = parsed.username
            if not userinfo and parsed.netloc:
                userinfo = parsed.netloc.split("@")[0] if "@" in parsed.netloc else None

            method, password = None, None
            if userinfo:
                userinfo_padded = userinfo + "=" * (-len(userinfo) % 4)
                try:
                    decoded_userinfo = base64.b64decode(userinfo_padded).decode("utf-8")
                    if ":" in decoded_userinfo:
                        method, password = decoded_userinfo.rsplit(":", 1)
                except Exception:
                    pass

            if not method or not password:
                method = parsed.username
                password = parsed.password

            if not method or not password:
                return None

            method = str(method).lower().strip()
            ALLOWED_2022_METHODS = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]
            if method not in ALLOWED_2022_METHODS:
                print(f"Skipping SS node: method '{method}' is not Shadowsocks-2022 for tag '{tag}'")
                return None

            try:
                password_padded = password + "=" * (-len(password) % 4)
                key_length = len(base64.b64decode(password_padded))
            except Exception:
                return None

            if method == "2022-blake3-aes-128-gcm" and key_length != 16:
                return None
            elif method in ["2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"] and key_length != 32:
                return None

            outbound = {
                "type": "shadowsocks",
                "tag": tag,
                "server": parsed.hostname,
                "server_port": port,
                "method": method,
                "password": password,
            }
        except Exception:
            return None

    # --- СТРОГО ПЕРЕД ФИНАЛЬНОЙ СТРОКОЙ RETURN OUTBOUND ---
    # Глобальная фильтрация российских доменов в SNI (server_name) для ВСЕХ протоколов (VLESS, Trojan и т.д.)
    if outbound and "tls" in outbound and outbound["tls"].get("enabled"):
        sni = str(outbound["tls"].get("server_name", "")).lower().strip()
        
        # Список запрещенных российских доменных зон
        RU_ZONES = (".ru", ".su", ".рф")
        
        # Проверяем, заканчивается ли SNI на одну из зон или содержит ли её с портом
        if sni.endswith(RU_ZONES) or any(f"{zone}:" in sni for zone in RU_ZONES):
            print(f"Skipping node '{tag}': forbidden Russian domain in server_name (SNI: '{sni}')")
            return None

    return outbound

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
