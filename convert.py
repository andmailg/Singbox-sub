import base64
import json
import os
import re
import urllib.parse
import requests


def parse_proxy_link(link: str) -> dict | None:
    link = link.strip()
    if not link:
        return None

    parsed = urllib.parse.urlparse(link)
    scheme = parsed.scheme.lower()
    params = urllib.parse.parse_qs(parsed.query)

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Node"

    if scheme == "vless":
        uuid = parsed.username
        server = parsed.hostname
        port = parsed.port

        outbound = {
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": uuid,
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

        net = params.get("type", ["tcp"])[0]
        if net != "tcp":
            transport = {"type": net}
            path = params.get("path", [None])[0]
            host = params.get("host", [None])[0]
            if path:
                transport["path"] = path
            if host:
                transport["headers"] = {"Host": host}
            outbound["transport"] = transport

        return outbound

    elif scheme == "vmess":
        try:
            b64_data = parsed.netloc
            # Добавляем дополнение base64 при необходимости
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

            net = data.get("net", "tcp")
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

    elif scheme == "ss":
        # Shadowsocks
        try:
            userinfo = parsed.username
            if not userinfo and parsed.netloc:
                userinfo = parsed.netloc.split("@")[0]

            if userinfo:
                userinfo += "=" * (-len(userinfo) % 4)
                try:
                    decoded_userinfo = base64.b64decode(userinfo).decode("utf-8")
                    method, password = decoded_userinfo.split(":", 1)
                except Exception:
                    method = parsed.username
                    password = parsed.password

            server = parsed.hostname
            port = parsed.port

            return {
                "type": "shadowsocks",
                "tag": tag,
                "server": server,
                "server_port": port,
                "method": method,
                "password": password,
            }
        except Exception:
            return None

    return None


def clean_outbound(outbound: dict) -> dict:
    """Применение специфических правил очистки sing-box."""
    # 1. Удаление transport/packet_encoding из TCP
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

    # Декодируем Base64, если подписка закодирована
    try:
        content_padded = content + "=" * (-len(content) % 4)
        decoded_content = base64.b64decode(content_padded).decode("utf-8")
        links = decoded_content.splitlines()
    except Exception:
        links = content.splitlines()

    outbounds = []
    node_tags = []

    for link in links:
        outbound = parse_proxy_link(link)
        if outbound:
            outbound = clean_outbound(outbound)
            outbounds.append(outbound)
            node_tags.append(outbound["tag"])

    # Формируем селектор и urltest
    selector_outbound = {
        "type": "selector",
        "tag": "select",
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

    # Итоговая структура sing-box
    singbox_config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "google", "address": "tls://8.8.8.8"},
                {"tag": "local", "address": "228.0.0.1", "detour": "direct"},
            ]
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        ],
        "outbounds": [
            selector_outbound,
            urltest_outbound,
            *outbounds,
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
        ],
    }

    with open("sing-box.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated sing-box.json with {len(outbounds)} nodes.")


if __name__ == "__main__":
    main()
