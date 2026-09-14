"""Сборка и экспорт роутер-конфига sing-box (router)."""

import json


def build_router_config(outbounds: list[dict]) -> dict:
    """Собирает минимальный конфиг sing-box для роутера."""
    # Применяем speed settings для router (up/down_mbps=100)
    for o in outbounds:
        if o.get("type") == "hysteria2":
            o.setdefault("up_mbps", 100)
            o.setdefault("down_mbps", 100)

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

    singbox_config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080,
                "tcp_fast_open": True,
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"},
            selector_outbound,
            urltest_outbound,
            *outbounds,
        ],
        "route": {
            "final": "proxy-out",
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": "/opt/etc/sing-box/cache",
            },
            "clash_api": {
                "external_controller": "192.168.1.1:9090",
                "external_ui": "/opt/etc/sing-box/ui",
                "external_ui_download_detour": "direct-out",
                "access_control_allow_private_network": True,
            },
        },
    }

    return singbox_config


def export_router(outbounds: list[dict], output_file: str = "config.json") -> int:
    """Экспортирует ноды в роутер-конфиг sing-box."""
    singbox_config = build_router_config(outbounds)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)
    print(f"Successfully generated {output_file} with {len(outbounds)} nodes.")
    return len(outbounds)
