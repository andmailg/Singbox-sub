"""Сборка минимального роутер-конфига sing-box (router)."""


def build_router_config(outbounds: list[dict]) -> dict:
    """Собирает минимальный конфиг sing-box для роутера."""
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
