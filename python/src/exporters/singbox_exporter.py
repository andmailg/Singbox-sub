"""Экспорт sing-box JSON (мобильный и роутер конфиги)."""

import json
from collections.abc import Callable

from .tun_config_builder import build_tun_config
from .router_config_builder import build_router_config


def export_tun(outbounds: list[dict], output_file: str = "output.json") -> int:
    """Экспортирует ноды в мобильный конфиг sing-box (tun)."""
    return _export(outbounds, output_file, build_tun_config, 20)


def export_router(outbounds: list[dict], output_file: str = "config.json") -> int:
    """Экспортирует ноды в роутер-конфиг sing-box."""
    return _export(outbounds, output_file, build_router_config, 100)


def _export(
    outbounds: list[dict],
    output_file: str,
    build_fn: Callable[[list[dict]], dict],
    speed_mbps: int = 20,
) -> int:
    """Общий экспорт: speed settings → билд → запись на диск."""
    for o in outbounds:
        if o.get("type") == "hysteria2":
            o.setdefault("up_mbps", speed_mbps)
            o.setdefault("down_mbps", speed_mbps)

    singbox_config = build_fn(outbounds)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)
    print(f"Successfully generated {output_file} with {len(outbounds)} nodes.")
    return len(outbounds)
