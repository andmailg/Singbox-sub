"""Универсальный экспорт Sing-box JSON."""

import json

from .config_builder import build_singbox_config


def export_singbox(outbounds: list[dict], output_file: str = "output.json") -> int:
    """Экспортирует ноды в конфиг sing-box."""
    singbox_config = build_singbox_config(outbounds)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)
    print(f"Successfully generated {output_file} with {len(outbounds)} nodes.")
    return len(outbounds)
