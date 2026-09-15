"""Модуль сборки и экспорта конфига Sing-box для Trojan нод."""

from src.common import is_valid_ip
from src.orchestrator import run_pipeline


def _filter_trojan(outbound: dict) -> bool:
    """Фильтр: только IP-адреса и RU-теги."""
    server = str(outbound.get("server", "")).strip("[]")
    if not is_valid_ip(server):
        return False
    node_tag = str(outbound.get("tag", "")).lower()
    if "ru" in node_tag or "russia" in node_tag:
        return False
    return True


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.trojan_parser",
        exporter="singbox",
        output_file="trojan.json",
    )
