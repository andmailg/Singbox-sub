"""Модуль сборки и экспорта конфига Sing-box для VLESS HTTP (RKN+GeoIP)."""

from src.orchestrator import run_pipeline


def _filter_vless_http(outbound: dict) -> bool:
    """Фильтр RU-тегов для VLESS HTTP."""
    node_tag = str(outbound.get("tag", "")).lower()
    if "ru" in node_tag or "russia" in node_tag:
        return False
    return True


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_http_parser",
        exporter="singbox",
        output_file="vless-http.json",
    )
