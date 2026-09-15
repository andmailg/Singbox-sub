"""Модуль сборки и экспорта конфига Sing-box для VLESS HTTP (RKN+GeoIP)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_http_parser",
        exporter="singbox",
        output_file="vless-http.json",
    )
