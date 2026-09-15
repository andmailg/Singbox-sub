"""Модуль сборки и экспорта конфига Sing-box для VLESS HTTP (RKN+GeoIP)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_http_parser",
        exporter="tun",
        output_file="vless-http-tun.json",
        health_check_timeout=5.0,
        health_check_protocol="auto",
    )
