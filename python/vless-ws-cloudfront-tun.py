"""Модуль сборки и экспорта конфига Sing-box для VLESS WS Cloudfront (RKN+GeoIP)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_ws_parser",
        exporter="tun",
        output_file="vless-ws-cloudfront-tun.json",
        parse_kwargs={"require_cloudfront": True},
        health_check_timeout=5.0,
        health_check_protocol="auto",
    )
