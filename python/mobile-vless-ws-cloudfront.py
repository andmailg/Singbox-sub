"""Модуль сборки и экспорта конфига Sing-box для VLESS WS Cloudfront (RKN+GeoIP)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_ws_parser",
        exporter="singbox",
        output_file="vless-ws-cloudfront.json",
        dedup_key="fingerprint",
        parse_kwargs={"require_cloudfront": True},
    )
