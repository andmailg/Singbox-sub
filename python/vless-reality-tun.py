"""Модуль сборки и экспорта конфига Sing-box для VLESS reality нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_reality_parser",
        exporter="tun",
        output_file="vless-reality-tun.json",
        health_check_timeout=5.0,
        health_check_protocol="auto",
    )
