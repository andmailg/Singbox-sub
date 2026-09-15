"""Модуль сборки и экспорта конфига Sing-box для VLESS reality нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_reality_parser",
        exporter="singbox",
        output_file="vless-reality.json",
        dedup_key="fingerprint",
    )
