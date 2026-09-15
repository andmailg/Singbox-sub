"""Модуль экспорта VMess нод в формат V2Ray (ссылки)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vmess_parser",
        exporter="v2ray",
        output_file="vmess.txt",
    )
