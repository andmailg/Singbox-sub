"""Модуль сборки и экспорта конфига Sing-box для VMess нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vmess_parser",
        exporter="tun",
        output_file="vmess-tun.json",
    )
