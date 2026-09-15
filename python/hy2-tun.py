"""Модуль сборки и экспорта конфига Sing-box для Hysteria2 нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.hy2_parser",
        exporter="tun",
        output_file="hy2-tun.json",
    )
