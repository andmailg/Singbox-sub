"""Модуль сборки роутер-конфига sing-box из Hysteria2 нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.hy2_parser",
        output_file="config.json",
    )
