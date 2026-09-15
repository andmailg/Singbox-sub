"""Модуль сборки роутер-конфига sing-box из Hysteria2 нод."""

from src.orchestrator import run_pipeline


def _export_router(outbounds: list[dict], output_file: str) -> None:
    """Экспорт в роутер-конфиг."""
    from src.exporters.singbox_exporter import export_router
    export_router(outbounds, output_file)


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.hy2_parser",
        output_file="config.json",
    )
