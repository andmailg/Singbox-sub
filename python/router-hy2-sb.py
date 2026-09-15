"""Модуль сборки роутер-конфига sing-box из Hysteria2 нод."""

from src.orchestrator import run_pipeline


def _filter_router_hy2(outbound: dict) -> bool:
    """Дополнительные фильтры для роутер-конфига."""
    tls_opts = outbound.get("tls", {})
    if not isinstance(tls_opts, dict) or not tls_opts.get("enabled"):
        return False
    server_name = tls_opts.get("server_name")
    if not server_name or not isinstance(server_name, str) or not server_name.strip():
        return False
    server_address = str(outbound.get("server", "")).lower()
    if server_address.lower().endswith((".ru", ".su", ".рф")):
        return False
    return True


def _export_router(outbounds: list[dict], output_file: str) -> None:
    """Экспорт в роутер-конфиг."""
    from src.exporters.singbox_exporter import export_router
    export_router(outbounds, output_file)


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.hy2_parser",
        output_file="config.json",
        dedup_key="server",
        extra_filter=_filter_router_hy2,
        export_func=_export_router,
    )
