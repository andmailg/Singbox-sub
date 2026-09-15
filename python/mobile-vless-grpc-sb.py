"""Модуль сборки и экспорта конфига Sing-box для VLESS gRPC нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_grpc_parser",
        exporter="tun",
        output_file="vless-grpc.json",
    )
