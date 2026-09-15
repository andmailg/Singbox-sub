"""Универсальный оркестратор pipeline для сборки прокси-конфигов."""

import importlib
import json
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.common import (
    country_code_to_flag,
    fetch_subscription,
    load_sources,
    resolve_domain,
)
from src.rkn_filter import (
    download_geoip,
    load_rkn_list,
    open_geoip_reader,
    resolve_and_check,
)


SOURCES_JSON_PATH = "./sub_urls.json"


def _fetch_links(sub_urls: list[str]) -> list[str]:
    """Параллельно скачивает все подписки."""
    links: list[str] = []
    max_workers = min(10, len(sub_urls))
    print(f"Fetching {len(sub_urls)} subscriptions with {max_workers} workers...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(fetch_subscription, url): url
            for url in sub_urls
        }
        for future in as_completed(future_to_url):
            try:
                links.extend(future.result())
            except Exception as e:
                url = future_to_url[future]
                print(f"Error fetching {url}: {e}")
    print(f"Total raw lines collected: {len(links)}")
    return links


def _resolve_outbound_server(server: str) -> str | None:
    """Резолвит домен в IP, если это не IP-адрес. Возвращает None при неудаче."""
    from src.common import is_valid_ip

    clean = server.strip("[]")
    if is_valid_ip(clean):
        return clean
    resolved = resolve_domain(clean)
    return resolved


def _parse_and_deduplicate(
    links: list[str],
    parse_proxy_link: Callable,
    clean_outbound: Callable,
    extra_filter: Callable[[dict], bool] | None,
    parse_kwargs: dict | None,
) -> list[dict]:
    """Парсинг, DNS-резолвинг, дедупликация по IP:port и дополнительные фильтры."""
    seen: set[str] = set()
    outbounds: list[dict] = []
    kw = parse_kwargs or {}

    print(f"Parsing and deduplicating {len(links)} links...")
    for link in links:
        outbound = parse_proxy_link(link, **kw)
        if not outbound:
            continue

        outbound = clean_outbound(outbound)
        if not outbound:
            continue

        if extra_filter and not extra_filter(outbound):
            continue

        # DNS-резолвинг + дедупликация по resolved_ip:port
        server = str(outbound.get("server", "")).strip("[]").lower()
        port = outbound.get("server_port", "")
        resolved_ip = _resolve_outbound_server(server)

        # Если резолвинг не удался — пропускаем
        if not resolved_ip:
            continue

        dedup_val = f"{resolved_ip}:{port}"

        if dedup_val in seen:
            continue
        seen.add(dedup_val)

        # Сохраняем resolved IP для RKN-фильтра
        outbound["server"] = resolved_ip
        outbounds.append(outbound)

    return outbounds


def _rkn_geoip_filter(
    outbounds: list[dict],
) -> list[dict]:
    """RKN + GeoIP фильтрация через resolve_and_check."""
    from src.common import session

    download_geoip(session)
    blocked_networks = load_rkn_list(session)
    reader = open_geoip_reader()

    if reader:
        print("GeoIP database loaded for geolocation filtering.")

    num_workers = min(8, len(outbounds))
    print(f"Filtering {len(outbounds)} nodes with {num_workers} workers...")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_idx = {
            executor.submit(
                resolve_and_check,
                o.get("server", "").strip("[]"),
                blocked_networks,
                reader,
            ): idx
            for idx, o in enumerate(outbounds)
        }

        results: list[dict | None] = [None] * len(outbounds)
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None

    filtered: list[dict] = []
    for idx, check_result in enumerate(results):
        if check_result is not None:
            node = outbounds[idx]
            country = check_result.get("country")
            if country:
                node["_country"] = country
            filtered.append(node)

    if reader:
        reader.close()

    return filtered


def _sort_and_tag(outbounds: list[dict]) -> None:
    """Сортировка по стране и сквозная нумерация с флагами."""
    outbounds.sort(key=lambda o: (o.get("_country", ""), o.get("server", "")))
    for idx, outbound in enumerate(outbounds, start=1):
        country = outbound.pop("_country", None)
        flag = country_code_to_flag(country) if country else ""
        outbound["tag"] = f"{flag}node-{idx}" if flag else f"node-{idx}"


def run_pipeline(
    parser_module: str,
    *,
    exporter: str = "singbox",
    output_file: str = "output.json",
    extra_filter: Callable[[dict], bool] | None = None,
    parse_kwargs: dict | None = None,
    export_func: Callable | None = None,
    post_process: Callable[[list[dict]], None] | None = None,
) -> None:
    """Запускает полный pipeline сборки конфига.

    Args:
        parser_module: dotted path к модулю парсера (например "src.parsers.hy2_parser").
        exporter: "singbox" или "v2ray". Используется по умолчанию, если export_func не указан.
        output_file: имя выходного файла.
        extra_filter: дополнительная функция фильтрации (возвращает True/False).
        parse_kwargs: дополнительные аргументы для parse_proxy_link.
        export_func: кастомная функция экспорта. Если None — используется exporter.
        post_process: функция для постобработки перед экспортом.
    """
    # 1. Загрузка подписок
    sub_urls_path = os.path.join(os.path.dirname(__file__), SOURCES_JSON_PATH)
    with open(sub_urls_path, "r", encoding="utf-8") as f:
        sub_urls_data = json.load(f)
    sub_urls = list(sub_urls_data.values()) if isinstance(sub_urls_data, dict) else sub_urls_data
    if not sub_urls:
        return

    links = _fetch_links(sub_urls)
    if not links:
        return

    # 2. Импорт парсера
    mod = importlib.import_module(parser_module)
    parse_proxy_link = mod.parse_proxy_link
    clean_outbound = mod.clean_outbound

    # 3. Парсинг + дедупликация
    outbounds = _parse_and_deduplicate(
        links,
        parse_proxy_link,
        clean_outbound,
        extra_filter,
        parse_kwargs,
    )

    if not outbounds:
        print("Error: No valid proxy nodes left after parsing!")
        return

    # 4. RKN + GeoIP фильтрация
    outbounds = _rkn_geoip_filter(outbounds)

    if not outbounds:
        print("Error: No valid proxy nodes left after RKN+GeoIP filtration!")
        return

    print(f"Total {len(outbounds)} nodes passed all filters.")

    # 5. Сортировка + нумерация
    _sort_and_tag(outbounds)

    # 6. Постобработка
    if post_process:
        post_process(outbounds)

    # 7. Экспорт
    if export_func:
        export_func(outbounds, output_file)
    elif exporter == "v2ray":
        from src.exporters.v2ray_exporter import export_v2ray_by_type
        export_v2ray_by_type(outbounds, output_file)
    else:
        from src.exporters.singbox_exporter import export_tun
        export_tun(outbounds, output_file)
