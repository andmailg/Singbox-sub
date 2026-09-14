"""Модуль сборки и экспорта конфига Sing-box для VLESS WS Cloudfront (RKN+GeoIP)."""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.common import country_code_to_flag, fetch_subscription, load_sources
from src.rkn_filter import (
    RKNBlockList,
    download_geoip,
    load_rkn_list,
    open_geoip_reader,
    resolve_and_check,
)
from src.Parsers.vless_ws_parser import clean_outbound, is_valid_server, parse_proxy_link, should_accept_outbound


def main():
    SOURCES_JSON_URL = "https://github.com/andmailg/Singbox-sub/raw/refs/heads/main/Python/src/sub_urls.json"

    sub_urls = load_sources(SOURCES_JSON_URL)
    if not sub_urls:
        return

    from src.common import session

    # --- Загрузка подписок ---
    links = []
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

    # --- RKN + GeoIP ---
    download_geoip(session)
    blocked_networks = load_rkn_list(session)
    reader = open_geoip_reader()

    if reader:
        print("GeoIP database loaded successfully for geolocation filtering.")

    # --- Парсинг и дедупликация (только cloudfront) ---
    seen_fingerprints: set[str] = set()
    pre_parsed_nodes = []

    print(f"Parsing and deduplicating {len(links)} links...")
    for link in links:
        outbound = parse_proxy_link(link, require_cloudfront=True)
        if not outbound:
            continue
        outbound = clean_outbound(outbound)
        if not outbound:
            continue
        if not should_accept_outbound(outbound, seen_fingerprints):
            continue
        pre_parsed_nodes.append(outbound)

    # --- RKN + GeoIP фильтрация (параллельная) ---
    num_workers = min(8, len(pre_parsed_nodes))
    print(f"Filtering {len(pre_parsed_nodes)} nodes with {num_workers} workers...")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_idx = {
            executor.submit(
                resolve_and_check,
                outbound.get("server", "").strip("[]"),
                blocked_networks,
                reader,
            ): idx
            for idx, outbound in enumerate(pre_parsed_nodes)
        }

        results = [None] * len(pre_parsed_nodes)
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None

    filtered_nodes = []
    for idx, check_result in enumerate(results):
        if check_result is not None:
            node = pre_parsed_nodes[idx]
            country = check_result.get("country")
            if country:
                node["_country"] = country
            filtered_nodes.append(node)

    if reader:
        reader.close()

    outbounds = filtered_nodes
    print(f"Всего выбрано {len(outbounds)} валидных VLESS WS Cloudfront узлов после всех этапов фильтрации.")

    if not outbounds:
        print("Error: No valid proxy nodes left after filtration!")
        return

    # --- Сортировка по стране (флаг) ---
    outbounds.sort(key=lambda o: (o.get("_country", ""), o.get("server", "")))

    # --- Теги с флагами: нумерация внутри каждой группы страны ---
    from src.common import _extract_tag_number

    country_groups: dict[str, list[dict]] = {}
    for outbound in outbounds:
        country = outbound.pop("_country", None)
        if country:
            country_groups.setdefault(country, []).append(outbound)
        else:
            country_groups.setdefault("", []).append(outbound)

    sorted_outbounds: list[dict] = []
    for country, nodes in country_groups.items():
        nodes.sort(key=lambda o: _extract_tag_number(o.get("tag", "")))
        flag = country_code_to_flag(country) if country else ""
        for idx, outbound in enumerate(nodes, start=1):
            outbound["tag"] = f"{flag}node-{idx}" if flag else f"node-{idx}"
        sorted_outbounds.extend(nodes)

    outbounds = sorted_outbounds

    # --- Экспорт ---
    from src.Exporters.sb_exporter import export_singbox
    export_singbox(outbounds)


if __name__ == "__main__":
    main()
