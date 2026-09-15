"""Модуль сборки и экспорта конфига Sing-box для Trojan нод."""

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.common import country_code_to_flag, fetch_subscription, is_valid_ip, load_sources
from src.rkn_filter import download_geoip, load_rkn_list, open_geoip_reader, resolve_and_check
from src.parsers.trojan_parser import clean_outbound, parse_proxy_link
from src.exporters.singbox_exporter import export_tun


def main():
    SOURCES_JSON_URL = "https://github.com/andmailg/singbox-sub/raw/refs/heads/main/python/src/sub_urls.json"

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
        print("GeoIP database loaded for geolocation filtering.")

    # --- Парсинг, фильтрация и дедупликация ---
    seen_servers: set[str] = set()
    pre_parsed_nodes: list[dict] = []

    print(f"Parsing, filtering and deduplicating {len(links)} links...")
    for link in links:
        outbound = parse_proxy_link(link)
        if not outbound:
            continue

        outbound = clean_outbound(outbound)
        if not outbound:
            continue

        server = str(outbound.get("server", "")).strip("[]")

        # 1. Только IP-адреса
        if not is_valid_ip(server):
            continue

        # 2. RU фильтр по тегу
        node_tag = str(outbound.get("tag", "")).lower()
        if "ru" in node_tag or "russia" in node_tag:
            continue

        # 3. Дедупликация по IP
        if server in seen_servers:
            continue
        seen_servers.add(server)
        pre_parsed_nodes.append(outbound)

    # --- RKN + GeoIP фильтрация (единый resolve_and_check) ---
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

        results: list[dict | None] = [None] * len(pre_parsed_nodes)
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None

    filtered_nodes: list[dict] = []
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
    print(f"Всего выбрано {len(outbounds)} валидных Trojan узлов с IP-адресами (порт != 443).")

    if not outbounds:
        print("Error: No valid proxy nodes left after filtration!")
        return

    # --- Сортировка по стране, сквозная нумерация ---
    outbounds.sort(key=lambda o: (o.get("_country", ""), o.get("server", "")))

    for idx, outbound in enumerate(outbounds, start=1):
        country = outbound.pop("_country", None)
        flag = country_code_to_flag(country) if country else ""
        outbound["tag"] = f"{flag}node-{idx}" if flag else f"node-{idx}"

    # --- Экспорт ---
    export_tun(outbounds, "trojan.json")


if __name__ == "__main__":
    main()