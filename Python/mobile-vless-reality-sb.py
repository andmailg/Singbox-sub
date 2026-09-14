"""Модуль сборки и экспорта конфига Sing-box для VLESS reality нод."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from src.common import country_code_to_flag, fetch_subscription, load_sources
from src.rkn_filter import download_geoip, load_rkn_list, open_geoip_reader, resolve_and_check
from src.Exporters.sb_exporter import export_singbox
from src.Parsers.vless_reality_parser import (
    clean_outbound,
    parse_proxy_link,
    should_accept_outbound,
)


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

    # --- Парсинг и дедупликация ---
    seen_servers: set[str] = set()
    outbounds: list[dict] = []

    print(f"Parsing and deduplicating {len(links)} links...")
    for link in links:
        outbound = parse_proxy_link(link)
        if not should_accept_outbound(outbound, seen_servers):
            continue
        outbound = clean_outbound(outbound)
        if not outbound:
            continue
        outbounds.append(outbound)

    # --- RKN + GeoIP + DNS фильтрация ---
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
                outbound.get("server", "").strip("[]"),
                blocked_networks,
                reader,
            ): idx
            for idx, outbound in enumerate(outbounds)
        }

        results = [None] * len(outbounds)
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None

    filtered_nodes = []
    for idx, check_result in enumerate(results):
        if check_result is not None:
            node = outbounds[idx]
            country = check_result.get("country")
            if country:
                node["_country"] = country
            filtered_nodes.append(node)

    if reader:
        reader.close()

    outbounds = filtered_nodes
    print(f"✅ {len(outbounds)} nodes passed RKN+GeoIP+DNS check.")

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
    export_singbox(outbounds)


if __name__ == "__main__":
    main()
