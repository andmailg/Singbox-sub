import base64
import functools
import ipaddress
import json
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests

# Инициализация сессии для повторного использования соединений
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})


@functools.lru_cache(maxsize=4096)
def is_valid_ip(address: str) -> bool:
    """Проверяет, является ли строка валидным IPv4 или IPv6 адресом."""
    try:
        ipaddress.ip_address(address.strip("[]"))
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=4096)
def is_valid_domain(domain: str) -> bool:
    """Проверяет, является ли строка валидным доменным именем (не IP-адресом)."""
    if not domain or is_valid_ip(domain):
        return False
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))


@functools.lru_cache(maxsize=4096)
def domain_exists(domain: str) -> bool:
    """Проверяет, разрешается ли домен в IP-адрес через DNS."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


# Зоны, узлы которых блокируются глобально
RU_ZONES = (".ru", ".su", ".рф")

# Домены фейковых нод, которые блокируются
FAKE_DOMAINS = ("whatsapp.com", "vk.com", "huawei")


def _is_ru_zone(hostname: str) -> bool:
    """Проверяет, относится ли хост к заблокированным зонам."""
    h = hostname.lower()
    return h.endswith(RU_ZONES) or any(f"{z}:" in h for z in RU_ZONES)


def should_accept_outbound(outbound: dict, seen_servers: set[str]) -> bool:
    """Быстрая фильтрация ноды после парсинга."""
    if not outbound:
        return False
    tls_opts = outbound.get("tls")
    if not isinstance(tls_opts, dict) or not tls_opts.get("enabled"):
        return False
    server_name = tls_opts.get("server_name")
    if not server_name or not isinstance(server_name, str) or not server_name.strip():
        return False
    if any(d in server_name.lower() for d in FAKE_DOMAINS):
        return False
    node_tag = str(outbound.get("tag", "")).lower()
    if "ru" in node_tag or "russia" in node_tag:
        return False
    server_address = str(outbound.get("server", "")).lower()
    if _is_ru_zone(server_address):
        return False
    if any(d in server_address for d in FAKE_DOMAINS):
        return False
    if server_address in seen_servers:
        return False
    seen_servers.add(server_address)
    return True


def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server."""
    if not server or "@" in server:
        return False
    clean_server = server.strip("[]")
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата Hysteria2."""
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        parsed = urllib.parse.urlparse(link)
        hostname = parsed.hostname
        if not hostname:
            return None
        hostname = hostname.strip("[]")
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    # Фильтр: Только Hysteria2
    if scheme not in ["hysteria2", "hy2"]:
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Фильтрация небезопасных узлов
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0]
    if insecure == "1" or insecure.lower() == "true":
        return None

    # 2. Обработка портов: первое число из диапазона или удаление узла, если порт не указан
    try:
        port = parsed.port
    except ValueError:
        # В случае диапазона портов (например, 21000-21199) извлекаем первое число
        port_part = parsed.netloc.rsplit(":", 1)[-1].split("?")[0].split("#")[0]
        first_port = port_part.split("-")[0]
        port = int(first_port) if first_port.isdigit() else None

    # Если порт не указан в ссылке или не определен, пропускаем узел
    if not port:
        return None

    # 3. Извлечение пароля
    netloc = parsed.netloc
    password = parsed.username

    if not password and "@" in netloc:
        user_part = netloc.split("@")[0]
        password = (
            user_part.split(":", 1)[-1] if ":" in user_part else user_part
        )

    if not password:
        return None

    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"
    )

    # 4. Обработка SNI
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    # Переопределение server_host значением SNI (если они различаются)
    server_host = hostname
    if sni and hostname.lower() != sni.lower():
        server_host = sni

    # SNI обязателен для TLS
    if not sni:
        return None

    tls_opts = {
        "enabled": True,
        "server_name": sni
    }

    # 5. Сборка объекта outbound для sing-box
    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": server_host,
        "server_port": port,
        "up_mbps": 20,
        "down_mbps": 20,
        "password": urllib.parse.unquote(password),
        "tls": tls_opts,
    }

    # Глобальные проверки (SERVER, SNI, RU DOMAINS)
    if not is_valid_server(outbound["server"]):
        return None

    if sni:
        sni_val = sni.lower()
        if not is_valid_domain(sni_val):
            return None

        if _is_ru_zone(sni_val):
            return None

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение Hysteria2 ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    outbound.setdefault("up_mbps", 20)
    outbound.setdefault("down_mbps", 20)

    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        # Очищаем неиспользуемый блок reality для hysteria2
        tls_opts.pop("reality", None)

    return outbound


def fetch_subscription(url: str) -> list[str]:
    """Скачивает и декодирует отдельную подписку."""
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code != 200:
            return []

        content = resp.text.strip()
        try:
            content_padded = content + "=" * (-len(content) % 4)
            decoded_content = base64.b64decode(content_padded).decode("utf-8", errors="ignore")
            return decoded_content.splitlines()
        except Exception:
            return content.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []


def main():
    SOURCES_JSON_URL = "https://github.com/andmailg/Singbox-sub/raw/refs/heads/main/Python/src/sub_urls.json"

    print(f"Fetching subscription sources from {SOURCES_JSON_URL}...")
    try:
        sources_resp = session.get(SOURCES_JSON_URL, timeout=15)
        sources_resp.raise_for_status()

        try:
            sub_urls = sources_resp.json()
        except Exception:
            sub_urls = json.loads(sources_resp.text)

        if isinstance(sub_urls, dict):
            sub_urls = list(sub_urls.values())

        if not isinstance(sub_urls, list):
            raise ValueError(f"Expected list or dict, got {type(sub_urls)}")

        print(f"✅ Successfully loaded {len(sub_urls)} subscription sources.")

    except Exception as e:
        print(f"❌ Error fetching sources JSON: {e}")
        return

    # --- ШАГ 1: Ленивый парсинг, фильтрация и дедупликация в одном проходе ---
    seen_servers: set[str] = set()
    outbounds: list[dict] = []

    print("Downloading and parsing links in parallel...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        for lines in executor.map(fetch_subscription, sub_urls):
            for link in lines:
                outbound = parse_proxy_link(link)
                if not should_accept_outbound(outbound, seen_servers):
                    continue
                outbound = clean_outbound(outbound)
                if not outbound:
                    continue
                # Single-pass tagging
                outbound["tag"] = f"node-{len(outbounds) + 1}"
                outbounds.append(outbound)

    # --- ШАГ 2: Проверка существования доменов через DNS ---
    print(f"Checking DNS existence for {len(outbounds)} nodes...")
    valid_outbounds: list[dict] = []
    for outbound in outbounds:
        server = str(outbound.get("server", "")).lower()
        sni = str(outbound.get("tls", {}).get("server_name", "")).lower()
        if is_valid_domain(server) and not domain_exists(server):
            continue
        if is_valid_domain(sni) and not domain_exists(sni):
            continue
        valid_outbounds.append(outbound)

    outbounds = valid_outbounds
    print(f"✅ {len(outbounds)} nodes passed DNS check.")

    if not outbounds:
        print("Error: No valid proxy nodes left after filtration!")
        return

    # --- ШАГ 3: ЭКСПОРТ НОД В ФОРМАТЕ V2RAY (hysteria2:// ссылки) ---
    v2ray_links: list[str] = []
    for outbound in outbounds:
        tag = outbound.get("tag", "node")
        server = outbound.get("server", "")
        port = outbound.get("server_port", 443)
        password = outbound.get("password", "")
        sni = outbound.get("tls", {}).get("server_name", "")

        # Формируем ссылку hysteria2://password@server:port?sni=xxx#tag
        query_params = urllib.parse.urlencode({"sni": sni, "security": "tls"})
        fragment = urllib.parse.quote(tag)
        netloc = f"{server}:{port}"
        v2ray_link = f"hysteria2://{urllib.parse.quote(password, safe='')}@{netloc}?{query_params}#{fragment}"
        v2ray_links.append(v2ray_link)

    output_file = "hy2-v2ray.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(v2ray_links))

    print(f"✅ Successfully exported {len(v2ray_links)} nodes to {output_file}")


if __name__ == "__main__":
    main()
