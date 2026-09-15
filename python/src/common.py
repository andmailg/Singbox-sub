"""Общие утилиты: сессия, валидаторы, DNS-проверки, константы."""

import base64
import functools
import ipaddress
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Инициализация сессии для повторного использования соединений
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
session.verify = False


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
def resolve_domain(domain: str) -> str | None:
    """Кэшированный DNS-резолвинг домена в IPv4-адрес."""
    try:
        return socket.gethostbyname(domain.strip("[]"))
    except socket.gaierror:
        return None


def is_valid_host(host_str: str) -> bool:
    """Проверяет, является ли raw-string валидным доменным именем.
    Предварительно очищает от [], портов (:), ведущих /.
    """
    if not host_str or not isinstance(host_str, str):
        return False
    clean_host = host_str.strip().strip("[]").split(":")[0].strip()
    if clean_host.startswith("/"):
        return False
    return is_valid_domain(clean_host)


# Зоны, узлы которых блокируются глобально
RU_ZONES = (".ru", ".su", ".рф")

# Домены фейковых нод, которые блокируются
FAKE_DOMAINS = ("whatsapp.com", "vk.com", "huawei", "bing.com")


def is_valid_server(server: str) -> bool:
    """Проверяет корректность поля server."""
    if not server or "@" in server:
        return False
    clean_server = server.strip().strip("[]").split(":")[0].strip()
    return is_valid_ip(clean_server) or is_valid_domain(clean_server)


def country_code_to_flag(cc: str) -> str:
    """Конвертирует ISO 3166-1 alpha-2 код страны в Unicode-флаг.
    Пример: 'US' -> '🇺🇸', 'DE' -> '🇩🇪'
    """
    if not cc or len(cc) != 2:
        return ""
    return "".join(chr(ord(c) - ord('A') + 0x1F1E6) for c in cc.upper())


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


def load_sources(sources_json_url: str) -> list[str]:
    """Загружает список URL подписок из JSON."""
    print(f"Fetching subscription sources from {sources_json_url}...")
    try:
        sources_resp = session.get(sources_json_url, timeout=15)
        sources_resp.raise_for_status()

        try:
            sub_urls = sources_resp.json()
        except Exception:
            sub_urls = __import__('json').loads(sources_resp.text)

        if isinstance(sub_urls, dict):
            sub_urls = list(sub_urls.values())

        if not isinstance(sub_urls, list):
            raise ValueError(f"Expected list or dict, got {type(sub_urls)}")

        print(f"✅ Successfully loaded {len(sub_urls)} subscription sources.")
        return sub_urls

    except Exception as e:
        print(f"❌ Error fetching sources JSON: {e}")
        return []


def check_tcp_connect(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> bool:
    """Проверяет доступность хоста по TCP-соединению.
    
    Args:
        host: IP-адрес или домен.
        port: Порт для проверки.
        timeout: Таймаут в секундах.
    
    Returns:
        True если порт открыт, False в противном случае.
    """
    try:
        clean_host = host.strip("[]")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((clean_host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_udp_ping(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> bool:
    """Проверяет доступность хоста по UDP (для Hysteria2).
    
    Args:
        host: IP-адрес или домен.
        port: Порт для проверки.
        timeout: Таймаут в секундах.
    
    Returns:
        True если хост отвечает, False в противном случае.
    """
    try:
        clean_host = host.strip("[]")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Отправляем пустой пакет
        sock.sendto(b'', (clean_host, port))
        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return True
        except socket.timeout:
            # Для Hysteria2 отсутствие ответа не всегда означает недоступность
            # Но если сервер жив — он должен ответить
            sock.close()
            return False
    except Exception:
        return False


def check_node_health(
    outbound: dict,
    timeout: float = 5.0,
    protocol: str = "auto",
) -> bool:
    """Проверяет доступность ноды.
    
    Args:
        outbound: словарь outbound конфига SingBox.
        timeout: таймаут проверки.
        protocol: тип протокола ('tcp', 'udp', 'auto').
    
    Returns:
        True если нода доступна, False в противном случае.
    """
    server = str(outbound.get("server", ""))
    port = outbound.get("server_port", 0)
    
    if not server or not port:
        return False
    
    if protocol == "udp" or (protocol == "auto" and outbound.get("type") == "hysteria2"):
        return check_udp_ping(server, port, timeout)
    else:
        return check_tcp_connect(server, port, timeout)
