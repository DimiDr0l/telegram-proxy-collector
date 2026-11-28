#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MTProto & SOCKS5 Proxy Collector v4.2
# - FIX: регион определяется по GeoIP (ISO-коду страны), а не только по домену в secret
# - FIX: GeoIP: maxminddb.open_database + fallback на geoip2
# - Расширенный фильтр подозрительных портов (Tomcat, Minecraft, RDP…)
# - Расширенный ALLOWED_COUNTRIES: Азия, Ближний Восток, Мексика
# - ADD: источники kort0881/telegram-proxy-collector (regional + all + socks5)
# - ADD: MANUAL_PROXIES — всегда проверяемые прокси
# - ADD: проверка ответа Telegram через MTProto и SOCKS5 после TCP ping

import requests
import re
import socket
import concurrent.futures
import time
import random
from datetime import datetime, timezone
from html import escape
import json
import os
import argparse
from typing import Optional, Set, List, Dict, Any, Tuple
from urllib.parse import quote, unquote
import logging

from telegram_proxy import MTProxySecret, check_telegram_proxy

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ---------- GEOIP ----------
geoip_reader = None
GEOIP_MODE = None

try:
    import maxminddb
    _HAS_MAXMIND = hasattr(maxminddb, 'open_database')
except ImportError:
    maxminddb = None
    _HAS_MAXMIND = False

try:
    from geoip2.database import Reader as GeoIP2Reader
    _HAS_GEOIP2 = True
except ImportError:
    GeoIP2Reader = None
    _HAS_GEOIP2 = False

# ------------------ НАСТРОЙКИ ------------------
RU_DOMAINS = ['.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube', 'sber', 'tinkoff', 'vtb', 'gosuslugi', 'nalog', 'mos.ru', 'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline']
US_DOMAINS = ['.us', '.nyc', '.la', '.sf', '.dallas', 'amazonaws.com', 'digitalocean.com', '.gov', 'cloudflare.com']
ASIA_DOMAINS = ['.asia', '.jp', '.cn', '.sg', '.hk', '.kr', '.in', '.tw', '.ph', '.my', '.id', '.vn', '.th']
BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject']

# ISO-коды стран → регион сайта
RU_COUNTRIES   = {'RU', 'BY', 'KZ', 'UA', 'MD', 'AM', 'GE', 'AZ', 'UZ', 'KG', 'TJ', 'TM'}
US_COUNTRIES   = {'US', 'CA', 'MX'}
ASIA_COUNTRIES = {'JP', 'KR', 'SG', 'HK', 'IN', 'TW', 'PH', 'MY', 'ID', 'VN', 'TH', 'MN',
                  'CN', 'MO', 'AE', 'SA', 'IL', 'PK', 'BD', 'NP', 'LK', 'KH', 'MM', 'LA', 'BN'}

# Порты, которые НЕ бывают MTProto
SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 161, 162,
    389, 445, 465, 514, 587, 631, 993, 995,
    1433, 1521, 2049, 3306, 5432, 5900, 6379, 9200, 11211, 27017,
    80, 1080, 3389,
    8009, 8080, 8443, 25565,
}

ALLOWED_COUNTRIES = {
    'RU','BY','KZ','UA','MD','AM','GE','AZ','UZ','KG','TJ','TM',
    'DE','NL','FI','GB','FR','SE','PL','CZ','AT','CH','IT','ES',
    'NO','DK','BE','IE','LU','EE','LV','LT','PT','GR','RO','BG',
    'HU','SK','SI','HR','RS','TR',
    'CA','US','MX',
    'JP','KR','SG','HK','IN','TW','PH','MY','ID','VN','TH','MN',
    'CN','MO','AE','SA','IL','PK','BD','NP','LK','KH','MM','LA','BN',
}

# ---------- Ручные прокси (проверяются всегда) ----------
MANUAL_PROXIES = [
    "tg://proxy?server=iriguchi.proxy.rlwy.net&port=45066&secret=eebb8410139359861806644276b18735327777772e636c6f7564666c6172652e636f6d",
    "tg://proxy?server=shortline.proxy.rlwy.net&port=36077&secret=ee31fcc7de872ddee361f1217d9a0377e17777772e636c6f7564666c6172652e636f6d",
    "tg://proxy?server=monorail.proxy.rlwy.net&port=52938&secret=654e03cc7529c0da7164ecad503d9d0d",
    "tg://proxy?server=monorail.proxy.rlwy.net&port=52938&secret=dd654e03cc7529c0da7164ecad503d9d0d",
    "tg://proxy?server=ballast.proxy.rlwy.net&port=31126&secret=e8fa724103180483b35921b1d926118a",
    # из issues #64 (NormOne, 26.10.2026)
    "tg://proxy?server=tg.normone.cc&port=443&secret=ee8e1b968cc826dbb4c2d6f288b4313d337777772e676f6f676c652e636f6d",
    "tg://proxy?server=proxy-a.normone.cc&port=8444&secret=ee0579c89b293b8ed2cc6cf535da97b28a706574726f766963682e7275",
    "tg://proxy?server=proxy-b.normone.cc&port=9443&secret=ddae0e2ca6e12d135fe03ae3bac49ce415",
    "tg://proxy?server=proxy-c.normone.cc&port=10443&secret=ee248678d3439f2b14508773c98c3b46787777772e6d6963726f736f66742e636f6d",
]

# ---------- Источники ----------
SOURCES = [
    # --- твой репозиторий kort0881/telegram-proxy-collector ---
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_us.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_asia.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all_mtproto.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt",

    # --- внешние источники ---
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://mhditaheri.github.io/ProxyCollector/proxy.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/refs/heads/main/mtproto.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/refs/heads/main/proxy_all.txt",
    "https://raw.githubusercontent.com/Maxsool/MTProxyCollector/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/kubiknubika/my-tg-proxies/refs/heads/main/data/proxies.json",
    "https://raw.githubusercontent.com/shablin/mtproto-proxy/refs/heads/main/data/valid_proxy.json",
    "https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/global-iran-russia-proxies.txt",
    "https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/turkmenistan-global-iran-russia.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/McDaived/ProxyDaiv/refs/heads/main/public/proxies.json",
    "https://raw.githubusercontent.com/weltimistar777-crypto/MTProxy/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_verified.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_tme_verified.txt",
    "https://raw.githubusercontent.com/Airuop/MTProtoCollector/refs/heads/main/proxy/mtproto.json",
    "https://raw.githubusercontent.com/blog1703/tgonline/refs/heads/main/proxies.txt",
    # из issue #40 (VestraNet-Nodes, 310 прокси на 18.11)
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/mtproto.txt",
    "https://moonlunavpn.com/proxies.txt",
    "https://moonlunavpn.com/proxies.json",
    "https://tgmtproxy.github.io/mtproxy/proxies.txt",
]

SOCKS_SOURCES = [
    # --- твой репозиторий ---
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/socks5.txt",

    # --- внешние ---
    "https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt",
    "https://gist.githubusercontent.com/December000/fd23d2530ffc29264297a5e687a79ecd/raw/all.yaml",
    "https://raw.githubusercontent.com/CB-X2-Jun/proxy-lists/main/proxy.txt",
    "https://raw.githubusercontent.com/CB-X2-Jun/proxy-lists/main/public/proxies.json",
    "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/all/data.txt",
]

# ---------- Регэкспы MTProto (единый источник правды) ----------
# (pattern, flags) — флаги у формата host:port:secret отличаются, поэтому они в паре
MTPROTO_PATTERNS = [
    (r'tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', re.I),
    (r't\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)', re.I),
    (r'(?<![A-Za-z0-9.-])(?<!(?i:socks5://))([A-Za-z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})', 0),
]

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
def _valid_port(p: str) -> bool:
    try:
        return 1 <= int(p) <= 65535
    except ValueError:
        return False

def _region_from_country(iso_code: Optional[str]) -> str:
    if not iso_code:
        return 'eu'
    code = iso_code.upper()
    if code in RU_COUNTRIES:   return 'ru'
    if code in US_COUNTRIES:   return 'us'
    if code in ASIA_COUNTRIES: return 'asia'
    return 'eu'

def _detect_region(domain: Optional[str]) -> str:
    if not domain:
        return 'eu'
    d = domain.lower()
    if any(m in d for m in RU_DOMAINS):   return 'ru'
    if any(m in d for m in US_DOMAINS):   return 'us'
    if any(m in d for m in ASIA_DOMAINS): return 'asia'
    return 'eu'

def _load_geoip(path: str):
    global GEOIP_MODE
    if _HAS_MAXMIND:
        try:
            reader = maxminddb.open_database(path)
            GEOIP_MODE = 'maxminddb'
            return reader
        except Exception as e:
            print(f'⚠️ maxminddb.open_database не сработал: {e}')
    if _HAS_GEOIP2:
        try:
            reader = GeoIP2Reader(path)
            GEOIP_MODE = 'geoip2'
            return reader
        except Exception as e:
            print(f'⚠️ geoip2.Reader не сработал: {e}')
    return None

def _geo_country(address: str) -> Optional[Tuple[str, str]]:
    if geoip_reader is None:
        return None
    try:
        if GEOIP_MODE == 'maxminddb':
            country = (geoip_reader.get(address) or {}).get('country') or {}
            code, names = country.get('iso_code'), country.get('names') or {}
        elif GEOIP_MODE == 'geoip2':
            country = geoip_reader.country(address).country
            code, names = country.iso_code, country.names
        else:
            return None
        if code:
            return code.upper(), names.get('ru') or names.get('en') or code.upper()
    except Exception:
        return None
    return None

def get_proxies_from_text(text: str, *, include_socks: bool = True) -> Set[Tuple[str, str, int, Any]]:
    proxies = set()
    mtproto_ips = set()
    link_text = text.replace('&amp;', '&')

    for pattern, flags in MTPROTO_PATTERNS:
        for h, p, s in re.findall(pattern, link_text, flags):
            if _valid_port(p):
                proxies.add(('mtproto', h, int(p), s)); mtproto_ips.add((h, int(p)))
    for h, p, u, pw in re.findall(r'tg://socks\?server=([^&\s]+)&port=(\d+)(?:&(?:user|username)=([^&\s]*))?(?:&(?:pass|password)=([^&\s]*))?', link_text, re.I):
        if _valid_port(p):
            proxies.add(('socks5', h, int(p), (unquote(u) if u else None, unquote(pw) if pw else None)))
    for u, pw, h, p in re.findall(r'socks5://(?:([^:@]+):([^@]+)@)?([A-Za-z0-9\.-]+):(\d+)', text, re.I):
        if _valid_port(p):
            proxies.add(('socks5', h, int(p), (unquote(u) if u else None, unquote(pw) if pw else None)))
    for match in re.findall(r'(socks5)://([\d.]+):(\d+):\w+', text, re.I):
        ip, port = match[1], match[2]
        if _valid_port(port):
            proxies.add(('socks5', ip, int(port), (None, None)))

    txt = text.strip()
    if txt.startswith('[') or txt.startswith('{'):
        try:
            data = json.loads(txt)
            items = data if isinstance(data, list) else [data]
            for item in items:
                if not isinstance(item, dict): continue
                if 'host' in item and 'port' in item and 'secret' in item:
                    h, p, s = item['host'], str(item['port']), str(item['secret'])
                    if _valid_port(p):
                        proxies.add(('mtproto', h, int(p), s)); mtproto_ips.add((h, int(p)))
                elif 'socks5' in str(item).lower() and ('ip' in item or 'host' in item) and 'port' in item:
                    h = item.get('ip') or item.get('host')
                    if h is None: continue
                    p = str(item['port'])
                    if _valid_port(p):
                        proxies.add(('socks5', h, int(p), (None, None)))
        except json.JSONDecodeError:
            pass

    if 'proxies:' in txt:
        try:
            import yaml
            data = yaml.safe_load(text)
            if isinstance(data, dict) and 'proxies' in data:
                for item in data['proxies']:
                    if item.get('type') == 'socks5':
                        server, port = item.get('server'), str(item.get('port'))
                        if server and port and _valid_port(port):
                            proxies.add(('socks5', server, int(port), (None, None)))
        except (ImportError, Exception):
            pass

    if not include_socks:
        return {p for p in proxies if p[0] != 'socks5'}
    return proxies

def fetch_source(session: requests.Session, url: str, timeout: int = 15) -> str:
    for attempt in range(3):
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.text
        except requests.Timeout:
            logger.debug(f"Timeout fetching {url} (attempt {attempt + 1})")
        except requests.RequestException as exc:
            logger.debug(f"Error fetching {url} (attempt {attempt + 1}): {exc}")
        time.sleep(0.5 * (2 ** attempt))
    return ''

def check_proxy_tcp(p: Tuple[str, str, int, Any], timeout: float) -> Optional[Dict[str, Any]]:
    typ, host, port, extra = p
    host = str(host).strip()
    if not host:
        return None

    if typ == 'mtproto' and port in SUSPICIOUS_PORTS and p not in MANUAL_KEYS:
        return None

    country = _geo_country(host)
    if country and country[0] not in ALLOWED_COUNTRIES:
        return None

    proxy_secret = None
    credentials = (None, None)
    if typ == 'mtproto':
        try:
            proxy_secret = MTProxySecret.parse(extra)
        except ValueError:
            return None
        domain = proxy_secret.domain
        if any(blocked in domain for blocked in BLOCKED):
            return None
        link = f'tg://proxy?server={host}&port={port}&secret={extra}'
        domain_str = domain
    elif typ == 'socks5':
        link = f'tg://socks?server={host}&port={port}'
        if isinstance(extra, tuple) and len(extra) == 2:
            credentials = extra
        user, password = credentials
        if user:
            link += f'&user={quote(user, safe="")}'
            if password is not None:
                link += f'&pass={quote(password, safe="")}'
        domain_str = ''
    else:
        return None

    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as connection:
            ping = round(time.monotonic() - start, 3)
            if geoip_reader is not None and country is None:
                country = _geo_country(connection.getpeername()[0])
                if country and country[0] not in ALLOWED_COUNTRIES:
                    return None
        start = time.monotonic()
        if not check_telegram_proxy(host, port, timeout, secret=proxy_secret, credentials=credentials):
            return None
        response_time = time.monotonic() - start
        country_code, country_name = country or (None, None)
        region = _detect_region(domain_str) if domain_str else _region_from_country(country_code)
        return {
            'type': typ, 'host': host, 'port': port,
            'secret': extra if typ == 'mtproto' else None,
            'link': link, 'ping': ping, 'region': region,
            'domain': domain_str, 'probe_resistant': False,
            'country_code': country_code, 'country_name': country_name, 'response_time': response_time,
        }
    except (socket.timeout, socket.error, OSError, TypeError):
        return None

def deduplicate_and_sort(proxies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []
    for p in proxies:
        key = (p['type'], p['host'], p['port'], p.get('secret'))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    unique.sort(key=lambda x: (
        0 if (x['type'] == 'mtproto' and x.get('probe_resistant', False)) else 1 if x['type'] == 'mtproto' else 2,
        x['ping']
    ))
    return unique

def _report_groups(proxies: List[Dict[str, Any]], top: int):
    countries: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for proxy in proxies:
        countries.setdefault(proxy['country_code'], []).append(proxy)

    groups = []
    for code in sorted(countries, key=lambda code: (code is None, code or '')):
        ranked = sorted(countries[code], key=lambda proxy: (
            proxy['response_time'], proxy['host'], proxy['port'], proxy['link'],
        ))
        name = ranked[0]['country_name']
        label = f'{name} ({code})' if name and name != code else code or 'Страна не определена'
        rows = []
        for proxy in ranked[:top]:
            host = proxy['host']
            endpoint = f'[{host}]:{proxy["port"]}' if ':' in host else f'{host}:{proxy["port"]}'
            protocol = 'MTProto' if proxy['type'] == 'mtproto' else 'SOCKS5'
            rows.append((endpoint, proxy['link'], protocol, round(proxy['response_time'] * 1000)))
        groups.append((label, rows))
    return groups

def write_html_report(path: str, groups, utc: datetime):
    with open(path, 'w', encoding='utf-8') as report:
        report.write('''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Проверенные прокси Telegram</title>
<style>
  :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
  body { max-width: 52rem; margin: 0 auto; padding: 1.5rem 1rem; }
  section { margin-block: 2rem; }
  h1, h2 { line-height: 1.2; }
  table { width: 100%; table-layout: fixed; border-collapse: collapse; text-align: left; }
  th, td { padding: .5rem .25rem; border-bottom: 1px solid GrayText; overflow-wrap: anywhere; }
  th:first-child { width: 50%; }
  :is(th, td):last-child { text-align: right; font-variant-numeric: tabular-nums; }
</style>
</head>
<body>
<main>
<h1>Проверенные прокси Telegram</h1>
''')
        report.write(f'<p>Проверено <time datetime="{utc.isoformat()}">{utc:%Y-%m-%d %H:%M:%S} UTC</time></p>\n')
        if not groups:
            report.write('<p>Рабочие прокси не найдены.</p>\n')

        for label, rows in groups:
            report.write(f'<section>\n<h2>{escape(label)}</h2>\n<table>\n'
                         '<thead><tr><th scope="col">Подключиться</th><th scope="col">Протокол</th>'
                         '<th scope="col">Ответ Telegram, мс</th></tr></thead>\n<tbody>\n')
            for endpoint, link, protocol, milliseconds in rows:
                report.write(f'<tr><td><a href="{escape(link)}">{escape(endpoint)}</a></td>'
                             f'<td>{protocol}</td><td>{milliseconds}</td></tr>\n')
            report.write('</tbody>\n</table>\n</section>\n')
        report.write('</main>\n</body>\n</html>\n')

def _escape_markdown(text: str) -> str:
    return re.sub(r'[\\\[\]_*<>|&#~`]', lambda match: '\\' + match.group(), ' '.join(text.splitlines()))

def write_markdown_report(path: str, groups, utc: datetime):
    with open(path, 'w', encoding='utf-8') as report:
        report.write(f'# Проверенные прокси Telegram\n\nПроверено {utc:%Y-%m-%d %H:%M:%S} UTC\n')
        if not groups:
            report.write('\nРабочие прокси не найдены.\n')

        for label, rows in groups:
            report.write(f'\n## {_escape_markdown(label)}\n\n'
                         '| Подключиться | Протокол | Ответ Telegram, мс |\n'
                         '| --- | --- | ---: |\n')
            for endpoint, link, protocol, milliseconds in rows:
                url = 'https://t.me/' + link.removeprefix('tg://')
                url = quote(url, safe=':/?&=%')
                report.write(f'| [{_escape_markdown(endpoint)}]({url}) | {protocol} | {milliseconds} |\n')

def _write_reports(output_dir, report_writers, proxies, top, utc):
    groups = _report_groups(proxies, top)
    for extension, writer in report_writers:
        path = os.path.join(output_dir, f'proxy_report.{extension}')
        writer(path, groups, utc)
        print(f'💾 Отчёт: {path}')

def load_local_proxies(file_path: str, *, include_socks: bool = True) -> Set[Tuple[str, str, int, Any]]:
    if not os.path.isfile(file_path):
        return set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            proxies = get_proxies_from_text(f.read(), include_socks=include_socks)
        print(f"✓ Загружено {len(proxies)} прокси из {file_path}")
        return proxies
    except IOError as e:
        print(f"✗ Ошибка чтения {file_path}: {e}")
        return set()

# Ключи прокси из MANUAL_PROXIES — для них фильтр SUSPICIOUS_PORTS не применяется
MANUAL_KEYS = get_proxies_from_text('\n'.join(MANUAL_PROXIES))

# ---------- MAIN ----------
def run(args):
    global geoip_reader, GEOIP_MODE

    include_socks = not getattr(args, 'skip_socks', False)
    report_writers = []
    if getattr(args, 'html_report', False):
        report_writers.append(('html', write_html_report))
    if getattr(args, 'markdown_report', False):
        report_writers.append(('md', write_markdown_report))
    start_time = time.time()
    print('🚀 MTProxy Collector v4.2')
    print('=' * 48)

    geoip_path = args.geoip or ('data/GeoLite2-Country.mmdb' if report_writers else None)
    geoip_reader = GEOIP_MODE = None
    if geoip_path and os.path.isfile(geoip_path):
        geoip_reader = _load_geoip(geoip_path)
        if geoip_reader is not None:
            print(f"✅ GeoIP загружен ({GEOIP_MODE}) из {geoip_path}")
        else:
            print("⚠️ Не удалось загрузить базу GeoIP, проверка по стране отключена")
    else:
        print("⚠️ База GeoIP не указана или не найдена, проверка по стране отключена.")

    os.makedirs(args.output_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })

    all_raw: Set[Tuple[str, str, int, Any]] = set()

    print('\n📥 Сбор MTProto...')
    for url in SOURCES:
        name = (url.split('/')[-1] or url.split('/')[-2])[:42]
        text = fetch_source(session, url)
        if text:
            ext = get_proxies_from_text(text, include_socks=include_socks)
            cnt = sum(1 for x in ext if x[0] == 'mtproto')
            all_raw.update(ext)
            print(f'  ✓ {name:<42} +{cnt} MTProto')
        else:
            print(f'  ✗ {name:<42} недоступен')

    if include_socks:
        print('\n📥 Сбор SOCKS5...')
        for url in SOCKS_SOURCES:
            name = (url.split('/')[-1] or url.split('/')[-2])[:42]
            text = fetch_source(session, url)
            if text:
                ext = get_proxies_from_text(text)
                cnt = sum(1 for x in ext if x[0] == 'socks5')
                all_raw.update(ext)
                print(f'  ✓ {name:<42} +{cnt} SOCKS5')
            else:
                print(f'  ✗ {name:<42} недоступен')

    # MANUAL_PROXIES — всегда
    manual_count = len(MANUAL_PROXIES)
    if MANUAL_PROXIES:
        manual_parsed = get_proxies_from_text('\n'.join(MANUAL_PROXIES), include_socks=include_socks)
        all_raw.update(manual_parsed)
        if not include_socks:
            manual_count = len(manual_parsed)
        print(f'\n📌 MANUAL_PROXIES: +{len(manual_parsed)} (из {len(MANUAL_PROXIES)} строк)')

    if args.manual:
        all_raw.update(load_local_proxies(args.manual, include_socks=include_socks))

    print(f'\n🧩 Уникальных прокси всего: {len(all_raw)}')
    if include_socks and not all_raw:
        if report_writers and not args.dry_run:
            _write_reports(args.output_dir, report_writers, [], 0, datetime.now(timezone.utc))
        print('\n⚠️ Нет прокси. Завершение.')
        return

    if args.max_check and len(all_raw) > args.max_check:
        all_raw = set(random.sample(list(all_raw), args.max_check))
        print(f'⚠️ Ограничено до {args.max_check} случайных прокси')

    if args.dry_run:
        print('\n🧪 DRY-RUN: собрано прокси, TCP-проверка пропущена.')
        print(f'   Уникальных прокси: {len(all_raw)}')
        print(f"   MTProto: {sum(1 for x in all_raw if x[0] == 'mtproto')}")
        if include_socks:
            print(f"   SOCKS5: {sum(1 for x in all_raw if x[0] == 'socks5')}")
        return

    print(f'\n⚡ Проверка {len(all_raw)} прокси (TCP ping и ответ Telegram)...\n')
    valid = []
    checked = 0
    total = len(all_raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(check_proxy_tcp, p, args.timeout): p for p in all_raw}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            checked += 1
            if res:
                valid.append(res)
            if checked % 500 == 0 or checked == total:
                print(f'  [{checked}/{total}] {checked/total*100:.0f}% | найдено: {len(valid)}')

    if not valid:
        print('\n⚠️ Рабочих прокси не найдено.')

    valid = deduplicate_and_sort(valid)
    mtproto_ru   = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'ru']
    mtproto_eu   = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'eu']
    mtproto_us   = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'us']
    mtproto_asia = [x for x in valid if x['type'] == 'mtproto' and x['region'] == 'asia']
    socks5       = [x for x in valid if x['type'] == 'socks5']

    top = args.top if args.top > 0 else len(valid)
    utc = datetime.now(timezone.utc)

    print(f'\n💾 Сохранение в {args.output_dir}/...')

    all_proxies = mtproto_ru[:top] + mtproto_eu[:top] + mtproto_us[:top] + mtproto_asia[:top] + socks5[:top]
    all_proxies.sort(key=lambda x: (x['region'], x['ping']))

    files_data = {
        'proxy_ru_verified.txt':   (mtproto_ru[:top],   f'# MTProto RU ({len(mtproto_ru[:top])})\n# Updated: {utc}\n\n'),
        'proxy_eu_verified.txt':   (mtproto_eu[:top],   f'# MTProto EU ({len(mtproto_eu[:top])})\n# Updated: {utc}\n\n'),
        'proxy_us_verified.txt':   (mtproto_us[:top],   f'# MTProto US ({len(mtproto_us[:top])})\n# Updated: {utc}\n\n'),
        'proxy_asia_verified.txt': (mtproto_asia[:top], f'# MTProto ASIA ({len(mtproto_asia[:top])})\n# Updated: {utc}\n\n'),
        'socks5_proxies.txt':      (socks5[:top],       f'# SOCKS5 ({len(socks5[:top])})\n# Updated: {utc}\n\n'),
        'proxy_all_tme_verified.txt': (all_proxies, f'# Verified Proxies t.me format ({len(all_proxies)})\n# Updated: {utc}\n\n'),
        'proxy_all.txt':           (all_proxies, f'# All proxies ({len(all_proxies)})\n# Updated: {utc}\n\n'),
        'proxy_all_verified.txt':  (all_proxies, f'# All verified proxies ({len(all_proxies)})\n# Updated: {utc}\n\n'),
        'proxy_links.txt':         (all_proxies, f'# Proxy links ({len(all_proxies)})\n# Updated: {utc}\n\n'),
        'proxy_links_clean.txt':   (all_proxies, f'# Clean proxy links ({len(all_proxies)})\n# Updated: {utc}\n\n'),
        'proxy_links_tme_clean.txt': (all_proxies, f'# Clean t.me proxy links ({len(all_proxies)})\n# Updated: {utc}\n\n'),
    }

    for filename, (data, header) in files_data.items():
        with open(f'{args.output_dir}/{filename}', 'w', encoding='utf-8') as f:
            f.write(header + '\n'.join(x['link'] for x in data))

    with open(f'{args.output_dir}/verification.log', 'w', encoding='utf-8') as f:
        f.write(f"Verification completed at {utc}\n")
        f.write(f"GeoIP mode: {GEOIP_MODE}\n")
        f.write(f"Total proxies checked: {total}\n")
        f.write(f"Valid proxies found: {len(valid)}\n")
        f.write(f"Top saved: {top}\n")
        f.write(f"Manual proxies: {manual_count}\n")

    domain_proxies = [p for p in all_proxies if p.get('domain')]
    with open(f'{args.output_dir}/proxy_domain_verified.txt', 'w', encoding='utf-8') as f:
        f.write(f"# Proxies with domain ({len(domain_proxies)})\n# Updated: {utc}\n\n")
        for p in domain_proxies:
            f.write(f"{p['link']} # domain: {p['domain']}\n")

    if report_writers:
        _write_reports(args.output_dir, report_writers, valid, top, utc)

    elapsed = round(time.time() - start_time, 1)
    print('=' * 48)
    summary = f'✅ MTProto RU: {len(mtproto_ru)}  EU: {len(mtproto_eu)}  US: {len(mtproto_us)}  ASIA: {len(mtproto_asia)}'
    if include_socks:
        summary += f'  SOCKS5: {len(socks5)}'
    print(summary)
    if mtproto_ru:   print(f'🏆 Лучший RU: {mtproto_ru[0]["host"]}:{mtproto_ru[0]["port"]} ({mtproto_ru[0]["ping"]}s)')
    if mtproto_eu:   print(f'🏆 Лучший EU: {mtproto_eu[0]["host"]}:{mtproto_eu[0]["port"]} ({mtproto_eu[0]["ping"]}s)')
    if mtproto_us:   print(f'🏆 Лучший US: {mtproto_us[0]["host"]}:{mtproto_us[0]["port"]} ({mtproto_us[0]["ping"]}s)')
    if mtproto_asia: print(f'🏆 Лучший ASIA: {mtproto_asia[0]["host"]}:{mtproto_asia[0]["port"]} ({mtproto_asia[0]["ping"]}s)')
    if socks5:       print(f'🏆 Лучший SOCKS5: {socks5[0]["host"]}:{socks5[0]["port"]} ({socks5[0]["ping"]}s)')
    print(f'⏱️ Время: {elapsed}s')
    print('=' * 48)

def main():
    parser = argparse.ArgumentParser(description="MTProto & SOCKS5 Proxy Collector v4.1")
    parser.add_argument('--timeout', type=float, default=2.0, help='Timeout in seconds for each check stage (TCP and Telegram)')
    parser.add_argument('--workers', type=int, default=100)
    parser.add_argument('--top', type=int, default=0)
    parser.add_argument('--output-dir', default='verified')
    parser.add_argument('--manual', type=str)
    parser.add_argument('--geoip', type=str)
    parser.add_argument('--max-check', type=int, default=30000)
    parser.add_argument('--skip-socks', action='store_true', help='Skip SOCKS5 sources and exclude SOCKS5 proxies from verification and reports')
    parser.add_argument('--html-report', action='store_true', help='Write proxy_report.html grouped by GeoIP country and ranked by Telegram response time')
    parser.add_argument('--markdown-report', action='store_true', help='Write proxy_report.md grouped by GeoIP country and ranked by Telegram response time')
    parser.add_argument('--dry-run', action='store_true', help='Only collect and parse proxies, skip network verification')
    args = parser.parse_args()
    run(args)

if __name__ == '__main__':
    main()
