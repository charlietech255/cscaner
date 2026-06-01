#!/usr/bin/env python3
"""
CSCAN — Live NVD CVE Database Integration
Pulls fresh vulnerability data from NIST NVD API v2.
Results are cached locally (TTL = 24h) to avoid hammering the API.
"""

import json
import os
import re
import time
from datetime import datetime

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.ui import (
    section, ok, warn, alert, info, critical, divider,
    progress_bar, G, R, Y, C, M, W, BR, DM, RS
)

# ── Cache config ──────────────────────────────────────────────────────────────
_CACHE_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.nvd_cache')
_CACHE_TTL  = 86400   # 24 hours
_NVD_BASE   = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
_TIMEOUT    = 15

# ── CVSS severity thresholds ──────────────────────────────────────────────────
def _cvss_label(score):
    if score is None: return ('UNKNOWN', W)
    s = float(score)
    if s >= 9.0: return ('CRITICAL', R)
    if s >= 7.0: return ('HIGH',     Y)
    if s >= 4.0: return ('MEDIUM',   C)
    return ('LOW', G)


def _cache_path(key: str) -> str:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', key)
    return os.path.join(_CACHE_DIR, f'{safe}.json')


def _read_cache(key: str):
    p = _cache_path(key)
    try:
        with open(p) as f:
            data = json.load(f)
        if time.time() - data.get('_cached_at', 0) < _CACHE_TTL:
            return data.get('payload')
    except Exception:
        pass
    return None


def _write_cache(key: str, payload):
    p = _cache_path(key)
    try:
        with open(p, 'w') as f:
            json.dump({'_cached_at': time.time(), 'payload': payload}, f)
    except Exception:
        pass


# ── NVD query helpers ─────────────────────────────────────────────────────────
def _query_nvd(params: dict) -> dict | None:
    try:
        r = requests.get(_NVD_BASE, params=params, timeout=_TIMEOUT,
                         headers={'User-Agent': 'CSCAN/2.2 (security research)'})
        if r.status_code == 200:
            return r.json()
        if r.status_code == 429:
            warn("NVD API rate limit hit — retrying in 6s…")
            time.sleep(6)
            r = requests.get(_NVD_BASE, params=params, timeout=_TIMEOUT,
                             headers={'User-Agent': 'CSCAN/2.2 (security research)'})
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        warn(f"NVD API error: {e}")
    return None


def _extract_cve_summary(item: dict) -> dict:
    """Flatten a single NVD CVE item into a compact dict."""
    cve = item.get('cve', {})
    cve_id = cve.get('id', 'N/A')

    # Description (English preferred)
    descs  = cve.get('descriptions', [])
    desc   = next((d['value'] for d in descs if d.get('lang') == 'en'), 'No description')

    # CVSS score — prefer v3.1, fall back to v3.0, then v2
    metrics = cve.get('metrics', {})
    score, vector = None, None
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = metrics.get(key, [])
        if entries:
            data   = entries[0].get('cvssData', {})
            score  = data.get('baseScore')
            vector = data.get('vectorString')
            break

    # References
    refs = [r['url'] for r in cve.get('references', [])[:3]]

    # Published / modified dates
    published = cve.get('published', 'N/A')[:10]
    modified  = cve.get('lastModified', 'N/A')[:10]

    return {
        'cve_id':    cve_id,
        'score':     score,
        'vector':    vector,
        'desc':      desc[:200],
        'published': published,
        'modified':  modified,
        'refs':      refs,
    }


# ── Public API ────────────────────────────────────────────────────────────────
def search_cves_by_keyword(keyword: str, max_results: int = 10) -> list:
    """Search NVD for CVEs matching a keyword (service name, version, etc.)."""
    cache_key = f'kw_{keyword}_{max_results}'
    cached = _read_cache(cache_key)
    if cached is not None:
        return cached

    data = _query_nvd({'keywordSearch': keyword, 'resultsPerPage': max_results})
    if not data:
        return []

    items   = data.get('vulnerabilities', [])
    results = [_extract_cve_summary(i) for i in items]
    _write_cache(cache_key, results)
    return results


def search_cves_by_cpe(cpe_string: str, max_results: int = 20) -> list:
    """
    Search NVD for CVEs matching a CPE string, e.g.:
    cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*
    """
    cache_key = f'cpe_{cpe_string}'
    cached = _read_cache(cache_key)
    if cached is not None:
        return cached

    data = _query_nvd({'cpeName': cpe_string, 'resultsPerPage': max_results})
    if not data:
        return []

    items   = data.get('vulnerabilities', [])
    results = [_extract_cve_summary(i) for i in items]
    _write_cache(cache_key, results)
    return results


# ── Software → CPE mapping ────────────────────────────────────────────────────
_SOFTWARE_CPE_MAP = {
    'nginx':      'cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*',
    'apache':     'cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*',
    'openssh':    'cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*',
    'openssl':    'cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*',
    'php':        'cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*',
    'mysql':      'cpe:2.3:a:mysql:mysql:{version}:*:*:*:*:*:*:*',
    'postgresql': 'cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*',
    'mongodb':    'cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*',
    'redis':      'cpe:2.3:a:redislabs:redis:{version}:*:*:*:*:*:*:*',
    'wordpress':  'cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*',
    'joomla':     r'cpe:2.3:a:joomla:joomla\!:{version}:*:*:*:*:*:*:*',
    'drupal':     'cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*',
    'iis':        'cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*',
}


def _build_cpe(software: str, version: str) -> str | None:
    key = software.lower().replace(' ', '').replace('-', '')
    tpl = _SOFTWARE_CPE_MAP.get(key)
    if tpl and version:
        # Strip leading 'v' and trailing qualifiers like 'p1', 'ubuntu...'
        clean_ver = re.sub(r'p\d+$', '', version.lstrip('v'))
        return tpl.replace('{version}', clean_ver)
    return None


def _display_cve(c: dict):
    sev, col = _cvss_label(c['score'])
    score_str = f"{c['score']}" if c['score'] else 'N/A'
    print(f"  {BR}{col}[{sev}]{RS}  {BR}{W}{c['cve_id']}{RS}  {DM}CVSS {score_str}{RS}")
    print(f"         {DM}{c['desc'][:100]}...{RS}")
    print(f"         {DM}Published:{RS} {c['published']}  |  {DM}Modified:{RS} {c['modified']}")
    if c.get('refs'):
        print(f"         {DM}Ref:{RS} {c['refs'][0]}")
    print()


# ── Live CVE mapping (main feature) ──────────────────────────────────────────
def live_cve_mapping(detected_versions: dict, ports_data: list = None) -> dict:
    """
    Given a dict of {software_name: version_string} (+ optional port banners),
    query NVD live and return full CVE details.
    """
    section("LIVE NVD CVE MAPPING")
    info(f"Source: {BR}{C}NIST National Vulnerability Database (api.nvd.nist.gov){RS}")
    info(f"Cache TTL: {BR}{C}24 hours{RS}\n")

    # Merge in banner-extracted versions
    if ports_data:
        from modules.web import CVE_DATABASE
        import re as _re
        for port, banner in (ports_data or []):
            if not banner:
                continue
            for tech, tech_data in CVE_DATABASE.items():
                pat = tech_data.get('pattern')
                if pat:
                    m = _re.search(pat, banner, _re.IGNORECASE)
                    if m and tech not in detected_versions:
                        detected_versions[tech] = m.group(1)
                        info(f"Banner ({port}/tcp): {BR}{G}{tech} {m.group(1)}{RS}")

    if not detected_versions:
        warn("No software versions provided — run Version Extraction first.")
        return {}

    results = {}
    total   = len(detected_versions)

    for i, (software, version) in enumerate(detected_versions.items(), 1):
        progress_bar(i, total, f'{software} {version}')
        print()  # newline after progress bar
        info(f"Checking {BR}{W}{software} {version}{RS}…")

        cves = []

        # Try CPE-based search first (most precise)
        cpe = _build_cpe(software, version)
        if cpe:
            cves = search_cves_by_cpe(cpe, max_results=15)

        # Fallback to keyword search
        if not cves:
            keyword = f"{software} {version}"
            cves    = search_cves_by_keyword(keyword, max_results=10)

        if cves:
            alert(f"Found {BR}{R}{len(cves)}{RS} CVE(s) for {software} {version}")
            for c in cves[:5]:  # show top 5
                _display_cve(c)
            results[software] = {
                'version': version,
                'cve_count': len(cves),
                'cves': cves,
            }
        else:
            ok(f"{software} {version} — no CVEs found in NVD (may be patched or too new).")

        # NVD public API rate limit: ~5 req/s, be polite
        time.sleep(0.8)

    divider()
    total_cves = sum(r['cve_count'] for r in results.values())
    if total_cves:
        critical(f"Total {total_cves} CVE(s) found across {len(results)} software component(s)!")
        info("Priority: patch CRITICAL (CVSS ≥ 9.0) first, then HIGH (≥ 7.0).")
    else:
        ok("No CVEs found — software appears current. Keep monitoring NVD.")

    return results


# ── Interactive menu function ─────────────────────────────────────────────────
def menu_nvd_lookup() -> dict:
    """Manual CVE lookup by software + version keyword."""
    section("NVD LIVE CVE LOOKUP")
    info("Search the NIST National Vulnerability Database for a specific software.")
    print()
    software = input(f"  {BR}{W}Software name (e.g. nginx, OpenSSH, WordPress): {RS}").strip()
    version  = input(f"  {BR}{W}Version (e.g. 1.24.0, 9.6, 6.4.2) — optional : {RS}").strip()

    if not software:
        warn("No software entered.")
        return {}

    keyword = f"{software} {version}".strip()
    info(f"Querying NVD for: {BR}{C}{keyword}{RS}\n")

    cves = search_cves_by_keyword(keyword, max_results=15)
    if not cves:
        warn("No CVEs found. Try a different keyword or check spelling.")
        return {}

    ok(f"Found {len(cves)} result(s):")
    print()
    for c in cves:
        _display_cve(c)

    return {'keyword': keyword, 'cves': cves}
