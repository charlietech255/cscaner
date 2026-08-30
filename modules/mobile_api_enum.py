#!/usr/bin/env python3
"""
Lightweight API endpoint enumeration for mobile and low-resource environments.
This module is intentionally lighter than the full browser-driven API scanner.
It focuses on fast, readable results without heavy crawling or WAF bypass.
"""

import time
from datetime import datetime
from urllib.parse import urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.path_api_enum import DEFAULT_API_PATHS


def _coerce_target(target: str, use_ssl: bool = False) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    scheme = "https" if use_ssl else "http"
    return f"{scheme}://{target.rstrip('/')}"


def _is_api_path(path: str) -> bool:
    lowered = path.lower()
    api_markers = (
        "/api", "/v1", "/v2", "/graphql", "/swagger", "/openapi",
        "/oauth", "/auth", "/login", "/token", "/admin", "/internal",
        "/health", "/status", "/metrics", "/debug", "/actuator",
    )
    return any(marker in lowered for marker in api_markers)


def _category_for_path(path: str) -> str:
    lowered = path.lower()
    if "/auth" in lowered or "/login" in lowered or "/token" in lowered:
        return "AUTHENTICATION"
    if "/admin" in lowered or "/debug" in lowered or "/internal" in lowered:
        return "ADMIN/DEBUG"
    if "/health" in lowered or "/status" in lowered or "/metrics" in lowered:
        return "OBSERVABILITY"
    if "/graphql" in lowered or "/swagger" in lowered or "/openapi" in lowered:
        return "API_SPEC"
    if "/api" in lowered or "/v1" in lowered or "/v2" in lowered:
        return "API"
    return "GENERAL"


def _is_candidate_response(resp) -> bool:
    if resp is None:
        return False
    status = getattr(resp, "status_code", 0)
    if status in (404, 410):
        return False
    ctype = (resp.headers.get("Content-Type", "") or "").lower()
    text = (resp.text or "")[:1000].lower()
    if "json" in ctype or "xml" in ctype or "yaml" in ctype:
        return True
    for marker in ("openapi", "swagger", "graphql", "token", "message", "status", "error"):
        if marker in text:
            return True
    return status in (200, 201, 202, 204, 301, 302, 307, 401, 403, 405)


def _normalize_wordlist(wordlist):
    seen = set()
    items = []
    for entry in wordlist or DEFAULT_API_PATHS:
        if not entry:
            continue
        path = str(entry).strip()
        if not path.startswith("/"):
            path = "/" + path
        if path in seen:
            continue
        seen.add(path)
        items.append(path)
    return items


def enumerate_mobile_api_endpoints(
    target: str,
    use_ssl: bool = False,
    wordlist=None,
    probe: bool = True,
    timeout: float = 6.0,
    verify_ssl: bool = False,
) -> dict:
    """
    Run a lightweight API path scan for low-resource or mobile workflows.

    Args:
        target: target host or URL
        use_ssl: use HTTPS when target does not specify a scheme
        wordlist: explicit list of candidate paths. If absent, use common API paths
        probe: when False, return candidates without performing network requests
        timeout: per-request timeout in seconds
        verify_ssl: whether to verify TLS certificates

    Returns:
        dict with the target, counts, and a structured list of endpoints
    """
    base_url = _coerce_target(target, use_ssl)
    paths = _normalize_wordlist(wordlist)

    endpoints = []
    for path in paths:
        full_url = f"{base_url}{path}"
        entry = {
            "path": path,
            "url": full_url,
            "status": None,
            "content_type": "candidate",
            "size": 0,
            "is_api": _is_api_path(path),
            "category": _category_for_path(path),
            "methods": ["GET"],
        }

        if not probe:
            endpoints.append(entry)
            continue

        try:
            resp = requests.get(
                full_url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Linux; Android 14; CSCAN) AppleWebKit/537.36",
                    "Accept": "application/json, text/html, application/xml, */*",
                },
            )
            entry["status"] = resp.status_code
            entry["content_type"] = (resp.headers.get("Content-Type", "unknown") or "unknown").split(";", 1)[0]
            entry["size"] = len(resp.content or b"")
            entry["is_api"] = entry["is_api"] or _is_candidate_response(resp)
            if resp.status_code == 404 and "not found" in (resp.text or "").lower():
                continue
            if resp.status_code < 500:
                endpoints.append(entry)
        except requests.RequestException:
            entry["status"] = "error"
            endpoints.append(entry)

    result = {
        "target": base_url,
        "timestamp": datetime.now().isoformat(),
        "paths_checked": len(paths),
        "probe_enabled": probe,
        "endpoints": endpoints,
    }
    result["summary"] = {
        "total": len(endpoints),
        "api_like": sum(1 for item in endpoints if item.get("is_api")),
        "status_200_plus": sum(1 for item in endpoints if isinstance(item.get("status"), int) and item["status"] >= 200),
    }
    return result
