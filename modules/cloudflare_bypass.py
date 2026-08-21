#!/usr/bin/env python3
"""
CSCAN — Cloudflare WAF / UAM Bypass Module
Adapted from: https://github.com/0dev1337/AntiCloudflareWAF

Uses the advanced browser engine to solve Cloudflare's
Under-Attack-Mode (UAM) challenge and extract the cf_clearance cookie
+ matching User-Agent so subsequent requests can bypass the WAF.

Requirements (install separately):
    pip install "camoufox[geoip]"
    python -m camoufox fetch
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider,
    G, R, Y, C, M, W, BR, DM, RS
)

# ── Availability check ────────────────────────────────────────────────────────
_CAMOUFOX_AVAILABLE = False
try:
    from camoufox.async_api import AsyncCamoufox
    _CAMOUFOX_AVAILABLE = True
except ImportError:
    pass


# ── Config dataclass (mirrors AntiCloudflareWAF WafSolveRequest schema) ───────
@dataclass
class CloudflareBypassConfig:
    """Configuration for the Cloudflare UAM solver."""
    domain: str
    headless: bool = True
    proxy: Optional[str] = None          # format: http://user:pass@host:port
    disable_coop: bool = True
    locale: list = field(default_factory=lambda: ["en-US"])
    block_webrtc: bool = False
    block_webgl: bool = False
    humanize: bool = True                # camoufox human-like mouse/timing
    geoip: bool = True                   # match geolocation to proxy IP
    os: Optional[str] = None            # 'windows', 'macos', 'linux'
    i_know_what_im_doing: bool = False   # suppress camoufox safety warnings
    timeout_ms: int = 30_000            # page load timeout in milliseconds


# ── Core solver (async) ───────────────────────────────────────────────────────
async def _solve_cloudflare_async(cfg: CloudflareBypassConfig) -> tuple[str, str] | None:
    """
    Launch a camoufox browser, navigate to the target domain, wait for
    Cloudflare's UAM challenge to resolve, and extract the cf_clearance
    cookie and User-Agent string.

    Returns:
        (cf_clearance_value, user_agent) on success
        None on failure
    """
    cf_clearance_cookie = None
    user_agent = None

    camoufox_options: dict = {
        "webgl_config": ("Apple", "Apple M1, or similar"),
        "disable_coop": cfg.disable_coop,
        "locale": cfg.locale,
        "block_webrtc": cfg.block_webrtc,
        "block_webgl": cfg.block_webgl,
        "humanize": cfg.humanize,
        "geoip": cfg.geoip,
        "i_know_what_im_doing": cfg.i_know_what_im_doing,
        "headless": cfg.headless,
    }

    # Optional OS fingerprint override
    if cfg.os:
        camoufox_options["os"] = cfg.os

    # Optional proxy support (format: http://user:pass@host:port)
    if cfg.proxy:
        try:
            # Parse http://user:pass@host:port
            after_proto = cfg.proxy.split("://", 1)[1]          # user:pass@host:port
            credentials, hostport = after_proto.rsplit("@", 1)  # split on last @
            username, password = credentials.split(":", 1)
            camoufox_options["proxy"] = {
                "server": f"http://{hostport}",
                "username": username,
                "password": password,
            }
        except Exception as e:
            warn(f"Could not parse proxy '{cfg.proxy}': {e} — proceeding without proxy.")

    try:
        async with AsyncCamoufox(**camoufox_options) as browser:
            page = await browser.new_page()

            await page.goto(
                cfg.domain,
                wait_until="networkidle",
                timeout=cfg.timeout_ms,
            )

            # Wait up to 30s for cf_clearance cookie to appear
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                cookies = await page.context.cookies()
                for cookie in cookies:
                    if cookie.get("name") == "cf_clearance":
                        cf_clearance_cookie = cookie["value"]
                        break
                if cf_clearance_cookie:
                    break
                await asyncio.sleep(1)

            # Grab the User-Agent that matched the cf_clearance
            user_agent = await page.evaluate("navigator.userAgent")

    except Exception as e:
        alert(f"Browser engine error: {e}")
        return None

    if cf_clearance_cookie:
        return cf_clearance_cookie, user_agent
    return None


# ── Public sync wrapper ───────────────────────────────────────────────────────
def solve_cloudflare_waf(cfg: CloudflareBypassConfig) -> tuple[str, str] | None:
    """
    Synchronous wrapper around _solve_cloudflare_async().
    Returns (cf_clearance, user_agent) or None.
    """
    try:
        # When called from within an already-running event loop (cscan.py uses asyncio.run),
        # we offload to a new thread so asyncio.run() works cleanly.
        try:
            asyncio.get_running_loop()
            # We're inside a running loop — use a thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _solve_cloudflare_async(cfg))
                return future.result(timeout=cfg.timeout_ms / 1000 + 10)
        except RuntimeError:
            # No running loop — safe to use asyncio.run() directly
            return asyncio.run(_solve_cloudflare_async(cfg))
    except Exception as e:
        alert(f"Cloudflare bypass failed: {e}")
        return None


# ── Convenience: inject cf_clearance into a requests.Session ─────────────────
def inject_cf_cookies(
    session,
    domain: str,
    cf_clearance: str,
    user_agent: str,
) -> None:
    """
    Inject a solved cf_clearance cookie and matching User-Agent into an
    existing requests.Session so all subsequent calls bypass Cloudflare.

    Args:
        session:        A requests.Session object (or StealthSession._session)
        domain:         The target domain (e.g. 'https://example.com')
        cf_clearance:   The extracted cf_clearance cookie value
        user_agent:     The User-Agent returned by solve_cloudflare_waf()
    """
    from urllib.parse import urlparse
    hostname = urlparse(domain).hostname or domain

    from requests.cookies import RequestsCookieJar
    jar = session.cookies if hasattr(session, "cookies") else RequestsCookieJar()
    jar.set("cf_clearance", cf_clearance, domain=hostname, path="/")

    if hasattr(session, "headers"):
        session.headers.update({"User-Agent": user_agent})


# ── Interactive menu handler ──────────────────────────────────────────────────
def handle_cf_bypass_menu(session_data: dict) -> dict | None:
    """
    Interactive Cloudflare UAM bypass wizard.

    Args:
        session_data: The cscan SESSION dict (used to read target/stealth config)

    Returns:
        dict with keys 'cf_clearance', 'user_agent', 'domain' on success
        None on failure or unavailability
    """
    section("CLOUDFLARE WAF / UAM BYPASS")

    if not _CAMOUFOX_AVAILABLE:
        alert("Browser engine dependencies are not installed.")
        print(f"""
  {Y}This module requires the advanced browser engine.

  {C}Please install the required dependencies:{RS}
    {W}pip install "camoufox[geoip]"{RS}
    {W}python -m camoufox fetch{RS}
""")
        return None

    target = session_data.get("target")
    if not target:
        target = input(f"  {BR}{W}Enter target domain (e.g. https://example.com): {RS}").strip()
        if not target:
            warn("No target provided.")
            return None

    info(f"Target        : {BR}{C}{target}{RS}")

    # Stealth config
    stealth = session_data.get("stealth", {})
    proxy = stealth.get("proxy") if stealth.get("enabled") else None

    if proxy:
        info(f"Proxy         : {BR}{DM}{proxy}{RS}")
    else:
        info(f"Proxy         : {DM}none (direct){RS}")

    # Headless mode
    headless_raw = input(f"  {BR}{W}Run browser headless? [Y/n]: {RS}").strip().lower()
    headless = headless_raw not in ("n", "no")

    # OS fingerprint
    print(f"\n  {C}OS fingerprint:{RS}")
    print(f"    {G}[1]{RS}  Auto (engine default)")
    print(f"    {G}[2]{RS}  Windows")
    print(f"    {G}[3]{RS}  macOS")
    print(f"    {G}[4]{RS}  Linux\n")
    os_choice = input(f"  {BR}{W}Select [1-4]: {RS}").strip()
    os_map = {"2": "windows", "3": "macos", "4": "linux"}
    os_fp = os_map.get(os_choice)

    cfg = CloudflareBypassConfig(
        domain=target,
        headless=headless,
        proxy=proxy,
        humanize=True,
        geoip=bool(proxy),
        os=os_fp,
        i_know_what_im_doing=True,
    )

    print(f"\n  {BR}{M}[*]{RS}  Launching stealth browser, solving Cloudflare challenge...")
    print(f"  {DM}(This may take up to 30 seconds){RS}\n")

    result = solve_cloudflare_waf(cfg)

    if result is None:
        alert("Failed to obtain cf_clearance cookie. Cloudflare challenge was not solved.")
        info("Tips:")
        info("  • Try running with headless=False so you can see the browser")
        info("  • Add a proxy that matches the target's region (geoip=True)")
        info("  • Run: python -m camoufox fetch  (to update browser fingerprints)")
        return None

    cf_clearance, user_agent = result

    divider()
    ok(f"Cloudflare UAM BYPASSED!")
    print(f"  {DM}cf_clearance :{RS} {G}{cf_clearance[:40]}…{RS}")
    print(f"  {DM}User-Agent   :{RS} {DM}{user_agent[:60]}…{RS}")
    divider()

    return {
        "cf_clearance": cf_clearance,
        "user_agent": user_agent,
        "domain": target,
    }
