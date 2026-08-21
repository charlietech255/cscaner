#!/usr/bin/env python3
"""
CSCAN — AI Analysis Module (Powered by Google Gemini)
Sends scan findings to Gemini API via plain HTTP requests
and returns a structured security overview with actionable advice.
"""

import json
import sys
import time
import textwrap

import requests

from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider, pause,
    prompt_yes, BR, DM, RS, G, R, Y, C, M, W, B
)

# ── Gemini API config ─────────────────────────────────────────────────────────
GEMINI_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro"
]
TIMEOUT       = 60  # Gemini can be slow on large payloads


# ─────────────────────────────────────────────────────────────────────────────
#  API KEY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

def get_available_models(api_key: str) -> list:
    """Fetch available models from Gemini API that support generateContent."""
    try:
        resp = requests.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            params={"key": api_key},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            models = []
            for m in data.get("models", []):
                name = m.get("name", "").replace("models/", "")
                methods = m.get("supportedGenerationMethods", [])
                if "generateContent" in methods and "gemini" in name:
                    models.append(name)
            
            # Sort to prefer flash and newer versions
            def score(n):
                s = 0
                if '2.5' in n: s += 40
                elif '2.0' in n: s += 30
                elif '1.5' in n: s += 20
                if 'flash' in n: s += 5
                elif 'pro' in n: s += 4
                return s
                
            models.sort(key=score, reverse=True)
            return models
    except Exception:
        pass
    return None


def prompt_api_key() -> str:
    """
    Interactively prompt for a Gemini API key and do a quick validation call.
    Returns the key on success, None on failure.
    """
    section("GEMINI AI ANALYSIS — API KEY SETUP")
    info(f"Get a free key at: {BR}{C}https://aistudio.google.com/app/apikey{RS}")
    info("Your key is only stored in memory for this session.\n")

    key = input(f"  {BR}{M}[>]{RS} {BR}{W}Enter your Gemini API key: {RS}").strip()
    if not key:
        warn("No key entered.")
        return None

    info("Validating API key and fetching available models…")
    
    global GEMINI_MODELS
    available = get_available_models(key)
    if available:
        GEMINI_MODELS = available
        ok(f"Found {len(available)} supported model(s). Prioritizing: {available[0]}")
    else:
        warn("Could not fetch model list, using defaults.")

    # Quick test call with minimal tokens
    try:
        resp = _call_gemini(key, "Reply with exactly: OK", max_tokens=5)
        if resp:
            ok("API key is valid and working!")
            return key
        else:
            alert("Key validation failed — check your key and try again.")
            return None
    except Exception as e:
        alert(f"Connection error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  GEMINI HTTP CALLER
# ─────────────────────────────────────────────────────────────────────────────

def _call_gemini(api_key: str, prompt: str, max_tokens: int = 2048) -> str | None:
    """
    Send a prompt to Gemini via plain requests.post() with automatic fallback
    to alternative models if the primary model is not supported or returns errors.
    """
    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}],
                "role": "user"
            }
        ],
        "generationConfig": {
            "maxOutputTokens":  max_tokens,
            "temperature":      0.1,
            "topP":             0.9,
        },
        "safetySettings": [
            {"category": c, "threshold": "BLOCK_NONE"}
            for c in [
                "HARM_CATEGORY_HARASSMENT",
                "HARM_CATEGORY_HATE_SPEECH",
                "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "HARM_CATEGORY_DANGEROUS_CONTENT",
            ]
        ]
    }

    last_error = None
    for model in GEMINI_MODELS:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        try:
            resp = requests.post(
                url,
                params={"key": api_key},
                json=payload,
                timeout=TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            
            # If the specific model is not found, unauthorized or restricted on free tier,
            # we try the next model.
            if resp.status_code in (400, 403, 404, 429):
                try:
                    err_msg = resp.json().get("error", {}).get("message", "API Error")
                except Exception:
                    err_msg = f"HTTP {resp.status_code}"
                
                last_error = f"{model}: {err_msg}"
                continue
                
            resp.raise_for_status()
            data = resp.json()

            # Extract text
            candidates = data.get("candidates", [])
            if not candidates:
                err = data.get("error", {})
                last_error = f"No candidates returned: {err.get('message', 'Unknown error')}"
                continue

            parts = candidates[0].get("content", {}).get("parts", [])
            result_text = "".join(p.get("text", "") for p in parts).strip()
            
            # Successful response!
            return result_text

        except requests.exceptions.HTTPError as e:
            try:
                err_body = e.response.json().get("error", {})
                last_error = f"API error on {model} [{e.response.status_code}]: {err_body.get('message', str(e))}"
            except Exception:
                last_error = f"HTTP error on {model}: {e}"
            continue
        except requests.exceptions.Timeout:
            last_error = f"Request to {model} timed out."
            continue
        except requests.exceptions.ConnectionError:
            last_error = f"Connection error trying {model}."
            continue
        except Exception as e:
            last_error = f"Unexpected error on {model}: {e}"
            continue

    # If we made it here, all models in the fallback loop failed
    alert(f"All Gemini models failed. Last error encountered:\n  {R}{last_error}{RS}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  PROMPT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _format_port_evidence(ports) -> list[str]:
    """Format scanner port results across tuple and dictionary result shapes."""
    formatted = []
    for item in ports or []:
        if isinstance(item, dict):
            port = item.get('port', 'unknown')
            state = item.get('state', 'open')
            banner = item.get('banner') or item.get('service') or 'no banner'
            formatted.append(f"{port}/tcp state={state} banner={str(banner)[:40]}")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            banner = item[1] or 'no banner'
            formatted.append(f"{item[0]}/tcp banner={str(banner)[:40]}")
    return formatted

def _ground_truth_summary(results: dict) -> str:
    """Convert raw scan output into a strict evidence-only summary.

    This prevents the model from inventing findings beyond the facts we observed.
    """
    if not results:
        return "GROUND TRUTH ONLY (do not invent anything):\nNo verified findings were collected. No vulnerability claims should be made based on missing data."

    lines = [
        "GROUND TRUTH ONLY (do not invent anything):",
        "Only report findings that are explicitly supported by the evidence below.",
        "If a result is missing, say so instead of guessing.",
        "Do not claim a CVE, exploit, or vulnerability unless the raw scan evidence directly supports it.",
        "",
    ]

    dns = results.get('dns', {})
    if dns:
        lines.append(f"DNS: ipv4={dns.get('ipv4', [])}, mx={dns.get('mx', [])}, ns={dns.get('ns', [])}")
    else:
        lines.append("DNS: no evidence collected")

    ports = results.get('ports_common', results.get('ports_full', []))
    if ports:
        port_entries = []
        for item in ports:
            if isinstance(item, dict):
                port = item.get('port', 'unknown')
                state = item.get('state', 'unknown')
                banner = item.get('banner') or item.get('service') or 'no banner'
                port_entries.append(f"{port}/tcp state={state} banner={banner}")
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                port = item[0]
                banner = item[1] if item[1] else 'no banner'
                port_entries.append(f"{port}/tcp banner={banner}")
        lines.append("OPEN PORTS: " + "; ".join(port_entries))
    else:
        lines.append("OPEN PORTS: no verified open ports")

    ssh = results.get('ssh', {})
    if ssh:
        if ssh.get('vulnerable'):
            credential = ssh.get('credential') or ('unknown', '')
            username = credential[0] if isinstance(credential, (list, tuple)) else 'unknown'
            lines.append(f"SSH AUDIT: accepted credentials observed for {username}; password redacted; banner={ssh.get('banner', 'unknown')}")
        elif ssh.get('open'):
            lines.append(f"SSH AUDIT: port open; no weak credentials observed; banner={ssh.get('banner', 'unknown')}")
        else:
            lines.append("SSH AUDIT: no verified SSH exposure in collected evidence")
    else:
        lines.append("SSH AUDIT: no evidence collected")

    ftp = results.get('ftp', {})
    if ftp:
        if ftp.get('anonymous'):
            lines.append(f"FTP AUDIT: anonymous login succeeded; listing={ftp.get('listing', [])}")
        elif ftp.get('open'):
            lines.append("FTP AUDIT: FTP service open but anonymous login not observed")
        else:
            lines.append("FTP AUDIT: no verified FTP exposure in collected evidence")
    else:
        lines.append("FTP AUDIT: no evidence collected")

    ssl = results.get('ssl', {})
    if ssl:
        subject = ssl.get('subject', ssl.get('Subject', {}))
        issuer = ssl.get('issuer', ssl.get('Issuer', {}))
        lines.append(
            "SSL/TLS: "
            f"CN={subject.get('commonName', subject.get('common_name', 'unknown'))}, "
            f"issuer={issuer.get('organizationName', issuer.get('organization_name', 'unknown'))}, "
            f"not_after={ssl.get('Not After', ssl.get('not_after', 'unknown'))}, "
            f"protocol={ssl.get('Protocol', ssl.get('protocol', 'unknown'))}"
        )
    else:
        lines.append("SSL/TLS: no evidence collected")

    web = results.get('web_vuln', {})
    if web:
        exposed = web.get('exposed', [])
        forb = web.get('forbidden', [])
        if exposed:
            entries = [f"{path} status={status} bytes={size}" for path, size, status in exposed]
            lines.append("WEB EXPOSED PATHS: " + "; ".join(entries))
        else:
            lines.append("WEB EXPOSED PATHS: none observed")
        if forb:
            lines.append("FORBIDDEN PATHS: " + "; ".join(f"{path}" for path, _, _ in forb[:5]))
    else:
        lines.append("WEB EXPOSED PATHS: no evidence collected")

    hdr = results.get('headers', {})
    if hdr:
        lines.append(f"HTTP HEADERS: score={hdr.get('score', 0)} missing={hdr.get('missing', [])} leaks={hdr.get('leaks', [])}")
    else:
        lines.append("HTTP HEADERS: no evidence collected")

    cms = results.get('cms', [])
    if cms:
        lines.append(f"CMS/TECH: {cms}")
    else:
        lines.append("CMS/TECH: no evidence collected")

    dirs = results.get('dir_brute', [])
    if dirs:
        lines.append("ACCESSIBLE PATHS: " + "; ".join(f"{path}" for path, _ in dirs[:10]))
    else:
        lines.append("ACCESSIBLE PATHS: no evidence collected")

    subs = results.get('subdomains', [])
    if subs:
        lines.append("SUBDOMAINS: " + "; ".join(f"{host}" for host, _ in subs[:10]))
    else:
        lines.append("SUBDOMAINS: no evidence collected")

    lines.append("")
    lines.append("ONLY VERIFIED FINDINGS SHOULD BE DISCUSSED. Missing evidence must not be turned into a vulnerability claim.")
    return "\n".join(lines)


def _build_findings_prompt(target: str, results: dict) -> str:
    """Convert SESSION results into a detailed security audit prompt."""
    ground_truth = _ground_truth_summary(results)

    lines = [
        "You are a senior cybersecurity analyst. You are allowed to explain the scan results only using the evidence below.",
        "Do not invent vulnerabilities, CVEs, exploitability, or impact not explicitly supported by the ground-truth summary.",
        "If data is missing or ambiguous, state that clearly instead of guessing.",
        "If no verified issues are present, say so plainly.",
        "",
        "1. EXECUTIVE SUMMARY (2-3 sentences, non-technical overview)",
        "2. VERIFIED FINDINGS (bullet list of only the issues directly supported by the evidence)",
        "3. RISK ASSESSMENT (rate overall risk: CRITICAL / HIGH / MEDIUM / LOW with justification based only on evidence)",
        "4. DETAILED ANALYSIS (explain what each finding means and why it matters)",
        "5. PRIORITIZED REMEDIATION STEPS (numbered, most urgent first)",
        "6. SECURITY HARDENING CHECKLIST (quick-win fixes the admin can apply today)",
        "7. CONCLUSION",
        "",
        "STRICT CONSTRAINTS:",
        "- Base your report STRICTLY on the provided evidence and do not add speculative claims.",
        "- If the findings do not explicitly state a vulnerability exists, do not write about one.",
        "- Do not assume a port is vulnerable just because it is open.",
        "- If CVEs are reported based on version numbers, mention that they might be false positives due to backported patches.",
        "- If no verified vulnerabilities were found, clearly state that none were detected from the evidence.",
        "- Do not use unsupported phrases like 'exploitable by default' or 'likely compromised' without evidence.",
        f"TARGET: {target}",
        "",
        "=== GROUND TRUTH EVIDENCE ===",
        ground_truth,
        "=== END OF GROUND TRUTH EVIDENCE ===",
    ]

    # DNS findings
    dns = results.get('dns', {})
    if dns:
        lines.append(f"DNS: IPv4={dns.get('ipv4', [])}, MX={dns.get('mx', [])}, NS={dns.get('ns', [])}")

    # Open ports
    ports = results.get('ports_common', results.get('ports_full', []))
    if ports:
        lines.append(f"OPEN PORTS: {', '.join(_format_port_evidence(ports))}")
    else:
        lines.append("OPEN PORTS: None detected on common ports.")

    # SSH
    ssh = results.get('ssh', {})
    if ssh:
        if ssh.get('vulnerable'):
            credential = ssh.get('credential') or ('unknown', '')
            username = credential[0] if isinstance(credential, (list, tuple)) else 'unknown'
            lines.append(f"SSH AUDIT: VULNERABLE — Accepted credentials for {username}; password redacted | Banner: {ssh.get('banner','')}")
        elif ssh.get('open'):
            lines.append(f"SSH AUDIT: Port open, no weak credentials found | Banner: {ssh.get('banner','')}")
        else:
            lines.append("SSH AUDIT: Port not open or unreachable.")

    # FTP
    ftp = results.get('ftp', {})
    if ftp:
        if ftp.get('anonymous'):
            lines.append(f"FTP AUDIT: Anonymous login SUCCEEDED — {len(ftp.get('listing', []))} files listed.")
        elif ftp.get('open'):
            lines.append("FTP AUDIT: Port open, anonymous login rejected.")
        else:
            lines.append("FTP AUDIT: Port not open.")

    # SSL
    ssl = results.get('ssl', {})
    if ssl:
        subj = ssl.get('Subject', {})
        issuer = ssl.get('Issuer', {})
        lines.append(
            f"SSL/TLS: CN={subj.get('commonName','?')}, "
            f"Issuer={issuer.get('organizationName','?')}, "
            f"ValidUntil={ssl.get('Not After','?')}, "
            f"Protocol={ssl.get('Protocol','?')}"
        )

    # Web vulns
    web = results.get('web_vuln', {})
    if web:
        exposed  = web.get('exposed', [])
        forb     = web.get('forbidden', [])
        if exposed:
            paths = [f"{p} ({s} bytes)" for p, s, _ in exposed]
            lines.append(f"WEB EXPOSED PATHS: {', '.join(paths)}")
        else:
            lines.append("WEB EXPOSED PATHS: None found.")
        if forb:
            lines.append(f"FORBIDDEN PATHS (403): {', '.join(p for p, _, _ in forb[:5])}")

    # HTTP headers
    hdr = results.get('headers', {})
    if hdr:
        missing = hdr.get('missing', [])
        leaks   = hdr.get('leaks', [])
        score   = hdr.get('score', 0)
        lines.append(f"HTTP SECURITY HEADERS: Score={score:.0f}%, Missing={missing}, Leaking={[h for h,_ in leaks]}")

    # CMS
    cms = results.get('cms', [])
    if cms:
        lines.append(f"CMS/TECH DETECTED: {', '.join(cms)}")

    # Dir brute
    dirs = results.get('dir_brute', [])
    if dirs:
        lines.append(f"ACCESSIBLE PATHS: {', '.join(p for p, c in dirs[:10])}")

    # Subdomains
    subs = results.get('subdomains', [])
    if subs:
        lines.append(f"SUBDOMAINS: {', '.join(h for h, _ in subs[:10])}")

    lines.append("\n=== END OF FINDINGS ===")
    lines.append(
        "\nPlease focus on actionable, specific advice. "
        "Format clearly using headers and bullet points. "
        "Avoid generic advice — reference the specific findings above."
    )
    return "\n".join(lines)


def _build_quick_prompt(target: str) -> str:
    return (
        f"You are a cybersecurity expert. The user wants a quick security overview for: {target}\n"
        "Without any scan data, provide:\n"
        "1. COMMON ATTACK VECTORS for this type of target\n"
        "2. TOP 5 SECURITY CHECKS they should perform\n"
        "3. QUICK HARDENING CHECKLIST for web servers\n"
        "4. TOOLS RECOMMENDED for local testing\n"
        "Keep it practical and actionable. Use bullet points and clear headers."
    )


def _build_cve_prompt(service: str, version: str) -> str:
    return (
        f"You are a cybersecurity vulnerability researcher.\n"
        f"Service: {service}\nVersion: {version}\n\n"
        "Please provide:\n"
        "1. KNOWN CVEs for this service/version (list by CVE ID if known)\n"
        "2. SEVERITY RATING (CRITICAL/HIGH/MEDIUM/LOW)\n"
        "3. EXPLOIT LIKELIHOOD\n"
        "4. RECOMMENDED PATCH/MITIGATION\n"
        "Be specific. If no known CVEs, say so clearly."
    )


# ─────────────────────────────────────────────────────────────────────────────
#  RESPONSE RENDERER
# ─────────────────────────────────────────────────────────────────────────────

def _render_ai_response(text: str):
    """Pretty-print Gemini's markdown-ish response with colors."""
    print()
    lines = text.split('\n')
    for line in lines:
        stripped = line.strip()

        # Section headers (##, ###, numbered heading, ALL CAPS word)
        if stripped.startswith('##') or stripped.startswith('###'):
            title = stripped.lstrip('#').strip()
            print(f"\n  {BR}{M}{'═' * 3} {title} {'═' * max(0, 55 - len(title))}{RS}")

        elif stripped and stripped[0].isdigit() and '. ' in stripped[:4]:
            print(f"\n  {BR}{Y}{stripped}{RS}")

        elif stripped.startswith(('CRITICAL', 'HIGH RISK', 'MEDIUM RISK')):
            print(f"  {BR}{R}{stripped}{RS}")

        elif stripped.startswith(('LOW RISK', 'PASS')):
            print(f"  {BR}{G}{stripped}{RS}")

        elif stripped.startswith(('*', '-', '•')):
            content = stripped.lstrip('*-• ').strip()
            # Colour bullet content based on keywords
            if any(k in content.lower() for k in ['critical', 'vulnerable', 'exposed', 'weak', 'risk', 'attack']):
                print(f"  {R}  ◆ {content}{RS}")
            elif any(k in content.lower() for k in ['recommend', 'fix', 'patch', 'update', 'use', 'enable', 'disable']):
                print(f"  {G}  ◆ {content}{RS}")
            else:
                print(f"  {C}  ◆ {content}{RS}")

        elif stripped.startswith('**') and stripped.endswith('**'):
            print(f"\n  {BR}{W}{stripped.strip('*')}{RS}")

        elif stripped == '':
            print()

        else:
            # Wrap long lines at 72 chars
            wrapped = textwrap.fill(stripped, width=70, initial_indent='     ', subsequent_indent='     ')
            print(f"{W}{wrapped}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def analyze_findings(api_key: str, target: str, results: dict) -> str:
    """Full AI security analysis of all scan findings."""
    section("AI SECURITY ANALYSIS — FULL FINDINGS REVIEW")

    if not results:
        warn("No scan results found in session. Run some scans first!")
        info("Tip: Run tools 1–16 then come back for AI analysis.")
        return ''

    info(f"Target        : {BR}{W}{target}{RS}")
    info(f"Result sets   : {BR}{W}{len(results)}{RS} module(s) collected")
    info(f"Model         : {BR}{C}gemini-2.5-flash (with auto-fallback){RS}")
    print()

    prompt = _build_findings_prompt(target, results)
    _show_thinking()

    response = _call_gemini(api_key, prompt, max_tokens=3000)
    _stop_thinking()
    if response:
        _render_ai_response(response)
        ok("\nAI analysis complete.")
        return response
    return ''


def quick_host_analysis(api_key: str, target: str) -> str:
    """Quick AI overview of a target without any scan data."""
    section("AI QUICK HOST ANALYSIS")
    info(f"Target        : {BR}{W}{target}{RS}")
    info(f"Mode          : General security overview (no scan data needed)")
    print()
    _show_thinking()

    response = _call_gemini(api_key, _build_quick_prompt(target), max_tokens=1500)
    _stop_thinking()
    if response:
        _render_ai_response(response)
        return response
    return ''


def cve_lookup(api_key: str) -> str:
    """Ask Gemini about CVEs for a specific service/version."""
    section("AI CVE & VULNERABILITY LOOKUP")
    service = input(f"  {BR}{W}Service name (e.g. OpenSSH, Apache, nginx): {RS}").strip()
    version = input(f"  {BR}{W}Version (e.g. 7.9, 2.4.51):                {RS}").strip()
    if not service:
        warn("No service entered.")
        return ''

    info(f"Querying Gemini for known vulnerabilities in {service} {version}…\n")
    _show_thinking()

    response = _call_gemini(api_key, _build_cve_prompt(service, version), max_tokens=1200)
    _stop_thinking()
    if response:
        _render_ai_response(response)
        return response
    return ''


def ask_ai(api_key: str) -> str:
    """Free-form question to Gemini about cybersecurity."""
    section("AI FREE-FORM SECURITY ASSISTANT")
    info("Ask anything about cybersecurity, configurations, CVEs, tools, etc.")
    print()
    question = input(f"  {BR}{M}[?]{RS} {BR}{W}Your question: {RS}").strip()
    if not question:
        warn("No question entered.")
        return ''

    prompt = (
        "You are a professional cybersecurity consultant.\n"
        f"Question: {question}\n\n"
        "Give a clear, accurate, and practical answer. "
        "Use bullet points and examples where helpful."
    )
    print()
    _show_thinking()
    response = _call_gemini(api_key, prompt, max_tokens=1500)
    _stop_thinking()
    if response:
        _render_ai_response(response)
        return response
    return ''


def generate_formal_report(api_key: str, target: str, results: dict) -> str:
    """Generate a formal security report text and save to file."""
    section("AI FORMAL SECURITY REPORT GENERATOR")

    if not results:
        warn("No scan results to report on. Run scans first.")
        return ''

    info(f"Generating formal report for: {BR}{W}{target}{RS}")
    print()

    prompt = (
        "You are writing a formal penetration testing report for a system administrator.\n"
        "Target: " + target + "\n\n"
        "Based on these findings:\n"
        + _build_findings_prompt(target, results) +
        "\n\nWrite a FORMAL security report with:\n"
        "- Report title and date\n"
        "- Scope and methodology\n"
        "- Executive Summary\n"
        "- Findings table (Severity | Issue | Location | Recommendation)\n"
        "- Detailed technical findings\n"
        "- Risk matrix\n"
        "- Remediation roadmap with estimated effort\n"
        "- Conclusion\n"
        "Format professionally. Use clear section headers."
    )

    _show_thinking()
    response = _call_gemini(api_key, prompt, max_tokens=4096)
    _stop_thinking()
    if response:
        _render_ai_response(response)

        # Save to file
        from datetime import datetime
        ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"cscan_ai_report_{ts}.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"CSCAN AI Security Report\nGenerated: {datetime.now()}\nTarget: {target}\n\n")
                f.write(response)
            ok(f"Report saved to: {BR}{G}{filename}{RS}")
        except Exception as e:
            warn(f"Could not save report: {e}")

        return response
    return ''


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _show_thinking():
    """Animated 'thinking' spinner while waiting for AI (blocking)."""
    import threading
    chars = ['-', '\\', '|', '/', '-', '\\', '|', '/', '-', '/']
    msgs  = [
        "Gemini is analysing findings   ",
        "Cross-referencing vuln database",
        "Generating recommendations     ",
        "Building remediation roadmap   ",
    ]
    stop  = threading.Event()

    def _spin():
        i = 0
        while not stop.is_set():
            msg = msgs[(i // 15) % len(msgs)]
            sys.stdout.write(f"\r  {BR}{M}{chars[i%len(chars)]}{RS}  {C}{msg}{RS}  ")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write('\r' + ' ' * 72 + '\r')
        sys.stdout.flush()

    thr = threading.Thread(target=_spin, daemon=True)
    thr.start()
    # Store stop event globally for cleanup (though daemon=True handles thread exit)
    _show_thinking._stop = stop
    # Small sleep to let the first frame render
    time.sleep(0.2)

def _stop_thinking():
    """Stop the thinking spinner."""
    if hasattr(_show_thinking, '_stop'):
        _show_thinking._stop.set()
        time.sleep(0.1) # Allow thread time to clear line
