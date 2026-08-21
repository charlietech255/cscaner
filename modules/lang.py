#!/usr/bin/env python3
"""
CSCAN — Language module
=======================================
Supports: English (en) | Kiswahili (sw)

"""

import os
import json

# ── Config file path (in user's home dir) ─────────────────────────────────────
_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".cscan_config.json")

# ── language active english ────────────────────────────────────────────
_LANG = "en"   # default


# ─────────────────────────────────────────────────────────────────────────────
#  TRANSLATIONS DICTIONARY
# ─────────────────────────────────────────────────────────────────────────────
_STRINGS = {

    # ── Language picker ────────────────────────────────────────────────────────
    "lang_select_title":   {"en": "LANGUAGE SELECTION",
                            "sw": "CHAGUA LUGHA"},
    "lang_select_prompt":  {"en": "Choose your preferred language / Chagua lugha:",
                            "sw": "Chagua lugha/ Choose your preferred language:"},
    "lang_opt_en":         {"en": "[1] English",
                            "sw": "[1] Kiingereza (English)"},
    "lang_opt_sw":         {"en": "[2] Kiswahili",
                            "sw": "[2] Kiswahili"},
    "lang_saved":          {"en": "Language saved.",
                            "sw": "Lugha imechaguliwa."},
    "lang_invalid":        {"en": "Invalid choice — using English.",
                            "sw": "Chaguo bovu — inatumia Kiingereza."},

    # ── Disclaimer ─────────────────────────────────────────────────────────────
    "disclaimer_title":    {"en": "LEGAL DISCLAIMER & ETHICAL USE NOTICE",
                            "sw": "ONYO LA KISHERIA & KAMA UNA RUHUSA TU"},
    "disclaimer_line1":    {"en": "CSCAN is designed for use on systems you OWN or",
                            "sw": "CSCAN imetengenezwa kutumika kwenye mfumo unao miliki tu au"},
    "disclaimer_line2":    {"en": "have EXPLICIT written permission to test.",
                            "sw": "una RUHUSA ya maandishi ya kujaribu sever hiyo."},
    "disclaimer_line3":    {"en": "Unauthorized scanning of systems is ILLEGAL and",
                            "sw": "Matumizi ya mifumo kuleta madhara ni HARAMU na"},
    "disclaimer_line4":    {"en": "may result in criminal prosecution.",
                            "sw": "sisi hatuto husika kwenye hilo."},
    "disclaimer_line5":    {"en": "By continuing, you confirm you have legal",
                            "sw": "Kwa kuendelea, unakubaliana na vigezo na masharti"},
    "disclaimer_line6":    {"en": "authorization to test the target system.",
                            "sw": "ya kujaribu targeted system."},
    "disclaimer_confirm":  {"en": "I confirm I have authorization to test my target",
                            "sw": "Nathibitisha nina ruhusa ya kujaribu target yangu"},
    "exit_not_ready":      {"en": "Exiting CSCAN. Try again when ready.",
                            "sw": "unatoka CSCAN. Jaribu tena ukiwa na uhitaji."},

    # ── Main menu labels ───────────────────────────────────────────────────────
    "menu_title":          {"en": "MAIN MENU",
                            "sw": "MENYU KUU"},
    "menu_recon":          {"en": "RECONNAISSANCE",
                            "sw": "RECONNAISSANCE"},
    "menu_network":        {"en": "NETWORK SCANNING",
                            "sw": "NETWORK SCANNING"},
    "menu_web":            {"en": "WEB ANALYSIS",
                            "sw": "WEB ANALYSIS"},
    "menu_exploit":        {"en": "EXPLOITATION",
                            "sw": "EXPLOITATION"},
    "menu_auto":           {"en": "AUTOMATION",
                            "sw": "AUTOMATION"},
    "menu_ai":             {"en": "AI ANALYSIS -- Powered by AI",
                            "sw": "AI ANALYSIS -- Inayotumia AI"},
    "menu_exit":           {"en": "Exit CSCAN",
                            "sw": "Toka CSCAN"},

    # ── Menu item descriptions ─────────────────────────────────────────────────
    "m1":   {"en": "DNS Lookup & IP Resolver",            "sw": "DNS Lookup & IP Resolver"},
    "m2":   {"en": "WHOIS Domain Intelligence",           "sw": "WHOIS Domain Intelligence"},
    "m3":   {"en": "Subdomain Enumerator",                "sw": "Orodha ya Subdomain"},
    "m4":   {"en": "GeoIP & Location Tracker",            "sw": "GeoIP & Location Tracker"},
    "m5":   {"en": "Reverse DNS Lookup",                  "sw": "Reverse DNS Lookup"},
    "m6":   {"en": "Port Scanner (Common Ports)",         "sw": "Port Scanner "},
    "m7":   {"en": "Port Scanner (Full Range 1–65535)",   "sw": "Port Scanner (Msururu Wote 1–65535)"},
    "m8":   {"en": "Service Banner Grabber",              "sw": "Service Banner Grabber"},
    "m9":   {"en": "SSL/TLS Certificate Inspector",       "sw": "Ukaguzi wa Cheti cha SSL/TLS"},
    "m10":  {"en": "Web Vulnerability Scanner",           "sw": "Skana ya Udhaifu wa Website"},
    "m11":  {"en": "HTTP Security Header Audit",          "sw": "Ukaguzi wa HTTP Security Header"},
    "m12":  {"en": "Directory & File Brute Forcer",       "sw": "Directory & File Brute Forcer"},
    "m13":  {"en": "CMS & Technology Fingerprinter",      "sw": "Kutambua CMS & Teknolojia"},
    "m14":  {"en": "SSH Credential Audit",                "sw": "SSH Credential Audit"},
    "m15":  {"en": "FTP Anonymous Login Check",           "sw": "FTP Anonymous Login Check"},
    "m16":  {"en": "HTTP Basic Auth Tester",              "sw": "HTTP Basic Auth Tester"},
    "m17":  {"en": "Full Auto-Scan Pipeline",             "sw": "Skani mfumo wote"},
    "m18":  {"en": "Export Last Results to File",         "sw": "Hamisha Matokeo ya Mwisho kwenye Faili"},
    "m19":  {"en": "Analyse Findings with AI",         "sw": "Chambua Matokeo kwa AI"},
    "m20":  {"en": "Quick AI Host Overview",           "sw": "Quick AI Host Overview"},
    "m21":  {"en": "CVE & Vulnerability Lookup",       "sw": "CVE & Vulnerability Lookup"},
    "m22":  {"en": "Ask AI Security Assistant",        "sw": "Chat na Ai kuhusu mamb ya cyber security"},
    "m23":  {"en": "Generate Formal Security Report",  "sw": "Tengeneza Ripoti ya Usalama"},

    # ── Prompts & questions ────────────────────────────────────────────────────
    "prompt_target":       {"en": "Enter target  (URL / IP / domain)",
                            "sw": "Ingiza target  (URL / IP / domain)"},
    "prompt_select":       {"en": "Select option  [0–34 | T=target | K=AI key | S=stealth]",
                            "sw": "Chagua chaguo  [0–34 | T=target | K= Key ya AI | S=Stealth]"},
    "q_set_target_now":    {"en": "Set a target now?",
                            "sw": "Weka target sasa?"},
    "q_use_ssl":           {"en": "Use HTTPS/SSL?",
                            "sw": "Tumia HTTPS/SSL?"},
    "q_proceed":           {"en": "Proceed with full scan?",
                            "sw": "Endelea kufanya full scan?"},
    "q_custom_wordlist":   {"en": "Use custom wordlist? (default: built-in 50 subs)",
                            "sw": "Tumia orodha ya maneno maalum? (chaguo-msingi: 50 ndani)"},
    "wordlist_path":       {"en": "Wordlist path",
                            "sw": "Njia ya faili la maneno"},
    "wordlist_loaded":     {"en": "Loaded {n} words from file.",
                            "sw": "Faili limepakia maneno {n}."},
    "wordlist_err":        {"en": "Could not load file: {e}. Using default.",
                            "sw": "Imeshindwa kupakia faili: {e}. Inatumia chaguo-msingi."},

    # ── Stealth section ────────────────────────────────────────────────────────
    "stealth_title":       {"en": "STEALTH MODE CONFIGURATION",
                            "sw": "MIPANGILIO YA STEALTH"},
    "stealth_enabled":     {"en": "Stealth mode ENABLED",
                            "sw": "Stealth imewashwa"},
    "stealth_disabled":    {"en": "Stealth mode DISABLED",
                            "sw": "Stealth imezimwa"},
    "stealth_proxy_prompt":{"en": "Proxy (http/socks4/socks5://host:port) [none]",
                            "sw": "Proxy [none]"},
    "stealth_jitter_min":  {"en": "Min jitter (seconds) [0.5]",
                            "sw": "Jitter chini (sekunde) [0.5]"},
    "stealth_jitter_max":  {"en": "Max jitter (seconds) [2.0]",
                            "sw": "Jitter juu (sekunde) [2.0]"},
    "stealth_timing_prompt":{"en": "Timing (paranoid/sneaky/polite/normal/aggressive/insane) [normal]",
                             "sw": "Timing profile [normal]"},
    "stealth_mutate_prompt":{"en": "Mutate paths to evade WAF?",
                             "sw": "Badilisha njia kuepuka WAF?"},
    "stealth_ua_prompt":   {"en": "Rotate realistic User-Agents?",
                             "sw": "Badilisha User-Agents?"},
    "stealth_nmap_prompt": {"en": "Try nmap for port scans when available?",
                             "sw": "Jaribu nmap kwa port scans?"},
    "status_stealth_on":   {"en": "STEALTH ON",
                             "sw": "STEALTH IMEWASHWA"},
    "stealth_current":     {"en": "Current stealth config:",
                             "sw": "Mipangilio ya stealth:"},

    # ── Status / info messages ─────────────────────────────────────────────────
    "no_target":           {"en": "No target provided.",
                            "sw": "Hakuna target iliyo wekwa."},
    "target_set":          {"en": "Target set to:",
                            "sw": "Target imewekwa:"},
    "ssl_enabled":         {"en": "SSL enabled.",
                            "sw": "SSL imewezeshwa."},
    "resolved_ip":         {"en": "Resolved IP   :",
                            "sw": "IP Iliyopatikana:"},
    "no_resolve_warn":     {"en": "Could not pre-resolve IP (not critical).",
                            "sw": "Imeshindwa kutafsiri IP mapema (si muhimu sana)."},
    "no_results_yet":      {"en": "No results to export yet. Run some scans first.",
                            "sw": "Hakuna matokeo ya kuhamisha bado. Endesha skana kwanza."},
    "export_ok":           {"en": "Results exported to:",
                            "sw": "Matokeo yamehamishwa kwenye:"},
    "export_fail":         {"en": "Export failed:",
                            "sw": "Uhamishaji umeshindwa:"},
    "no_scan_results":     {"en": "No scan results yet. Run tools from sections 1–16 first, then come back.",
                            "sw": "Hakuna matokeo ya skana bado. run tool tokea 1–16."},
    "unknown_option":      {"en": "Unknown option: '{c}'. Enter a number from the menu.",
                            "sw": "Chaguo lisilojulikana: '{c}'. Ingiza nambari kutoka kwenye menyu."},
    "interrupted":         {"en": "Interrupted by user.",
                            "sw": "Imezuiwa na mmiliki wa sever."},
    "goodbye":             {"en": "CSCAN terminated. Stay ethical.",
                            "sw": "CSCAN imezuiwa. huwezi endelea."},

    # ── Session status bar ─────────────────────────────────────────────────────
    "status_not_set":      {"en": "not set",       "sw": "haijawekwa"},
    "status_unknown":      {"en": "unknown",        "sw": "haijulikani"},
    "status_ai_on":        {"en": "AI ON",       "sw": "AI IMEWASHWA"},
    "status_ai_off":       {"en": "AI OFF",      "sw": "AI IMEZIMWA"},

    # ── Full auto scan ─────────────────────────────────────────────────────────
    "auto_title":          {"en": "FULL AUTO-SCAN PIPELINE",
                            "sw": "MCHAKATO KAMILI WA SKANA AUTOMATION"},
    "auto_warn":           {"en": "This will run the full recon + scan + exploit pipeline.",
                            "sw": "Hii itaendesha mchakato wote wa upelelezi + skana + unyonyaji."},
    "auto_time_est":       {"en": "Estimated time: 2–10 minutes depending on target.",
                            "sw": "Muda uliokadiriwa: dakika 2–10 kulingana na target."},
    "auto_starting":       {"en": "Starting full pipeline on:",
                            "sw": "Inaanza mchakato wote kwenye:"},
    "auto_step_fail":      {"en": "Step failed:",             "sw": "Hatua imeshindwa:"},
    "auto_summary_title":  {"en": "AUTO-SCAN SUMMARY",        "sw": "MUHTASARI WA SKANA AUTOMATION"},
    "auto_completed":      {"en": "Completed in {s}s",        "sw": "Imekamilika kwa sekunde {s}"},
    "auto_ip_addrs":       {"en": "IP Addresses   :",         "sw": "Anwani za IP   :"},
    "auto_open_ports":     {"en": "Open Ports     :",         "sw": "Ports Wazi   :"},
    "auto_no_ports":       {"en": "None on common ports",     "sw": "Hakuna katika POrt common"},
    "auto_ssl_found":      {"en": "SSL/TLS        : Certificate found",
                            "sw": "SSL/TLS        : certificate imepatikana"},
    "auto_web_exposed":    {"en": "Web Exposures  : {n} sensitive path(s) exposed!",
                            "sw": "Maeneo Wazi    : njia {n} za siri zimeachwa wazi!"},
    "auto_web_ok":         {"en": "Web Exposures  : None found",
                            "sw": "Maeneo Wazi    : Hakuna iliyopatikana"},
    "auto_hdr_score":      {"en": "Header Score   :",         "sw": "Alama ya Header :"},
    "auto_ssh_vuln":       {"en": "SSH VULNERABLE :",         "sw": "SSH ILIYO HATARINI:"},
    "auto_ssh_ok":         {"en": "SSH Hardened   : No weak credentials found",
                            "sw": "SSH Imeimarishwa: Hakuna taarifa dhaifu ilivyopatikana"},
    "auto_ssh_closed":     {"en": "SSH Port       : Not open",
                            "sw": "Ports ya SSH : Haifunguliki"},

    # ── Port scan section ──────────────────────────────────────────────────────
    "port_full_title":     {"en": "FULL PORT SCAN — RANGE SELECTOR",
                            "sw": "SKANA KAMILI YA PORT — CHAGUA MSTARI"},
    "port_full_info":      {"en": "Default range: 1–65535 (slow). You can narrow the range.",
                            "sw": "Mstari wa kawaida: 1–65535 (polepole). Unaweza kupunguza."},
    "port_start":          {"en": "Start port [1]",           "sw": "Port ya mwanzo [1]"},
    "port_end":            {"en": "End port   [65535]",       "sw": "Port ya mwisho [65535]"},
    "port_scanning_warn":  {"en": "Scanning {n} ports — this may take a while…",
                            "sw": "Inachunguza ports {n} — hii inaweza kuchukua muda…"},

    # ── Banner grabber ─────────────────────────────────────────────────────────
    "banner_title":        {"en": "BANNER GRABBER — PORT SELECTOR",
                            "sw": "KUNASA BANNER — CHAGUA PORT"},
    "banner_info":         {"en": "Leave blank to grab banners from all common ports.",
                            "sw": "Acha wazi kunasa banner kutoka port zote maarufu."},
    "banner_prompt":       {"en": "Specific ports (comma-separated, e.g. 22,80,443)",
                            "sw": "port maalum (tenganisha kwa koma, mfano 22,80,443)"},
    "banner_invalid":      {"en": "Invalid port input. Using all common ports.",
                            "sw": "Ingizo batili la port. Inatumia Ports zote maarufu."},

    # ── SSL section ────────────────────────────────────────────────────────────
    "ssl_port_prompt":     {"en": "SSL port [443]",           "sw": "Port ya SSL [443]"},

    # ── Dir brute ─────────────────────────────────────────────────────────────
    "dir_brute_title":     {"en": "DIR BRUTE FORCER — OPTIONS",
                            "sw": "DIR BRUTE FORCER — CHAGUO"},
    "q_custom_dir_wl":     {"en": "Load custom wordlist from file?",
                            "sw": "Pakia orodha ya maneno maalum kutoka faili?"},

    # ── SSH audit section ──────────────────────────────────────────────────────
    "ssh_title":           {"en": "SSH AUDIT — OPTIONS",
                            "sw": "UKAGUZI WA SSH — CHAGUO"},
    "ssh_port_prompt":     {"en": "SSH port [22]",            "sw": "Port ya SSH [22]"},
    "q_custom_creds":      {"en": "Load custom credential list from file?",
                            "sw": "Pakia orodha ya vitambulisho maalum kutoka faili?"},
    "creds_file_prompt":   {"en": "File path (user:pass per line)",
                            "sw": "Njia ya faili (mtumiaji:nenosiri kwa kila mstari)"},
    "creds_loaded":        {"en": "Loaded {n} credential pairs.",
                            "sw": "Imepakia jozi {n} za vitambulisho."},
    "creds_load_err":      {"en": "Could not load: {e}. Using default list.",
                            "sw": "Imeshindwa kupakia: {e}. Inatumia orodha ya chaguo-msingi."},

    # ── FTP section ────────────────────────────────────────────────────────────
    "ftp_port_prompt":     {"en": "FTP port [21]",            "sw": "Port ya FTP [21]"},

    # ── HTTP auth section ──────────────────────────────────────────────────────
    "http_auth_title":     {"en": "HTTP BASIC AUTH — OPTIONS",
                            "sw": "HTTP BASIC AUTH — CHAGUO"},
    "http_auth_path":      {"en": "Path to brute force [/]",  "sw": "Njia ya kuvunja kwa nguvu [/]"},

    # ── AI section ─────────────────────────────────────────────────────────────
    "ai_key_title":        {"en": "AI ANALYSIS — GEMINI AI API KEY REQUIRED",
                            "sw": "AI ANALYSIS — API key ya GEMINI iNAHITAJIKA"},
    "ai_key_heading":      {"en": "AI INTEGRATION — FIRST TIME SETUP",
                            "sw": "MUUNGANIKO WA AI — SETUP YA MARA YA KWANZA"},
    "ai_key_desc1":        {"en": "The AI Analysis section uses the AI engine to interpret",
                            "sw": "Sehemu ya Uchambuzi wa AI inatumia the AI engine kutafsiri"},
    "ai_key_desc2":        {"en": "scan findings and generate professional security reports.",
                            "sw": "matokeo ya skana na kutengeneza ripoti rasmi za usalama."},
    "ai_key_info1":        {"en": "Your API key is:",          "sw": "API key yako ni:"},
    "ai_key_bullet1":      {"en": "Never written to disk",     "sw": "Haijawahi kuandikwa kwenye diski"},
    "ai_key_bullet2":      {"en": "Stored only in this session's memory",
                            "sw": "Imehifadhiwa kwenye kumbukumbu ya kikao hiki pekee"},
    "ai_key_bullet3":      {"en": "Used only for CSCAN AI analysis calls",
                            "sw": "Inatumika kwa simu za uchambuzi wa AI za CSCAN pekee"},
    "ai_key_get":          {"en": "Get a free key → https://aistudio.google.com/app/apikey",
                            "sw": "Pata API key bure → https://aistudio.google.com/app/apikey"},
    "ai_active":           {"en": "AI is now active for this session!",
                            "sw": "AI iko active kwa kikao hiki!"},
    "ai_no_key":           {"en": "AI Analysis is unavailable without a valid API key.",
                            "sw": "Uchambuzi wa AI haupatikani bila API key Sahihi."},
    "ai_change_title":     {"en": "CHANGE / CLEAR AI API KEY",
                            "sw": "BADILISHA / FUTA AI API key"},
    "ai_current_key":      {"en": "Current key   :",           "sw": "Ufunguo wa sasa :"},
    "q_clear_key":         {"en": "Clear the current key and enter a new one?",
                            "sw": "Futa API Yako sasa na uweke mpya?"},
    "ai_key_updated":      {"en": "API key updated.",          "sw": "Ufunguo wa API umesasishwa."},
    "no_scan_to_report":   {"en": "No scan results to report on. Run some scans first.",
                            "sw": "Hakuna matokeo ya skana ya kuripoti. Endesha skana kwanza."},

    # ── Generic UI ─────────────────────────────────────────────────────────────
    "press_enter":         {"en": "Press ENTER to return to menu…",
                            "sw": "Bonyeza ENTER kurudi kwa menyu…"},
    "no_results":          {"en": "No results to display.",    "sw": "Hakuna matokeo ya kuonyesha."},
    "set_target_title":    {"en": "SET TARGET",                "sw": "WEKA TARGET(link)"},
    "goodbye_section":     {"en": "GOODBYE",                   "sw": "KWAHERI"},
    "subdomain_title":     {"en": "SUBDOMAIN ENUMERATOR",      "sw": "ORODHA YA SUBDOMAIN"},
    "export_title":        {"en": "EXPORT RESULTS",            "sw": "HAMISHA MATOKEO"},
    "banner_subtitle":     {"en": "Cybersecurity Scanner & Recon Toolkit v2.1",
                            "sw": "Zana ya Uchunguzi wa Usalama wa Mtandao v2.1"},
    "banner_tagline":      {"en": "[ Advanced Security Mode | Authorized Use Only ]",
                            "sw": "[ Advanced Security Mode | Matumizi Yaliyoidhinishwa Pekee ]"},

    # ── Short menu labels for 2-column table (max 15 chars, no emoji) ─────────
    # Prefix [N] adds 4 chars for single-digit, 5 for double-digit.
    # Total column width = 19. Labels must fit: 19 - len("[N] ") chars.
    "sm1":  {"en": "DNS Lookup",        "sw": "DNS Lookup"},
    "sm2":  {"en": "WHOIS",             "sw": "WHOIS"},
    "sm3":  {"en": "Subdomains",        "sw": "Subdomains"},
    "sm4":  {"en": "GeoIP Tracker",     "sw": "GeoIP Location"},
    "sm5":  {"en": "Reverse DNS",       "sw": "Reverse DNS"},
    "sm6":  {"en": "Port Scan",         "sw": "Skana Ports"},
    "sm7":  {"en": "Full Port Scan",    "sw": "Ports Zote"},
    "sm8":  {"en": "Banner Grabber",    "sw": "Kunasa Banner"},
    "sm9":  {"en": "SSL/TLS Inspect",   "sw": "SSL/TLS Ukaguzi"},
    "sm10": {"en": "Web Vuln Scan",     "sw": "Skana Udhaifu"},
    "sm11": {"en": "HTTP Headers",      "sw": "HTTP Headers"},
    "sm12": {"en": "Dir Brute Force",   "sw": "Bruteforce"},
    "sm13": {"en": "CMS Detect",        "sw": "Tambua CMS"},
    "sm14": {"en": "SSH Audit",         "sw": "Ukaguzi SSH"},
    "sm15": {"en": "FTP Anonymous",     "sw": "FTP Bila Jina"},
    "sm16": {"en": "HTTP Auth",         "sw": "HTTP Auth"},
    "sm17": {"en": "Full Auto-Scan",    "sw": "Skana Kamili"},
    "sm18": {"en": "Export Results",    "sw": "Hamisha Matokeo"},
    "sm19": {"en": "Analyse with AI",   "sw": "Changanua kwa AI"},
    "sm20": {"en": "Quick AI Overview", "sw": "Muhtasari wa AI"},
    "sm21": {"en": "CVE Lookup",        "sw": "Tafuta CVE"},
    "sm22": {"en": "Ask AI Assistant",  "sw": "Uliza Msaidizi"},
    "sm23": {"en": "Security Report",   "sw": "Ripoti ya Usalama"},
    "sm24": {"en": "Stealth Config",    "sw": "Mipangilio ya Stealth"},
    "sm25": {"en": "Toggle Stealth",    "sw": "Washa/Zima Stealth"},

    # ── Short section headers for 2-col table (max 19 chars each) ────────────
    "sh_recon":   {"en": "RECONNAISSANCE",  "sw": "RECONNAISSANCE"},
    "sh_network": {"en": "NETWORK SCAN",    "sw": "NETWORK SCAN"},
    "sh_web":     {"en": "WEB ANALYSIS",    "sw": "WEB ANALYSIS"},
    "sh_exploit": {"en": "EXPLOITATION",    "sw": "EXPLOITATION"},
    "sh_auto":    {"en": "AUTOMATION",      "sw": "AUTOMATION"},
    "sh_ai":      {"en": "AI ANALYSIS",   "sw": "AI ANALYSIS"},
    "sh_stealth": {"en": "STEALTH & OPSEC", "sw": "STEALTH & OPSEC"},
    "m_nav_hint": {"en": "T=Target  K=AI Key  S=Stealth  L=Language",
                   "sw": "T=Lengo   K=key ya AI  S=Stealth  L=Lugha"},

    # ── Language toggle (in-session) ────────────────────────────────────────────
    "lang_toggle_title":  {"en": "LANGUAGE / LUGHA",
                           "sw": "LUGHA / LANGUAGE"},
    "lang_toggled_en":    {"en": "Language switched to English.",
                           "sw": "Lugha imebadilishwa kwenda Kiingereza."},
    "lang_toggled_sw":    {"en": "Language switched to Kiswahili.",
                           "sw": "Lugha imebadilishwa kwenda Kiswahili."},
    "lang_current":       {"en": "Current language : English",
                           "sw": "Lugha ya sasa    : Kiswahili"},
}


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────


def T(key: str, **kwargs) -> str:
    """
    Translate a key to the current language.
    Supports optional format kwargs, e.g. T("wordlist_loaded", n=42)
    Falls back to the key itself if not found.
    """
    entry = _STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(_LANG, entry.get("en", key))
    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError:
            pass
    return text


def get_lang() -> str:
    """Return the current language code ('en' or 'sw')."""
    return _LANG


def set_lang(code: str):
    """Set the active language ('en' or 'sw')."""
    global _LANG
    if code in ("en", "sw"):
        _LANG = code


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG FILE — persist language preference
# ─────────────────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_config(cfg: dict):
    try:
        temp_path = f"{_CONFIG_PATH}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, _CONFIG_PATH)
        os.chmod(_CONFIG_PATH, 0o600)
    except Exception:
        pass   # not critical — silently ignore


def is_first_launch() -> bool:
    """Return True if no config file exists yet (very first run)."""
    return not os.path.exists(_CONFIG_PATH)


def load_saved_language():
    """Load the previously saved language preference into the active state."""
    cfg = _load_config()
    code = cfg.get("language", "en")
    set_lang(code)


def save_language(code: str):
    """Persist the chosen language to the config file."""
    cfg = _load_config()
    cfg["language"] = code
    _save_config(cfg)
    set_lang(code)
