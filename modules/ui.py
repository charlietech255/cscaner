#!/usr/bin/env python3
"""
CSCAN — UI: Colors, Banners, Prompts, Progress
"""

import sys
import time
import unicodedata

from modules.lang import T

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

# ── Fallback no-op colour objects ─────────────────────────────────────────────
class _Null:
    def __getattr__(self, _): return ''

if not HAS_COLOR:
    Fore = Back = Style = _Null()

# ── Colour aliases ─────────────────────────────────────────────────────────────
R  = Fore.RED
Y  = Fore.YELLOW
G  = Fore.GREEN
C  = Fore.CYAN
M  = Fore.MAGENTA
W  = Fore.WHITE
B  = Fore.BLUE
BR = Style.BRIGHT
DM = Style.DIM
RS = Style.RESET_ALL

# ── Print helpers ──────────────────────────────────────────────────────────────
def ok(msg):       print(f"  {BR}{G}[+]{RS} {msg}")
def warn(msg):     print(f"  {BR}{Y}[!]{RS} {msg}")
def alert(msg):    print(f"  {BR}{R}[x]{RS} {msg}")
def info(msg):     print(f"  {BR}{C}[>]{RS} {msg}")
def critical(msg): print(f"\n  {BR}{Back.RED}{W} CRITICAL {RS} {BR}{R}{msg}{RS}")
def bold(msg):     print(f"  {BR}{W}{msg}{RS}")

def section(title: str):
    bar = f"{BR}{C}{'─' * 45}{RS}"
    print(f"\n{bar}")
    print(f"  {BR}{M}{title}{RS}")
    print(bar)

def divider():
    print(f"  {DM}{C}{'·' * 45}{RS}")

# ── Wide-character helper (emoji, CJK) ────────────────────────────────────────
def _wide(s: str) -> int:
    """Count extra terminal cells taken by wide chars (each = +1 extra cell)."""
    return sum(1 for ch in s if unicodedata.east_asian_width(ch) in ('W', 'F'))

# ── ASCII Banner (narrow — safe on portrait Termux) ───────────────────────────
def _build_banner() -> str:
    subtitle = T("banner_subtitle")
    return (
        f"\n"
        f"{BR}{G}   ____                                 \n"
        f"{BR}{G}  / ___|___  ___ __ _ _ __  _ __   ___ _ __ \n"
        f"{BR}{Y} | |   / __|/ __/ _` | '_ \\| '_ \\ / _ \\ '__|\n"
        f"{DM}{W} | |___\\__ \\ (_| (_| | | | | | | |  __/ |   \n"
        f"{BR}{B}  \\____|___/\\___\\__,_|_| |_|_| |_|\\___|_|   \n"
        f"{BR}{Y}               [ T O O L ]{RS}\n"
        f"{BR}{M}  {'─'*43}\n"
        f"  {subtitle}\n"
        f"  {'─'*43}{RS}\n"
    )

# ── 2-column menu (mobile-optimised) ─────────────────────────────────────────
def _build_menu() -> str:
    """
    Layout (47 chars wide including 2-char indent):
      ╔═══════════════════╦═══════════════════╗  <- 2+1+21+1+21+1 = 47
      ║ LEFT (19 chars)   ║ RIGHT (19 chars)  ║
      ╚═══════════════════╩═══════════════════╝

    Single-col rows (after merge):
      ╔═════════════════════════════════════════╗  <- 2+1+43+1 = 47
      ║ FULL (41 chars)                         ║
      ╚═════════════════════════════════════════╝
    """
    wL = 19    # left column inner data width
    wR = 19    # right column inner data width
    wF = 41    # single-column inner data width  (= L+1+R)

    # ── number colour by section ──────────────────────────────────────────
    def _nc(n):
        n = int(n)
        if n <= 5:  return BR + G
        if n <= 9:  return BR + Y
        if n <= 13: return BR + B
        if n <= 16: return BR + R
        if n <= 18: return BR + W
        return BR + M

    # ── box borders ──────────────────────────────────────────────────────
    TOP2  = f"  {C}╔{'═'*(wL+2)}╦{'═'*(wR+2)}╗{RS}"
    MID2  = f"  {C}╠{'═'*(wL+2)}╬{'═'*(wR+2)}╣{RS}"
    MRG   = f"  {C}╠{'═'*(wL+2)}╩{'═'*(wR+2)}╣{RS}"   # 2-col → 1-col merge
    MID1  = f"  {C}╠{'═'*(wF+2)}╣{RS}"
    BOT   = f"  {C}╚{'═'*(wF+2)}╝{RS}"

    # ── row builders ─────────────────────────────────────────────────────
    def sec2(lt, rt=''):
        lp = f"{lt:<{wL}}"
        rp = f"{rt:<{wR}}" if rt else ' ' * wR
        return f"  {C}║{RS} {BR}{M}{lp}{RS} {C}║{RS} {BR}{M}{rp}{RS} {C}║{RS}"

    def row2(ln, lt, rn='', rt=''):
        nc_l  = _nc(ln)
        pfx_l = f"[{ln}] "
        lbl_l = f"{lt:<{wL - len(pfx_l)}}"
        left  = f"{nc_l}{pfx_l}{RS}{C}{lbl_l}"
        if rn:
            nc_r  = _nc(rn)
            pfx_r = f"[{rn}] "
            lbl_r = f"{rt:<{wR - len(pfx_r)}}"
            right = f"{nc_r}{pfx_r}{RS}{C}{lbl_r}"
        else:
            right = ' ' * wR
        return f"  {C}║{RS} {left} {C}║{RS} {right} {C}║{RS}"

    def sec1(title):
        return f"  {C}║{RS} {BR}{M}{title:<{wF - _wide(title)}}{RS} {C}║{RS}"

    def row1(n, label):
        nc  = _nc(n)
        pfx = f"[{n}] "
        pad = wF - len(pfx) - _wide(label)
        return f"  {C}║{RS} {nc}{pfx}{RS}{C}{label:<{pad}} {C}║{RS}"

    def row_hint(text):
        return f"  {C}║{RS} {DM}{text:<{wF - _wide(text)}}{RS} {C}║{RS}"

    # ── build lines ──────────────────────────────────────────────────────
    return '\n'.join([
        "",
        # RECON ←→ NETWORK
        TOP2,
        sec2(T("sh_recon"),   T("sh_network")),
        MID2,
        row2('1', T("sm1"),   '6', T("sm6")),
        row2('2', T("sm2"),   '7', T("sm7")),
        row2('3', T("sm3"),   '8', T("sm8")),
        row2('4', T("sm4"),   '9', T("sm9")),
        row2('5', T("sm5")),
        # WEB ←→ EXPLOIT
        MID2,
        sec2(T("sh_web"),     T("sh_exploit")),
        MID2,
        row2('10', T("sm10"), '14', T("sm14")),
        row2('11', T("sm11"), '15', T("sm15")),
        row2('12', T("sm12"), '16', T("sm16")),
        row2('13', T("sm13")),
        # AUTOMATION (single col)
        MRG,
        sec1(T("sh_auto")),
        MID1,
        row1('17', T("sm17")),
        row1('18', T("sm18")),
        # AI ANALYSIS (single col)
        MID1,
        sec1(T("sh_ai")),
        MID1,
        row1('19', T("sm19")),
        row1('20', T("sm20")),
        row1('21', T("sm21")),
        row1('22', T("sm22")),
        row1('23', T("sm23")),
        # STEALTH & OPSEC (single col)
        MID1,
        sec1(T("sh_stealth")),
        MID1,
        row1('24', T("sm24")),
        row1('25', T("sm25")),
        # EXIT + NAV
        MID1,
        row1('0', T("menu_exit")),
        row_hint(T("m_nav_hint")),
        BOT,
        "",
    ])


def show_banner():
    print(_build_banner())

def show_menu():
    print(_build_menu())

# ── Prompts ───────────────────────────────────────────────────────────────────
def prompt_target(label: str = None) -> str:
    if label is None:
        label = T("prompt_target")
    print()
    target = input(f"  {BR}{C}[?]{RS} {BR}{W}{label}: {RS}").strip()
    if not target:
        warn(T("no_target"))
        return None
    return target

def prompt_choice(label: str = None) -> str:
    if label is None:
        label = T("prompt_select")
    print()
    return input(f"  {BR}{M}[>]{RS} {BR}{W}{label}: {RS}").strip()

def prompt_yes(question: str) -> bool:
    ans = input(f"  {BR}{Y}[?]{RS} {question} {DM}(y/N){RS} ").strip().lower()
    return ans == 'y'

# ── Spinner / Progress ────────────────────────────────────────────────────────
def spinner(message: str, secs: float = 0.0):
    chars = ['-', '\\', '|', '/']
    end_time = time.time() + secs
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r  {BR}{C}{chars[i % len(chars)]}{RS}  {message}  ")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write('\r' + ' ' * 60 + '\r')

def progress_bar(current: int, total: int, label: str = ''):
    pct = int((current / total) * 25)
    bar = f"{G}{'#' * pct}{DM}{'.' * (25 - pct)}{RS}"
    sys.stdout.write(f"\r  {C}[{bar}{C}]{RS} {current}/{total} {DM}{label}{RS}  ")
    sys.stdout.flush()

# ── Table renderer ────────────────────────────────────────────────────────────
def print_table(headers: list, rows: list):
    if not rows:
        warn(T("no_results"))
        return
    col_w = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_w[i] = max(col_w[i], len(str(cell)))
    sep  = f"  {C}+" + "+".join(["─" * (w + 2) for w in col_w]) + f"+{RS}"
    hdr  = f"  {C}|" + "|".join(f" {BR}{W}{h:<{col_w[i]}}{RS}{C}" for i, h in enumerate(headers)) + f"|{RS}"
    print(sep); print(hdr); print(sep)
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            s = str(cell)
            colour = G if 'OPEN' in s or '+' in s else (R if 'VULN' in s or 'x' in s else W)
            cells.append(f" {colour}{s:<{col_w[i]}}{RS}")
        print(f"  {C}|" + "|".join(cells) + f"{C}|{RS}")
    print(sep)

def pause():
    input(f"\n  {DM}{T('press_enter')}{RS}")
