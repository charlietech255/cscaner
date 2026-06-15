#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# CSCAN — Professional Wordlist Fetcher
# Downloads SecLists and curated wordlists to replace toy-sized defaults.
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST_DIR="$SCRIPT_DIR/wordlists"
BACKUP_DIR="$WORDLIST_DIR/.originals"

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║    CSCAN — Professional Wordlist Downloader          ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""

mkdir -p "$WORDLIST_DIR" "$BACKUP_DIR"

# Back up originals
for f in "$WORDLIST_DIR"/*.txt; do
    [ -f "$f" ] && cp "$f" "$BACKUP_DIR/" 2>/dev/null || true
done

SECLISTS_BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master"

# ── 1. Subdomain wordlist (20k entries) ──────────────────────────────────────
echo "  [1/6] Downloading subdomain wordlist (20k entries)..."
curl -sL "$SECLISTS_BASE/Discovery/DNS/subdomains-top1million-20000.txt" \
    -o "$WORDLIST_DIR/subdomains.txt" 2>/dev/null
if [ -s "$WORDLIST_DIR/subdomains.txt" ]; then
    LINES=$(wc -l < "$WORDLIST_DIR/subdomains.txt")
    echo "  [+] subdomains.txt: $LINES entries"
else
    echo "  [!] Download failed, keeping original"
    cp "$BACKUP_DIR/subdomains.txt" "$WORDLIST_DIR/subdomains.txt" 2>/dev/null || true
fi

# ── 2. Directory bruteforce (combined 30k) ───────────────────────────────────
echo "  [2/6] Downloading directory wordlists (combined ~30k)..."
TMPDIR=$(mktemp -d)
curl -sL "$SECLISTS_BASE/Discovery/Web-Content/directory-list-2.3-medium.txt" \
    -o "$TMPDIR/dirs_medium.txt" 2>/dev/null
curl -sL "$SECLISTS_BASE/Discovery/Web-Content/common.txt" \
    -o "$TMPDIR/dirs_common.txt" 2>/dev/null
curl -sL "$SECLISTS_BASE/Discovery/Web-Content/raft-medium-directories.txt" \
    -o "$TMPDIR/dirs_raft.txt" 2>/dev/null

# Combine, deduplicate, take top 30k
cat "$TMPDIR"/dirs_*.txt 2>/dev/null | grep -v '^#' | sort -u | head -30000 \
    > "$WORDLIST_DIR/dir_bruteforce.txt" 2>/dev/null
LINES=$(wc -l < "$WORDLIST_DIR/dir_bruteforce.txt" 2>/dev/null || echo "0")
if [ "$LINES" -gt 1000 ]; then
    echo "  [+] dir_bruteforce.txt: $LINES entries"
else
    echo "  [!] Download partial, keeping original"
    cp "$BACKUP_DIR/dir_bruteforce.txt" "$WORDLIST_DIR/dir_bruteforce.txt" 2>/dev/null || true
fi
rm -rf "$TMPDIR"

# ── 3. Sensitive paths (expanded) ────────────────────────────────────────────
echo "  [3/6] Downloading sensitive paths wordlist..."
TMPDIR2=$(mktemp -d)
curl -sL "$SECLISTS_BASE/Discovery/Web-Content/quickhits.txt" \
    -o "$TMPDIR2/quickhits.txt" 2>/dev/null
curl -sL "$SECLISTS_BASE/Discovery/Web-Content/LinuxFileList.txt" \
    -o "$TMPDIR2/linux_files.txt" 2>/dev/null

# Merge with existing sensitive_paths.txt
cat "$WORDLIST_DIR/sensitive_paths.txt" "$TMPDIR2"/*.txt 2>/dev/null \
    | grep -v '^#' | sort -u > "$WORDLIST_DIR/sensitive_paths_new.txt" 2>/dev/null
LINES=$(wc -l < "$WORDLIST_DIR/sensitive_paths_new.txt" 2>/dev/null || echo "0")
if [ "$LINES" -gt 500 ]; then
    mv "$WORDLIST_DIR/sensitive_paths_new.txt" "$WORDLIST_DIR/sensitive_paths.txt"
    echo "  [+] sensitive_paths.txt: $LINES entries"
else
    rm -f "$WORDLIST_DIR/sensitive_paths_new.txt"
    echo "  [!] Keeping original sensitive_paths.txt"
fi
rm -rf "$TMPDIR2"

# ── 4. SSH credentials (expanded) ────────────────────────────────────────────
echo "  [4/6] Downloading SSH credential wordlists..."
TMPDIR3=$(mktemp -d)
curl -sL "$SECLISTS_BASE/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt" \
    -o "$TMPDIR3/ssh_better.txt" 2>/dev/null
curl -sL "$SECLISTS_BASE/Passwords/Common-Credentials/10-million-password-list-top-1000.txt" \
    -o "$TMPDIR3/top1k_passwords.txt" 2>/dev/null

# Build user:pass format from top passwords (combine with common usernames)
USERS="root admin user test guest oracle postgres mysql tomcat pi ubuntu deploy vagrant jenkins ansible nagios zabbix"
{
    # Keep existing creds
    cat "$WORDLIST_DIR/ssh_creds.txt" 2>/dev/null
    # Add better defaults
    cat "$TMPDIR3/ssh_better.txt" 2>/dev/null
    # Generate combos: common users × top passwords
    for u in $USERS; do
        while IFS= read -r pwd; do
            [ -n "$pwd" ] && echo "$u:$pwd"
        done < "$TMPDIR3/top1k_passwords.txt" 2>/dev/null | head -50
    done
} | grep -v '^#' | grep ':' | sort -u > "$WORDLIST_DIR/ssh_creds_new.txt" 2>/dev/null

LINES=$(wc -l < "$WORDLIST_DIR/ssh_creds_new.txt" 2>/dev/null || echo "0")
if [ "$LINES" -gt 200 ]; then
    mv "$WORDLIST_DIR/ssh_creds_new.txt" "$WORDLIST_DIR/ssh_creds.txt"
    echo "  [+] ssh_creds.txt: $LINES entries"
else
    rm -f "$WORDLIST_DIR/ssh_creds_new.txt"
    echo "  [!] Keeping original ssh_creds.txt"
fi
rm -rf "$TMPDIR3"

# ── 5. HTTP credentials (expanded) ───────────────────────────────────────────
echo "  [5/6] Downloading HTTP credential wordlists..."
TMPDIR4=$(mktemp -d)
curl -sL "$SECLISTS_BASE/Passwords/Default-Credentials/default-passwords.csv" \
    -o "$TMPDIR4/default_creds.csv" 2>/dev/null

{
    cat "$WORDLIST_DIR/http_creds.txt" 2>/dev/null
    # Parse CSV: username,password format → user:pass
    awk -F',' 'NR>1 && NF>=2 {print $1":"$2}' "$TMPDIR4/default_creds.csv" 2>/dev/null
} | grep -v '^#' | grep ':' | sort -u > "$WORDLIST_DIR/http_creds_new.txt" 2>/dev/null

LINES=$(wc -l < "$WORDLIST_DIR/http_creds_new.txt" 2>/dev/null || echo "0")
if [ "$LINES" -gt 200 ]; then
    mv "$WORDLIST_DIR/http_creds_new.txt" "$WORDLIST_DIR/http_creds.txt"
    echo "  [+] http_creds.txt: $LINES entries"
else
    rm -f "$WORDLIST_DIR/http_creds_new.txt"
    echo "  [!] Keeping original http_creds.txt"
fi
rm -rf "$TMPDIR4"

# ── 6. XSS / SQLi payload lists ─────────────────────────────────────────────
echo "  [6/6] Downloading fuzzing payloads..."
curl -sL "$SECLISTS_BASE/Fuzzing/XSS/XSS-Jhaddix.txt" \
    -o "$WORDLIST_DIR/xss_payloads.txt" 2>/dev/null
curl -sL "$SECLISTS_BASE/Fuzzing/SQLi/Generic-SQLi.txt" \
    -o "$WORDLIST_DIR/sqli_payloads.txt" 2>/dev/null

for f in xss_payloads.txt sqli_payloads.txt; do
    if [ -s "$WORDLIST_DIR/$f" ]; then
        LINES=$(wc -l < "$WORDLIST_DIR/$f")
        echo "  [+] $f: $LINES entries"
    else
        echo "  [!] $f download failed (optional)"
    fi
done

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║    Wordlist upgrade complete!                        ║"
echo "  ║    Originals backed up in wordlists/.originals/      ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Summary:"
for f in "$WORDLIST_DIR"/*.txt; do
    [ -f "$f" ] && echo "    $(basename "$f"): $(wc -l < "$f") entries"
done
echo ""
