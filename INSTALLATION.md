# CSCAN Installation Guide

Hey, welcome! This guide will help you get **CSCAN** (C Scanner by Charlie Tech) up and running on your machine. Just follow the steps below and you will be good to go.

With the latest updates, CSCAN now supports **Advanced Fingerprint-Resistant Browser Scanning** (WAF bypass, JS DOM extraction, cookie harvesting) and **AI Security Analyst Integration**. Below you'll find setup instructions for both core and advanced packages.

---

## Quick Start

### Option 1: Automatic Installation (Recommended)

This is the easiest way — just run these commands:

```bash
chmod +x install.sh
./install.sh
```

The script will:
- Detect your environment (Kali, Termux, or standard Linux)
- Create a virtual environment (Kali only, complying with PEP 668)
- Install all core dependencies
- Create a launcher shortcut (`cscan_launcher.sh` on Kali)

---

## Advanced Feature Setup (Highly Recommended)

To make full use of all the new tools in CSCAN, configure these advanced modules:

### 1. Advanced Browser Engine & WAF Evasion
Required for Cloudflare WAF Bypass, JS DOM Page Rendering, Cookie Harvester, dynamic Form Login Testing, and JavaScript Secret Scanning.

> [!NOTE]
> The browser engine is fully supported on Kali Linux, Ubuntu, Debian, and other desktop/server architectures.

Activate your environment and run:
```bash
# 1. Install the specialized fingerprint browser engine
pip install "camoufox[geoip]"

# 2. Fetch and synchronize the latest fingerprint data (downloads browser binaries)
python -m camoufox fetch
```

### 2. AI Security Analyst (Gemini Integration)
Required for Executive Findings Summaries, Quick Host Overview, CVE Lookup Assistant, and formal PDF/text Penetration Testing Report generation.

1. Obtain a free or pay-as-you-go API key from the [Google AI Studio Console](https://aistudio.google.com/).
2. You can:
   - Provide the key interactively inside the CSCAN menu when selecting any option `19–23`.
   - Or, permanently set it in your current terminal profile:
     ```bash
     export GEMINI_API_KEY="your-api-key-here"
     ```

---

## Detailed Manual Installation Workflows

### Option 2: Manual Installation on Kali Linux (PEP 668 Fix)

If you prefer to set up manually and avoid `externally-managed-environment` pip errors, run the following:

```bash
# 1. Install venv if you do not have it
sudo apt update
sudo apt install python3-venv python3-pip git nmap -y

# 2. Create the virtual environment
python3 -m venv venv

# 3. Activate the environment
source venv/bin/activate

# 4. Install core dependencies
pip install -r requirements.txt

# 5. [Optional] Install advanced WAF evasion browser engine
pip install "camoufox[geoip]"
python -m camoufox fetch

# 6. Run CSCAN
python3 cscan.py
```

### Option 3: Termux Installation (Android)

Termux does not enforce PEP 668, making installation very direct.

```bash
# 1. Update Termux environment packages
pkg update && pkg upgrade -y

# 2. Install Python, Git, and Nmap (for port scan capabilities)
pkg install python git nmap -y

# 3. Install core dependencies
pip install -r requirements.txt

# 4. Run CSCAN
python3 cscan.py
```

*Note: The fingerprint-resistant browser engine (`camoufox`) is currently restricted on Termux due to chromium-under-qemu/playwright mobile compatibility. Core stealth, path mutations, adaptive backoff, and AI analysts are fully supported on Termux.*

---

## After Installation

### On Kali / Desktop Linux:
To run CSCAN anytime:
```bash
# If you used the installer
./cscan_launcher.sh

# Or manually:
source venv/bin/activate
python3 cscan.py
```

### On Termux:
```bash
python3 cscan.py
```

---

## Troubleshooting

### Issue: `python3 -m venv: command not found`
**Fix:** Install the venv package for your system distribution:
```bash
# Debian/Ubuntu/Kali
sudo apt install python3-venv

# Fedora/RHEL
sudo dnf install python3-venv

# Arch
sudo pacman -S python-venv
```

### Issue: `ModuleNotFoundError` when running CSCAN
**Fix:** Make sure your virtual environment is active:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: Playwright / Camoufox errors
**Fix:** Ensure you fetched the browser binaries:
```bash
python -m camoufox fetch
```
If dynamic system libraries are missing on Linux, run `playwright install-deps` or ensure your system packages are updated.

---

## Dependencies Map

- **`requests`** — Interactive HTTP requests
- **`colorama`** — Responsive colored terminal styling
- **`paramiko`** — Multi-threaded SSH credential auditing
- **`python-whois`** — Domain registry intelligence
- **`python-nmap`** — Advanced nmap-integrated SYN scanning
- **`beautifulsoup4`** — Static DOM HTML analysis
- **`camoufox`** — (Optional) Advanced stealth browser engine for WAF evasion

---

## Virtual Environment (venv) Cheat Sheet

A virtual environment keeps your packages isolated so they do not conflict with the system packages.

```bash
# Activate the venv (needed each time you open a new terminal)
source venv/bin/activate

# Deactivate (when you want to return to standard terminal shell)
deactivate

# Clear venv to reinstall fresh
rm -rf venv
```

---

## Getting Help

If installation fails:
1. Verify python version is 3.8+: `python3 --version`
2. Update installer helpers: `pip install --upgrade pip setuptools`
3. Ensure active internet connection.
4. Try the automatic script option first: `bash install.sh`.
