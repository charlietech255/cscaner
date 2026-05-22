# CSCAN Installation Guide

Hey, welcome! This guide will help you get CSCAN up and running on your machine. Just follow the steps below and you will be good to go.

## Quick Start

### Option 1: Automatic Installation (Recommended)

This is the easiest way — just two commands:

```bash
chmod +x install.sh
./install.sh
```

The script will:
- Detect your environment (Kali, Termux, or Linux)
- Create a virtual environment (Kali only)
- Install all the dependencies for you
- Create a launcher script (Kali only)

### Option 2: Manual Installation on Kali (PEP 668 Fix)

**Problem:** You get `error: externally-managed-environment`

**Solution:** Use a virtual environment — here is how:

```bash
# 1. Install venv if you do not have it
sudo apt install python3-venv python3-pip -y

# 2. Create the virtual environment
python3 -m venv venv

# 3. Activate it
source venv/bin/activate

# 4. Install the dependencies
pip install -r requirements.txt

# 5. Run CSCAN
python3 cscan.py
```

### Option 3: Termux Installation

If you are on Termux, it is even simpler:

```bash
pkg install python git -y
pip install -r requirements.txt
python3 cscan.py
```

---

## After Installation

### On Kali:
```bash
# Method 1: Use the launcher (easiest)
./cscan_launcher.sh

# Method 2: Manual activation
source venv/bin/activate
python3 cscan.py

# Method 3: Direct (if venv is already active)
python3 cscan.py
```

### On Termux:
```bash
python3 cscan.py
```

### On Other Linux:
```bash
# Create a venv for safety
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 cscan.py
```

---

## Troubleshooting

Here are some common problems and how to fix them.

### Issue: `python3 -m venv: command not found`

**Fix:** Install the venv package for your system:

```bash
# Debian/Ubuntu/Kali
sudo apt install python3-venv

# Fedora/RHEL
sudo dnf install python3-venv

# Arch
sudo pacman -S python-venv
```

### Issue: `pip: command not found`

**Fix:** Install pip:

```bash
# Debian/Ubuntu/Kali
sudo apt install python3-pip

# Fedora/RHEL
sudo dnf install python3-pip
```

### Issue: Permission denied on install.sh

**Fix:** Make it executable first:

```bash
chmod +x install.sh
./install.sh
```

### Issue: `ModuleNotFoundError` when running cscan

**Fix:** Make sure the dependencies are installed:

```bash
# If you are in a venv
source venv/bin/activate
pip install -r requirements.txt

# If you are not in a venv yet
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Dependencies

All of these get installed automatically by `install.sh`:

**Required:**
- `requests` — HTTP requests
- `colorama` — Colored terminal output
- `python-whois` — WHOIS lookups
- `beautifulsoup4` — HTML parsing

**Optional:**
- `paramiko` — SSH auditing (not available on Termux due to cryptography build requirements)
- `python-nmap` — Nmap integration (Linux only, not Termux)

**No external crypto library needed** — crypto_utils.py uses Python stdlib (hashlib, hmac, base64) only.

### Termux Compatibility

On Termux, `paramiko` cannot be installed because it depends on `cryptography`, which requires Rust to compile. This is a Termux limitation, not CSCAN. If you need SSH auditing, use CSCAN on a standard Linux distribution.

All other CSCAN features (web scanning, WHOIS, directory brute-forcing, etc.) work perfectly on Termux.

---

## Environment Check

After installation, you can verify everything works like this:

```bash
# Activate venv if you are on Kali
source venv/bin/activate  # Optional

# Test that all imports work (core dependencies)
python3 << 'EOF'
import requests
import colorama
import bs4
print("All core dependencies are OK!")

# Try optional paramiko (may fail on Termux, which is OK)
try:
    import paramiko
    print("paramiko is available for SSH auditing")
except ImportError:
    print("paramiko not available (normal on Termux)")
EOF

# Test CSCAN itself
python3 cscan.py
```

---

## Virtual Environment Explained

A **virtual environment** (venv) is like a separate Python installation that keeps your packages isolated so they do not conflict with system packages. This is required on Kali because of PEP 668 restrictions.

```bash
# Activate venv (you need to do this every time you open a new terminal)
source venv/bin/activate

# Deactivate (when you are done)
deactivate

# Remove venv completely (if you need to start fresh)
rm -rf venv
```

---

## Getting Help

If installation fails, try these steps:

1. Check your Python version: `python3 --version` (you need 3.6 or higher)
2. Check pip: `pip --version`
3. Try updating: `pip install --upgrade pip setuptools`
4. Check your internet connection
5. Try the manual installation (see Option 2 above)
