#!/usr/bin/env bash

# ── CSCAN Installation Script ──────────────────────────────────────────────────
# Works on: Kali Linux, Debian, Ubuntu, Termux, and other Linux distributions
# Handles PEP 668 externally-managed-environment errors automatically

# Color definitions
GREEN="\e[1;32m"
BLUE="\e[1;36m"
YELLOW="\e[1;33m"
RED="\e[1;31m"
RESET="\e[0m"

# ── Detect Environment ─────────────────────────────────────────────────────────
echo -e "${BLUE}[*] Detecting environment...${RESET}"

IS_TERMUX=0
IS_KALI=0

# Better Termux detection
if [[ "$PREFIX" == *"com.termux"* ]] || [[ "$HOME" == *"com.termux"* ]] || [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=1
    echo -e "${GREEN}[+] Termux detected${RESET}"
elif grep -qi "kali" /etc/os-release 2>/dev/null; then
    IS_KALI=1
    echo -e "${GREEN}[+] Kali Linux detected${RESET}"
else
    echo -e "${YELLOW}[!] Could not auto-detect environment${RESET}"
    echo ""
    echo -e "${BLUE}[?] Which environment are you using?${RESET}"
    echo "  1) Kali Linux / Debian / Ubuntu"
    echo "  2) Termux (Android)"
    read -p "Choose [1 or 2]: " CHOICE
    
    if [ "$CHOICE" == "2" ]; then
        IS_TERMUX=1
        echo -e "${GREEN}[+] Using Termux${RESET}"
    else
        echo -e "${GREEN}[+] Using Linux${RESET}"
    fi
fi

# ── Check Python ───────────────────────────────────────────────────────────────
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 not found${RESET}"
    exit 1
fi

PYTHON=$(command -v python3)
echo -e "${GREEN}[+] Using Python: $PYTHON${RESET}"

# ── Setup Virtual Environment (required for Kali/system Python) ────────────────
if [ $IS_KALI -eq 1 ] && ! [ -d "venv" ]; then
    echo -e "${BLUE}[*] Setting up virtual environment (Kali requirement)...${RESET}"
    
    if ! $PYTHON -m venv venv 2>/dev/null; then
        echo -e "${RED}[!] Failed to create venv. Installing python3-venv...${RESET}"
        sudo apt install -y python3-venv python3-pip 2>/dev/null || {
            echo -e "${YELLOW}[!] Could not install venv package.${RESET}"
            echo -e "${YELLOW}[!] Try: sudo apt install python3-venv${RESET}"
            exit 1
        }
        $PYTHON -m venv venv
    fi
    
    echo -e "${GREEN}[+] Virtual environment created${RESET}"
    ACTIVATE_SCRIPT="$(pwd)/venv/bin/activate"
    source "$ACTIVATE_SCRIPT"
    echo -e "${GREEN}[+] Virtual environment activated${RESET}"
elif [ $IS_KALI -eq 1 ] && [ -d "venv" ]; then
    echo -e "${YELLOW}[*] Virtual environment already exists. Activating...${RESET}"
    source "$(pwd)/venv/bin/activate"
fi

# ── Install Python Dependencies ────────────────────────────────────────────────
echo ""
echo -e "${BLUE}[*] Installing Python dependencies...${RESET}"

PACKAGES="requests colorama python-whois beautifulsoup4"

# Show what will be installed
if [ $IS_TERMUX -eq 1 ]; then
    echo -e "${YELLOW}[*] Termux mode: Skipping paramiko and python-nmap${RESET}"
    echo -e "${YELLOW}[!] SSH auditing will not be available${RESET}"
    echo -e "${GREEN}[+] Web scanning features fully available${RESET}"
else
    echo -e "${GREEN}[+] Installing optional packages: paramiko, python-nmap${RESET}"
    # Add python-nmap only if not Termux
    PACKAGES="$PACKAGES python-nmap"
    # Add paramiko only if not Termux (requires Rust for cryptography compilation)
    PACKAGES="$PACKAGES paramiko"
fi

echo ""
pip install --upgrade pip setuptools 2>&1 | grep -E "(Successfully|already)" || true

for pkg in $PACKAGES; do
    echo -ne "  Installing $pkg... "
    if pip install "$pkg" -q 2>&1; then
        echo -e "${GREEN}[OK]${RESET}"
    else
        echo -e "${YELLOW}[!!]${RESET}"
    fi
done

# ── Verify Installation ────────────────────────────────────────────────────────
echo -e "${BLUE}[*] Verifying installation...${RESET}"

missing=0
for pkg in requests colorama; do
    python3 -c "import $(echo $pkg | sed 's/-/_/g')" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}[OK]${RESET} $pkg"
    else
        echo -e "  ${RED}[FAIL]${RESET} $pkg"
        missing=$((missing + 1))
    fi
done

# Check paramiko only on non-Termux systems
if [ $IS_TERMUX -eq 0 ]; then
    python3 -c "import paramiko" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}[OK]${RESET} paramiko"
    else
        echo -e "  ${RED}[FAIL]${RESET} paramiko"
        missing=$((missing + 1))
    fi
else
    echo -e "  ${YELLOW}[OPTIONAL]${RESET} paramiko (not available in Termux, SSH auditing disabled)"
fi

if [ $missing -gt 0 ]; then
    echo -e "${RED}[!] Some packages failed to install${RESET}"
    exit 1
fi

# ── Create Launcher Script (for Kali convenience) ───────────────────────────────
if [ $IS_KALI -eq 1 ]; then
    echo -e "${BLUE}[*] Creating launcher script...${RESET}"
    
    cat > cscan_launcher.sh << 'LAUNCHER'
#!/usr/bin/env bash
# CSCAN Launcher - Automatically activates venv and runs cscan

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if [ -d "venv" ]; then
    source venv/bin/activate
fi

python3 cscan.py "$@"
LAUNCHER
    
    chmod +x cscan_launcher.sh
    echo -e "${GREEN}[+] Launcher created: ${BLUE}./cscan_launcher.sh${RESET}"
fi

# ── Final Instructions ─────────────────────────────────────────────────────────
echo -e "\n${GREEN}╔════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║          CSCAN Installation Complete!                 ║${RESET}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${RESET}\n"

if [ $IS_KALI -eq 1 ]; then
    echo -e "${BLUE}To run CSCAN on Kali:${RESET}"
    echo -e "  ${YELLOW}./cscan_launcher.sh${RESET}          (auto venv activation)"
    echo -e "  ${YELLOW}source venv/bin/activate${RESET}    (then: python3 cscan.py)"
    echo -e "  ${YELLOW}python3 cscan.py${RESET}            (if venv already active)"
elif [ $IS_TERMUX -eq 1 ]; then
    echo -e "${BLUE}To run CSCAN on Termux:${RESET}"
    echo -e "  ${YELLOW}python3 cscan.py${RESET}"
else
    echo -e "${BLUE}To run CSCAN:${RESET}"
    echo -e "  ${YELLOW}./cscan_launcher.sh${RESET}         (if launcher created)"
    echo -e "  ${YELLOW}python3 cscan.py${RESET}           (direct execution)"
fi

echo -e "\n${GREEN}[+] All dependencies installed successfully!${RESET}\n"
