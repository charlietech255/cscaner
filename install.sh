#!/usr/bin/env bash

# Defines colors for bash output
GREEN="\e[1;32m"
BLUE="\e[1;36m"
YELLOW="\e[1;33m"
RED="\e[1;31m"
RESET="\e[0m"

echo -e "${BLUE}[*] Checking Termux environment setup...${RESET}"

# Use Termux prefix if available, otherwise default path
if [ -z "$PREFIX" ]; then
    PREFIX="/data/data/com.termux/files/usr"
fi

if ! command -v pkg &> /dev/null; then
    echo -e "${RED}[!] 'pkg' package manager not found.${RESET}"
    echo -e "${YELLOW}[!] This script is designed specifically for Termux.${RESET}"
fi

# Check for Python and Git
MISSING_DEPS=0
if ! command -v python &> /dev/null || ! command -v pip &> /dev/null || ! command -v git &> /dev/null; then
    echo -e "${RED}[!] Python, pip, or git is missing from your Termux environment.${RESET}"
    MISSING_DEPS=1
fi

if [ $MISSING_DEPS -eq 1 ]; then
    echo -e "${YELLOW}[!] The tool requires Python, pip, and git to function.${RESET}"
    read -p "[?] Do you want to automatically install them now? (y/N): " allow_install
    
    if [[ "$allow_install" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[*] Updating repositories and installing dependencies...${RESET}"
        pkg update -y
        pkg install python git -y
    else
        echo -e "${RED}[!] CSCAN setup cannot complete without dependencies. Installation aborted.${RESET}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] Base environment (Python, Git) found.${RESET}"
fi

echo -e "${BLUE}[*] Installing required Python dependencies...${RESET}"
pip install requests colorama paramiko python-whois > /dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to install Python packages. Check your internet connection.${RESET}"
    exit 1
fi
echo -e "${GREEN}[+] Dependencies installed successfully.${RESET}"

echo -e "${BLUE}[*] Creating universal shortcut...${RESET}"

TOOL_DIR="$(pwd)"
BIN_PATH="$PREFIX/bin/cscan"

# Create the wrapper script in the bin directory
cat << EOF > "$BIN_PATH"
#!/usr/bin/env bash
cd "$TOOL_DIR"
python cscan.py "\$@"
EOF

# Make both the wrapper and the original script executable
chmod +x "$BIN_PATH"
chmod +x "$TOOL_DIR/cscan.py" 2>/dev/null

echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║         INSTALLATION COMPLETE  
               enjoy C scanner toka kwa charlie
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "You can now run your tool directly from any folder by typing:"
echo -e "  ${BLUE}cscan${RESET}\n"
