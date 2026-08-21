# CSCAN Security Assessment Toolkit

CSCAN is a focused toolkit for authorized web reconnaissance and assessment. It is designed for owned or explicitly authorized targets and emphasizes structured discovery, inspection, and reporting rather than broad marketing claims.

This project is best understood as a practical lab and assessment helper for:

- DNS and host discovery
- subdomain enumeration
- common port and service review
- TLS inspection
- web crawling and endpoint discovery
- authenticated or session-aware testing
- structured findings and report export

It is not positioned as a universal enterprise-grade security platform. The intent is to provide a transparent, scriptable workflow for web-target assessment in controlled environments.

---

## Scope and maturity

This project is intentionally scoped to a set of practical assessment tasks. Some capabilities are experimental or best-effort, and some are intentionally limited to specific workflows.

This repository is most useful when used responsibly and with clear authorization. The tool should be treated as a research and assessment aid, not as a guarantee of production-grade coverage.

---

## Core features

* DNS and host intelligence for target validation
* Subdomain enumeration and passive-style discovery support
* Port scanning and service inspection
* TLS / certificate inspection
* Web crawling for page and parameter discovery
* Header and endpoint review for common web issues
* Auth-aware scanning support
* Structured reporting in JSON and text formats

---

## Installation Guide

Kindly follow the steps below depending on the system you are using. It is very simple to set up.

### 🐧 1. Installing on Linux (Ubuntu, Kali, Debian, etc.)

Linux is the most recommended environment for running CSCAN smoothly.

**Step 1:** Open your terminal and clone the repository:
```bash
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
```

**Step 2:** Make the installation script executable and run it:
```bash
chmod +x install.sh
./install.sh
```

**Step 3:** Download the professional wordlists to make your scans accurate:
```bash
chmod +x fetch_wordlists.sh
./fetch_wordlists.sh
```

**Step 4:** You can now start CSCAN by typing:
```bash
python3 cscan.py
```

---

### 📱 2. Installing on Termux (Android)

For our mobile users who want to do security assessments on the go, Termux is highly supported.

**Step 1:** Update your Termux packages first:
```bash
pkg update && pkg upgrade -y
```

**Step 2:** Install the required dependencies:
```bash
pkg install python git rust binutils -y
```

**Step 3:** Clone the project and enter the folder:
```bash
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
```

**Step 4:** Install the Python requirements and fetch the wordlists:
```bash
pip install -r requirements.txt
chmod +x fetch_wordlists.sh
./fetch_wordlists.sh
```

**Step 5:** Start CSCAN:
```bash
python cscan.py
```

---

### 🪟 3. Installing on Windows

You can run CSCAN on Windows using Python, or preferably using Windows Subsystem for Linux (WSL) for the best experience. 

**Option A: Using Python directly**
1. Download and install Python from the [official website](https://www.python.org/downloads/). Kindly make sure to check the box that says **"Add Python to PATH"** during installation.
2. Open your Command Prompt (CMD) or PowerShell and clone the repository:
   ```cmd
   git clone https://github.com/charlietech255/cscaner.git
   cd cscaner
   ```
3. Install the requirements:
   ```cmd
   pip install -r requirements.txt
   ```
4. Start the tool:
   ```cmd
   python cscan.py
   ```
*(Note: To get the professional wordlists on Windows, you may need to use Git Bash to run `./fetch_wordlists.sh`)*

**Option B: Using WSL (Highly Recommended)**
If you have WSL installed (Ubuntu on Windows), simply open your WSL terminal and follow the **Linux installation steps** above. It works perfectly!

---

## Usage

CSCAN can be used in two modes:

1. Interactive menu-driven mode:
   ```bash
   python3 cscan.py
   ```

2. Direct non-interactive workflow:
   ```bash
   python3 cscan.py --target https://example.com --module auto
   python3 cscan.py --target https://example.com --module dns
   python3 cscan.py --target https://example.com --module web
   python3 cscan.py --list-modules
   ```

This supports a more disciplined, repeatable usage pattern for assessment work. For a serious workflow, prefer the direct module execution and the exported JSON/text report output.

---

## Reporting

Results can be exported for later review. After a scan, use the export flow in the interactive menu or run a module and save the output in the project reports directory.

The goal is explicit evidence: target, findings, observations, and context captured in a consistent format.

---

## Update and maintenance

Security is always changing, and we frequently update CSCAN with new features and better payloads. To make sure you always have the latest version, kindly do the following:

Open your terminal, go into the CSCAN folder, and pull the latest changes:
```bash
cd cscaner
git pull origin main
```
If we have added new libraries, you may also need to update the requirements:
```bash
pip install -r requirements.txt --upgrade
```

It is a good practice to run `git pull` every week so that you do not miss out on any important security updates.

---

## ⚠️ Important Legal Disclaimer

**Please read this carefully:** CSCAN is an advanced tool that generates real cyber-attacks for testing purposes. You are strictly advised to use this tool **only** on systems that you own, or systems where you have been given explicit, written permission to test (such as bug bounty programs or authorized penetration tests).

Using CSCAN on unauthorized targets is illegal and can lead to serious consequences. Be a professional, act responsibly, and happy hunting!

---
*Developed with dedication for the cybersecurity community.*
