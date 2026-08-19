# CSCAN Security Framework (v3.0)

**Karibu sana!** Welcome to CSCAN. 

CSCAN is a professional, all-in-one security testing framework designed to make your reconnaissance and vulnerability scanning work easier and more effective. Whether you are a security researcher, a system administrator, or an ethical hacker, CSCAN provides you with the right tools to identify weaknesses in your systems before the bad actors do. 

We have designed CSCAN to be powerful but very simple to use. It handles everything from finding subdomains and gathering open-source intelligence (OSINT) to crawling websites and testing for vulnerabilities like XSS and SQL Injection.

---

## 🌟 Key Features

*   **Deep Web Crawler:** Discovers hidden pages, forms, and parameters automatically.
*   **Active Vulnerability Scanner:** Tests for XSS, SQLi, SSRF, and Command Injection using real data found by the crawler.
*   **Live CVE Mapping:** Checks your server software against the live NIST National Vulnerability Database to see if there are any known bugs.
*   **Passive OSINT Reconnaissance:** Gathers intelligence from free sources (like AlienVault, URLScan, and ThreatCrowd) without ever touching the target directly.
*   **Authenticated Scanning:** Allows you to put your session cookies so you can scan pages that require a login.
*   **Stealth & WAF Evasion:** Built-in techniques to safely bypass basic Web Application Firewalls (WAF) like Cloudflare.

---

## ⚙️ Installation Guide

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

## 🚀 How to Use CSCAN

Using CSCAN is very straightforward. When you run `python3 cscan.py`, you will be greeted by a beautiful, interactive menu.

**Step-by-step Usage:**
1. **Set your target:** Press `T` on your keyboard and enter the website or IP address you want to scan (for example: `example.com`).
2. **Run OSINT (Menu 40):** We advise you to start with passive reconnaissance. This will gather information from public databases without alerting the target.
3. **Run the Web Crawler (Menu 42):** This is a very important step. Let CSCAN spider the website to find all hidden links, forms, and JavaScript secrets.
4. **Configure Authentication (Menu 43):** If the website requires a login, go here to paste your session cookies.
5. **Run Active Scan (Menu 35):** Finally, run the active vulnerability scanner. CSCAN will use the data from the crawler to test for serious bugs.
6. **Auto Scan (Menu 17):** If you are in a hurry, you can choose the Auto Scan option, and CSCAN will run all the necessary steps automatically for you.

---

## 🔄 How to Stay Updated

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
