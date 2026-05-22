# CSCAN (C Scanner by Charlie Tech)

**CSCAN** is a cybersecurity scanner and pentesting toolkit made by Charlie Tech. It works great on **Termux** (Android) and also runs smooth on **Kali Linux** and other Debian-based systems.

It comes with an easy-to-use command-line interface, built-in wordlists, plenty of scanning features, and a proper **stealth / WAF-evasion engine** so you can work without raising alarms. Whether you are doing bug bounty hunting, managing servers, or running a pentest — CSCAN has got you sorted.

---

## Features

- **Web Vulnerability Scanning** — Scan for sensitive exposed paths and misconfigurations.
- **HTTP Header Auditing** — Check for security headers and information disclosure.
- **Directory & File Brute Forcing** — Discover hidden directories using custom wordlists.
- **CMS Fingerprinting** — Identify technologies like WordPress, Joomla, Drupal, and more.
- **Reconnaissance Suite** — Subdomain enumeration, DNS/WHOIS lookups, and GeoIP location tracking.
- **Exploitation & Credential Auditing** — Built-in SSH brute-forcer, FTP anonymous login checker, and HTTP Basic Auth brute-forcing.
- **Stealth & WAF Evasion** — Proxy/Tor support, request jitter, User-Agent rotation, path mutation, adaptive backoff, and nmap-integrated timing profiles.
- **Bilingual Support** — Interface available in English and Kiswahili.
- **Extensive Built-in Wordlists** — Pre-loaded with over 1,000+ entries for sensitive paths, subdomains, directory bruteforcing, and credentials.

---

## Installation

### On Termux

CSCAN comes with an installer script that handles everything for you — it checks your environment, installs the dependencies (`python`, `git`, `nmap`, and pip packages), and creates a universal shortcut.

1. **Clone the repo:**
   ```bash
   git clone https://github.com/charlietech255/cscaner.git
   cd cscaner
   ```

2. **Make the installer executable and run it:**
   ```bash
   chmod +x install.sh
   bash install.sh
   ```

3. **Done!**
   The install script maps the tool to your binaries. Once installed, just run it from anywhere.

### On Kali Linux

CSCAN runs natively on Kali. Make sure you have these system packages, then run the installer:

```bash
sudo apt update
sudo apt install python3 python3-pip git nmap -y
chmod +x install.sh
bash install.sh
```

> **Note:** The `nmap` binary is needed for optional SYN/stealth port scans. Root privileges are required for true SYN scans (`-sS`). Without root, CSCAN falls back gracefully to stealth TCP connect scans.

---

## Usage

If you installed using `install.sh`, you can run the tool from anywhere:

```bash
cscan
```

Or run it directly:

```bash
python cscan.py
```

When you launch, you will pick your language, agree to the legal disclaimer, and then you get an interactive menu where you choose what to scan and which module to use.

### Custom Wordlists

By default, CSCAN uses wordlists from the `wordlists/` folder. You can modify, update, or add your own payloads and dictionaries there — it is that simple.

---

## Stealth Mode & WAF Evasion

CSCAN has a proper **Stealth & OPSEC** engine built in to reduce your detection footprint and get past basic WAF rules.

### How to Enable

From the main menu:
- **`[25] Toggle Stealth`** — Quick on/off switch (or press `S` anywhere in the menu).
- **`[24] Stealth Config`** — Fine-tune every stealth parameter.

### Available Stealth Features

| Feature | What it Does |
|---------|-------------|
| **Proxy / Tor Support** | Route all HTTP(S) traffic through `http://`, `socks4://`, or `socks5://` proxies (e.g., Tor at `socks5://127.0.0.1:9050`). |
| **Request Jitter** | Add random delays between requests (`min`–`max` seconds) to avoid rate-limiting and traffic spikes. |
| **Realistic User-Agent Rotation** | Automatically rotate real browser UAs (Chrome, Firefox, Safari, Edge) on every request. |
| **Randomized Headers** | Inject realistic `Referer`, `Accept-Language`, and `X-Forwarded-For` headers to mimic organic traffic. |
| **Path Mutation** | Mutate brute-force paths with URL encoding, double slashes, case variations, and null-byte suffixes to evade simple path filters. |
| **Adaptive Backoff** | If the target returns `403/429/502/503`, CSCAN automatically increases delays to reduce blocking. |
| **Timing Profiles** | Choose scan speed profiles: `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, `insane`. Slower profiles use fewer threads and longer timeouts. |
| **nmap Integration** | Optionally delegate port scans to the system `nmap` binary when available, enabling advanced timing and scan techniques. |
| **SSH Brute Delay** | Introduce per-attempt delays during SSH credential audits when stealth is active. |
| **Cookie Persistence** | Re-use session cookies across requests to behave more like a real browser session. |

### Proxy Example (Tor)

1. Enable stealth `[25]`.
2. Open **Stealth Config `[24]`**.
3. Enter proxy: `socks5://127.0.0.1:9050`.
4. Set jitter (e.g., `1.0` – `3.0` seconds).
5. Choose a timing profile (e.g., `sneaky`).
6. Run any web or network module.

> **Tip:** For Tor on Termux, install Tor with `pkg install tor`, then run `tor` in a separate session before scanning.

---

## How it Works

- **Python is the Boss:** The whole tool is written in Python 3. We use standard libraries plus powerful ones like `requests` for talking to web servers, `paramiko` for testing SSH doors, and `python-whois` to dig up domain secrets.
- **Multithreading:** Python's `ThreadPoolExecutor` is used throughout. Instead of sending one request and waiting, CSCAN sends many requests at the same time. This makes directory brute-forcing and sensitive path scanning really fast.
- **Stealth Engine (`modules/stealth.py`):** A centralized session manager wraps every HTTP request with proxy support, header rotation, jitter, and WAF detection. Network scans inherit timing profiles and can fall back to `nmap` when available.
- **Brute-Forcing:** We use large, carefully selected dictionaries stored in the `wordlists/` folder. CSCAN picks words from these lists and tests them against the target. When stealth mode is on, paths are optionally mutated to bypass naive filters.
- **Smart Reconnaissance:** DNS lookups, WHOIS queries, and GeoIP tracking are performed using both system sockets and public APIs, now routed through your configured proxy when stealth is enabled.
- **Termux Native:** We designed the UI specifically for mobile screens running Termux. Clean terminal color codes and responsive table layouts keep everything readable, even when you are on the go with your phone.

Simply put, CSCAN does all the heavy lifting so you can focus on securing the system. Karibu sana to explore the code!

---

## Testing & Compatibility

CSCAN is tested on:
- **Termux** (Android 12+)
- **Kali Linux** (rolling release, x86_64 & ARM64)

All core features work without root. Advanced SYN scanning via `nmap` requires root privileges (standard for raw sockets on Linux/Android).

---

## Contributing

Contributions, issues, and feature requests are always welcome! If you want to help make CSCAN even better:

1. **Fork** the project.
2. Create your **Feature Branch** (`git checkout -b feature/AmazingFeature`).
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`).
4. **Push** to the branch (`git push origin feature/AmazingFeature`).
5. Open a **Pull Request**.

Please make sure your code follows the existing structure inside the `modules/` directory.

---

## Legal Disclaimer

**CSCAN is designed exclusively for educational purposes and authorized security auditing.**
The creator (Charlie Tech) assumes no liability and is not responsible for any misuse or damage caused by this program. You must make sure you have explicit, documented permission from the target owner before running any scans or attacks.

**Hack Responsibly.**
