# CSCAN (C Scanner by Charlie Tech)

**CSCAN** is a professional-grade, interactive cybersecurity reconnaissance and penetration testing toolkit thoughtfully designed specifically for the **Termux** environment.

With an easy-to-navigate command-line interface, built-in wordlists, and comprehensive scanning features, CSCAN provides a powerful suite of tools whether you are doing bug bounty hunting, server administration, or penetration testing.

## ✨ Features

- 🌐 **Web Vulnerability Scanning:** Scan for sensitive exposed paths and misconfigurations.
- 🔐 **HTTP Header Auditing:** Check for security headers and information disclosure.
- 🗂 **Directory & File Brute Forcing:** Discover hidden directories using custom wordlists.
- 🔍 **CMS Fingerprinting:** Identify technologies like WordPress, Joomla, Drupal, and more.
- 🌍 **Reconnaissance Suite:** Subdomain enumeration, DNS/WHOIS lookups, and GeoIP location tracking.
- 💥 **Exploitation & Credential Auditing:** Built-in SSH brute-forcer, FTP anonymous login checker, and HTTP Basic Auth brute-forcing.
- 📖 **Bilingual Support:** Interface available in English and Kiswahili.
- 📚 **Extensive Built-in Wordlists:** Pre-loaded with over 1,000+ entries for sensitive paths, subdomains, directory bruteforcing, and credentials. 

---

## 🚀 Installation (Termux)

CSCAN comes with a specialized installer script that checks your environment, installs necessary dependencies (`python`, `git`, and pip packages), and creates a universal shortcut.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/charlietech255/cscaner.git
   cd cscaner
   ```

2. **Make the installer executable and run it:**
   ```bash
   chmod +x install.sh
   bash install.sh
   ```

3. **Finish Setup:**
   The installation script will automatically map the tool to your binaries. Once installed, simply start the tool from anywhere!

---

## 🛠 Usage

If you installed using the `install.sh` script, you can run the tool globally:

```bash
cscan
```

Alternatively, you can run it manually:

```bash
python cscan.py
```

Upon launching, you will be prompted to select your language and agree to the legal disclaimer, followed by an interactive menu where you can input your target URLs or IPs and select the module you wish to execute.

### Custom Wordlists
By default, the tool pulls wordlists from the `wordlists/` directory. You can easily modify, update, or expand these text files to include your own payloads and dictionaries!

---

## 🧠 How it Works (Technologies & Approaches)

Habari! Welcome to the engine room of CSCAN. If you're wondering how this tool does its magic, pull up a chair. We designed this tool to be very simple but extremely powerful. Here is a breakdown of the techniques and technologies we packed inside:

- **Python is the Boss:** The whole tool is written in Python 3. Python is great because it handles network requests like a pro without complaining. We used standard libraries plus powerful ones like `requests` for talking to web servers, `paramiko` for testing SSH doors, and `python-whois` to dig up domain secrets. 
- **Multithreading (Speeding Things Up):** Nobody likes to wait all day for a scan to finish, right? So, we used Python's `ThreadPoolExecutor`. Basically, instead of sending one request and waiting for a reply, CSCAN sends many requests at the exact same time. This makes our directory brute-forcing and sensitive path scanning move exceptionally fast.
- **Brute-Forcing Approach:** For the brute-forcing part (like checking hidden directories or weak SSH passwords), the approach is very straightforward. We use large, carefully selected dictionaries stored in the `wordlists/` folder. CSCAN sequentially picks words from these lists and tests them against the target. If the server says "200 OK" or lets us login, we catch it and alert you immediately.
- **Smart Reconnaissance:** When we do recon, we don't just make noise. We silently look up DNS records, query WHOIS databases, and even use GeoIP APIs to track down exactly where a target server is actually located on the map.
- **Termux Native:** We tailored the UI specifically for mobile screens running Termux. We used clean terminal color codes and responsive table layouts so that everything looks beautiful and easy to read, even when you are hacking on the go with your phone.

Simply put, CSCAN does all the heavy lifting for you so you can focus on securing the system. Karibu sana to explore the code!

---

## 🤝 Contributing

Contributions, issues, and feature requests are always welcome! If you want to contribute and make CSCAN even better:

1. **Fork** the project.
2. Create your **Feature Branch** (`git checkout -b feature/AmazingFeature`).
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`).
4. **Push** to the branch (`git push origin feature/AmazingFeature`).
5. Open a **Pull Request**.

Please ensure your code follows the existing structure inside the `modules/` directory.

---

## ⚠️ Legal Disclaimer

**CSCAN is designed exclusively for educational purposes and authorized security auditing.** 
The creator (Charlie Tech) assumes no liability and is not responsible for any misuse or damage caused by this program. You must ensure you have explicit, documented permission from the target owner before executing any scans or attacks.  

**Hack Responsibly.**
