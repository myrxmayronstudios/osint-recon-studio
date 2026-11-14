# 🛡️ OSINT Recon Studio v1.3.0
### Native Windows Passive OSINT & Domain Attack Surface Auditing Studio + Personal Privacy Suite

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-blue?logo=windows)](https://microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python)](https://python.org)
[![GUI](https://img.shields.io/badge/GUI-PySide6%20%28Qt6%29-green?logo=qt)](https://www.qt.io/)
[![Theme](https://img.shields.io/badge/Themes-Mocha%20%7C%20Monochrome-black)](https://github.com/myrxmayronstudios/osint-recon-studio)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Recon](https://img.shields.io/badge/Recon-Strictly%20Passive-success)](#1-ethical--legal-guardrails)
[![Tests](https://img.shields.io/badge/Tests-35%20Passed%20%28100%25%29-brightgreen)](#6-running-and-testing)
[![Download Release](https://img.shields.io/badge/Download%20v1.3.0-Windows%20x64%20%28.zip%29-brightgreen?logo=windows)](https://github.com/myrxmayronstudios/osint-recon-studio/releases/latest)

**OSINT Recon Studio** is an enterprise-grade native Windows desktop application engineered for defensive security auditors, penetration testers, privacy researchers, and domain owners. It delivers comprehensive attack surface auditing and personal digital footprint auditing through **strictly passive, non-intrusive public queries with zero paid API keys required**.

> 📥 **Quick Download:** Grab the pre-compiled, zero-setup standalone executable from **[Releases v1.3.0](https://github.com/myrxmayronstudios/osint-recon-studio/releases/tag/v1.3.0)**. Extract the zip and run `OSINTReconStudio.exe`!

Featuring a dual-theme graphical interface with instant real-time toggling (`Ctrl+T`) between **Catppuccin Mocha Dark** and **Tactical Monochrome (Pure Grayscale / OLED Black)**, a responsive left navigation sidebar, 19 specialized intelligence & privacy views, non-blocking asynchronous multi-threading, resilient retry logic with fallbacks, high-DPI crisp rendering, desktop shortcut pinning, bootstrap crash prevention, and multi-format report exports into JSON, Markdown, and standalone HTML.

---

## 1. Ethical & Legal Guardrails

OSINT Recon Studio strictly observes defensive security principles and legal reconnaissance standards:

- **Strictly Passive Reconnaissance:** Queries **only** publicly advertised DNS records, ICANN/IANA RDAP registries, Certificate Transparency (CT) logs, Shodan's free InternetDB endpoint, URLScan.io public search, AlienVault OTX, Ubuntu/MIT PGP keyservers, GitHub public API, standard HTTP response headers, public manifests, and Internet Archive metadata.
- **Zero Offensive Vectors:** Does **NOT** conduct port scanning, directory brute-forcing, SQL injection, credential harvesting, vulnerability exploitation, or unauthorized web scraping.
- **Polite Network Hygiene:** Enforces configurable rate-limiting (default: `2 requests/sec`), strict socket timeouts (`10s`), and a transparent identifying `User-Agent` header (`OSINTReconStudio-PassiveAudit/1.0`).

---

## 2. 19 Modular Intelligence & Privacy Views

### Domain Attack Surface Reconnaissance (Views 1–16)
1. **📊 Executive Overview & Scorecard:** Unified domain security scorecard (Grade A+ to F, 0–100 score), high-level metric cards, and prioritized actionable remediation findings.
2. **🌐 DNS Records & Subdomains:** Standard DNS records (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `CAA`), reverse DNS (PTR), and Certificate Transparency subdomain discovery via `crt.sh` with exponential backoff and HackerTarget passive DNS fallback.
3. **⚡ Dangling CNAMEs & Subdomain Takeovers:** Resolves CNAME records for discovered subdomains, fingerprints cloud providers (GitHub Pages, AWS S3, Heroku, Azure, Shopify, Ghost, Pantheon, Netlify, Vercel, Fly.io, etc.), and flags high-risk dangling DNS pointers that resolve to `NXDOMAIN`.
4. **📋 RDAP & Whois Ownership:** Standardized REST queries across authoritative IANA/ICANN RDAP servers. Lifecycle dates (registration, renewal, expiration), registrar details, abuse contacts, EPP status flags, and privacy proxy detection.
5. **🔍 Passive Exposure (Shodan InternetDB):** Queries Shodan's official, free, zero-key passive lookup endpoint (`https://internetdb.shodan.io/{ip}`) for historical open ports, CPE software identifiers, hostnames, tags, and known CVE references without transmitting a single port-scan packet.
6. **🌍 IP Geolocation, ASN & Cloud:** Resolves public IP addresses to Autonomous System Numbers (ASN), BGP prefix, ISP/Organization, country/city geolocation, and cloud provider identification (Cloudflare, AWS, Azure, GCP, Akamai).
7. **🗄️ Threat History (URLScan.io & AlienVault OTX):** Passively retrieves historical scan records, observed IP address transitions, ASN shifts, page titles, and public scan links.
8. **🛡️ Web Posture & Security Headers:** OWASP security headers analysis (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), TLS certificate handshake inspection (CN, SANs, issuer, protocol, expiry window), and cookie hygiene flags (`Secure`, `HttpOnly`, `SameSite`).
9. **✉️ Email Security Posture:** Dedicated anti-spoofing audit computing an overall Email Spoofing Resistance Grade (`A` through `F`):
   - **SPF:** Validates mechanism enforcement (`-all` vs `~all` vs `?all` vs `+all`), includes chain, and RFC 7208 lookup limits.
   - **DMARC:** Evaluates policy enforcement (`reject`, `quarantine`, `none`), alignment modes, and reporting URIs (`rua`/`ruf`).
   - **DKIM Selectors:** Probes common public selectors (`default`, `google`, `selector1`, `k1`, `mail`, etc.) via DNS.
   - **BIMI & MTA-STS:** Audits Brand Indicators (`_bimi`) and Mail Transfer Agent Strict Transport Security (`_mta-sts` & TLS-RPT).
10. **⚙️ Tech Stack & Manifests:** Passive web technology fingerprinting (CMS, frontend frameworks, CDNs, analytics) from root page headers/HTML, RFC 9116 `/.well-known/security.txt` vulnerability disclosure metadata, and `/robots.txt` Disallowed paths.
11. **🐙 GitHub Org & Code Footprint:** Queries GitHub REST API for public organization/user profile, repository inventory, primary languages, star and fork counts, open issues, topics, and presence of a responsible disclosure `SECURITY.md` policy. Supports optional personal access tokens to elevate rate limits from 60 to 5,000 req/hr.
12. **🔑 Public PGP Keyserver Contacts:** Queries Ubuntu and MIT HKP keyservers (`options=mr`) to passively discover corporate contact names, key IDs, bit lengths, algorithms, and email identities under the target domain.
13. **👤 Brand / Username Footprint:** Sherlock-style passive brand/handle checker across 20 platforms (GitHub, GitLab, Reddit, HackerNews, Dev.to, PyPI, npm, DockerHub, Crates.io, Medium, Vimeo, Keybase, Gravatar, Wikipedia, Bitbucket, SourceForge, Dribbble, Behance, Telegram, Pastebin) using polite concurrency (`asyncio.Semaphore`).
14. **📁 Document Metadata Inspector:** Local file inspector tool (PDF, PNG, JPG, TIFF) and public document URL analyzer using `pypdf` and `Pillow`. Extracts author names, creator software, creation timestamps, and Exif camera/software metadata entirely locally without third-party leaks.
15. **⏳ Wayback Machine History:** Queries Internet Archive Availability and CDX Server APIs for historical inception date, latest snapshot, and sample captures across years.
16. **📜 Live Activity & JSON:** Real-time color-coded terminal log stream and syntax-formatted raw JSON inspector with one-click clipboard copying.

### Personal Digital Footprint & Self-Privacy Exposure Auditor (Views 17–19)
17. **📱 Phone Privacy & SIM Linking:**
    - Uses Google's `phonenumbers` engine to validate numbering plan compliance across all international regions.
    - Generates multi-format standards: E.164 (`+1650...`), RFC 3966 (`tel:+1-650...`), National, and International.
    - Identifies carrier name, line type (**Mobile** vs **VoIP/Disposable** vs **Landline**), and geographic exchange center.
    - Computes a 0–100 Phone Privacy Score (penalizing SIM-swappable mobile numbers without carrier PIN locks) and provides copyable defensive Google search dorks.
18. **📧 Email & Breach Exposure:**
    - Validates RFC syntax and verifies MX routing DNS records.
    - Flags burner / disposable temporary email domains (`mailinator.com`, `temp-mail.org`, etc.).
    - Computes cryptographic MD5 & SHA-256 hashes used by public avatar services.
    - Audits public Gravatar & Libravatar profiles to discover publicly leaked real names, avatars, and linked social accounts.
    - Passively queries the free public XposedOrNot breach API to list historical breach dumps, breach dates, and exposed data classes (passwords, physical addresses, credit cards).
19. **🌐 Social Footprint & Dossier Linkability:**
    - Performs unauthenticated OpenGraph metadata inspections across 8 major social networks (**GitHub, Reddit, YouTube, X/Twitter, LinkedIn, Instagram, TikTok, Facebook**).
    - Extracts `og:title`, `og:description`, and `og:image` without triggering bot blocks or requiring user credentials.
    - Calculates a 0–100 **Dossier Linkability Score** (scoring high when the same handle links personal, professional, and code identities together) with concrete account-hardening recommendations.

---

## 3. Desktop Hardening, Native Icon & Shortcut Pinning

- **Custom Native Windows Icon:** Multi-resolution `app_icon.ico` (16x16, 32x32, 48x48, 64x64, 128x128, 256x256 mipmaps) generated programmatically in `assets/` and embedded in the `.exe`.
- **Windows Taskbar Pinning & AppUserModelID:** Registers `OSINTReconStudio.Desktop.App.1.0` via `SetCurrentProcessExplicitAppUserModelID` so Windows taskbar groups windows cleanly under the custom icon rather than Python's generic interpreter icon.
- **One-Click Desktop Shortcut:**
  - In-app toolbar button: **"📌 Pin Shortcut to Desktop"** creates an instant Windows Shell desktop shortcut.
  - Standalone script: [Create_Desktop_Shortcut.bat](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/Create_Desktop_Shortcut.bat) dynamically locates either the compiled standalone `.exe` or Python launcher.
- **Silent Launch Crash Prevention:**
  - Bootstrap wrapper in `main.py` catches any startup exception, writes complete tracebacks to `crash_log.txt`, and surfaces an interactive native Windows error dialog (`ctypes.windll.user32.MessageBoxW`).
  - Dedicated root launcher [run_app.py](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/run_app.py) ensures reliable module resolution under PyInstaller (`sys._MEIPASS`).
  - Automated `--self-test` CLI mode allows CI/CD and build scripts to verify 100% GUI initialization headlessly.
- **Large Table UI Lag Mitigation:** Safe bulk population helper `populate_table_safely()` disables sorting and updates during table insertion and caps UI view rendering at 2,500 rows while preserving full data for export.
- **Embedded CA Bundle (`certifi`):** Bundles official Mozilla CA certificates directly via PyInstaller (`--collect-data certifi`) so packaged Windows `.exe` binaries never encounter `SSL: CERTIFICATE_VERIFY_FAILED`.
- **IDN / Punycode Normalization:** Normalizes internationalized domains (e.g. `münchen.de` -> `xn--mnchen-3ya.de`) and strips protocols/paths/ports without crashes.
- **Resilient DNS Resolvers:** Uses `dns.resolver.Resolver(configure=False)` with public recursive resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) to avoid corporate router stub timeouts.
- **Table Context Menus:** Right-click context menus on all data tables for "Copy Cell Value", "Copy Entire Row", and "Open Link in Default Browser" (also supported via double-click).
- **Sanitized Filenames:** Export paths are sanitized cross-platform against reserved characters (`<>:"/\|?*`) to prevent Windows `OSError: [Errno 22]`.

---

## 4. Multi-Format Reporting

- **JSON Export (`.json`):** Complete machine-readable data model for automated ingestion into SIEM or vulnerability management tools.
- **Markdown Export (`.md`):** Formatted executive report with scorecard tables, CNAME takeover findings, DNS records, subdomains, and remediation instructions.
- **Standalone HTML Dashboard (`.html`):** Dark-mode self-contained report with zero external CDN dependencies (100% offline-ready). Includes embedded printable CSS (`@media print`) for one-click "Print to PDF".

---

## 5. Configuration (`~/.osint_studio_config.json`)

Click **"⚙ Settings"** in the top bar to configure:
- Polite rate-limiting (requests/second, default `2.0`)
- Network timeout limit (seconds, default `10`)
- Custom User-Agent header
- Optional GitHub Personal Access Token (raises rate limit to 5,000 req/hr)
- Optional free-tier API keys (VirusTotal, URLScan.io, SecurityTrails, Shodan)

---

## 6. Running and Testing

### Quick Launch:
```cmd
run_app.bat
```

### Pin Desktop Shortcut:
Double-click [Create_Desktop_Shortcut.bat](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/Create_Desktop_Shortcut.bat) to place a high-resolution shortcut directly on your Windows Desktop.

### Run with Python:
```powershell
cd C:\Users\balin\.gemini\antigravity\scratch\osint-recon-studio
.\.venv\Scripts\activate
python run_app.py
```

### Compile Standalone Windows Executable (`.exe`):
Double-click [build_windows.bat](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/build_windows.bat) or execute:
```cmd
build_windows.bat
```
Output standalone executable:
`dist\OSINTReconStudio\OSINTReconStudio.exe`

### Quick Launch Options:
* **Desktop Shortcut:** Double-click [OSINT Recon Studio.lnk](file:///C:/Users/balin/Desktop/OSINT%20Recon%20Studio.lnk) on your Windows Desktop.
* **Batch Launcher:** Double-click [OSINTReconStudio.bat](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/OSINTReconStudio.bat) or [run_app.bat](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/run_app.bat).
* **Silent VBS Launcher (No Black Console):** Double-click [OSINTReconStudio.vbs](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/OSINTReconStudio.vbs).

### Switch Visual Themes:
* Press **`Ctrl+T`** or click the **`[🌓 Monochrome]`** button in the top toolbar to toggle between **Catppuccin Mocha Dark** and **Tactical Monochrome (Pure Grayscale / OLED Black)**.

### Run Headless Self-Test:
```cmd
dist\OSINTReconStudio\OSINTReconStudio.exe --self-test
```

### Run Test Suite:
```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```
*(All 35 tests execute 100% offline via deterministic mock fixtures).*

---

## 7. Version Control & GitHub Push

A turnkey automation script [push_to_github.bat](file:///C:/Users/balin/.gemini/antigravity/scratch/osint-recon-studio/push_to_github.bat) is provided to stage, commit, link remote, and push to GitHub:

```cmd
push_to_github.bat "feat: OSINT Recon Studio v1.3.0 release"
```

Or manually:
```cmd
git init -b main
git add .
git commit -m "feat: OSINT Recon Studio v1.3.0 release"
git remote add origin https://github.com/<your-username>/osint-recon-studio.git
git push -u origin main
```
