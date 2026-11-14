# 🛡️ OSINT Recon Studio v1.4.1
### Native Windows Passive OSINT, Unified Category Hubs & Ultra-Low-RAM Local AI Analyst

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-blue?logo=windows)](https://microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python)](https://python.org)
[![GUI](https://img.shields.io/badge/GUI-PySide6%20%28Qt6%29-green?logo=qt)](https://www.qt.io/)
[![Theme](https://img.shields.io/badge/Themes-Mocha%20%7C%20Monochrome-black)](https://github.com/myrxmayronstudios/osint-recon-studio)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Recon](https://img.shields.io/badge/Recon-Strictly%20Passive-success)](#1-ethical--legal-guardrails)
[![Tests](https://img.shields.io/badge/Tests-41%20Passed%20%28100%25%29-brightgreen)](#6-running-and-testing)
[![Download Release](https://img.shields.io/badge/Download%20v1.4.1-Windows%20x64%20%28.zip%29-brightgreen?logo=windows)](https://github.com/myrxmayronstudios/osint-recon-studio/releases/latest)

**OSINT Recon Studio** is an enterprise-grade native Windows desktop application engineered for defensive security auditors, penetration testers, privacy researchers, and domain owners. It delivers comprehensive attack surface auditing and personal digital footprint auditing through **strictly passive, non-intrusive public queries with zero paid API keys required**.

> 📥 **Quick Download:** Grab the pre-compiled, zero-setup standalone executable from **[Releases v1.4.1](https://github.com/myrxmayronstudios/osint-recon-studio/releases/tag/v1.4.1)**. Extract the zip and run `OSINTReconStudio.exe`!

Featuring a dual-theme graphical interface with instant real-time toggling (`Ctrl+T`) between **Catppuccin Mocha Dark** and **Tactical Monochrome (Pure Grayscale / OLED Black)**, **5 Consolidated Category Hubs**, an **Ultra-Low-RAM (<2 GB RAM) Local AI Intelligence Analyst** with zero-RAM rule-based fallback, **HTTP/2 multiplexing**, **SQLite 24-hour TTL caching** (<50ms repeat lookups), a **Privacy Metadata Scrubber ("Sanitize & Save Clean Copy")**, and multi-format report exports into JSON, Markdown, and standalone HTML.

---

## 1. Ethical & Legal Guardrails

OSINT Recon Studio strictly observes defensive security principles and legal reconnaissance standards:

- **Strictly Passive Reconnaissance:** Queries **only** publicly advertised DNS records, ICANN/IANA RDAP registries, Certificate Transparency (CT) logs, Shodan's free InternetDB endpoint, URLScan.io public search, AlienVault OTX, Ubuntu/MIT PGP keyservers, GitHub public API, standard HTTP response headers, public manifests, and Internet Archive metadata.
- **Zero Offensive Vectors:** Does **NOT** conduct port scanning, directory brute-forcing, SQL injection, credential harvesting, vulnerability exploitation, or unauthorized web scraping.
- **Polite Network Hygiene:** Enforces configurable rate-limiting (default: `2 requests/sec`), strict socket timeouts (`10s`), and a transparent identifying `User-Agent` header (`OSINTReconStudio-PassiveAudit/1.0`).
- **Zero Cloud Leakage for AI:** The intelligence synthesis engine operates 100% offline using local quantized models (Qwen 2.5 1.5B / LLaMA 3.2 1B) via Ollama, or an instantaneous deterministic 0-RAM Heuristic correlation engine.

---

## 2. 5 Consolidated Category Hubs

Rather than navigating dozens of disconnected tabs, OSINT Recon Studio v1.4.0 groups all capabilities into **5 unified, searchable Category Hubs**:

### 🏛️ Hub 1: Executive Overview & AI Dossier
- **Unified Security Scorecard & Risk Metrics:** Overall security posture grade (`A+` through `F`, 0–100 score), risk scorecards, and prioritized defensive findings.
- **Ultra-Low-RAM Local AI Analyst (<2 GB RAM):** Token-by-token streaming executive OSINT intelligence dossier using local 4-bit models (`qwen2.5:1.5b`, `llama3.2:1b`, `qwen2.5:3b`, `phi4-mini`) or zero-RAM deterministic rule-based analysis.
- **Interactive Offline AI Chat:** Ask follow-up remediation questions (`"How do I fix my DMARC record?"`, `"Which open port is most dangerous?"`) 100% locally with zero internet dependency.

### 🌐 Hub 2: Domain & Infrastructure Hub (Merged)
- **Unified Real-Time Search & Filter Bar:** Instant filtering across DNS records, subdomains, takeovers, and ownership.
- **DNS Resource Records:** Standard DNS resolution (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `CAA`) and reverse DNS.
- **Certificate Transparency Subdomain Discovery:** Comprehensive crt.sh log mapping with HackerTarget passive fallback.
- **Dangling CNAMEs & Subdomain Takeover Audit:** Fingerprints orphaned CNAME pointers pointing to abandoned cloud services (AWS S3, GitHub Pages, Heroku, Azure, Netlify, etc.) resolving to `NXDOMAIN`.
- **RDAP / Whois Domain Ownership:** Authoritative ICANN/IANA registry lifecycle, registrar details, and expiration tracking.

### ☁️ Hub 3: Network, Cloud & Threat Exposure Hub (Merged)
- **Shodan InternetDB Passive Exposure:** Passive enumeration of historical open ports, known CVEs, CPE identifiers, and tags with zero packets sent to target ports.
- **IP Geolocation, ASN, BGP & Cloud Fingerprinting:** Maps IPs to Autonomous System Numbers, BGP prefixes, ISPs, and major CDN/cloud providers (Cloudflare, AWS, Azure, GCP, Akamai).
- **Threat Archives (URLScan.io & AlienVault OTX):** Historical passive DNS transitions, ASN shifts, observed IP changes, and public archive links.

### 🛡️ Hub 4: Web & Email Defensive Posture Hub (Merged)
- **Email Anti-Spoofing & Posture Evaluation:** Dedicated spoofing resistance grade (`A` through `F`) evaluating SPF (`-all` vs `~all`), DMARC policy enforcement (`reject`, `quarantine`, `none`), DKIM selectors, and BIMI.
- **HTTP Security Headers & TLS Handshake:** OWASP security headers (`HSTS`, `CSP`, `X-Frame-Options`, `Permissions-Policy`), certificate expiry, and cookie hygiene flags.
- **Technology Stack & Manifests:** Framework and CMS signatures, RFC 9116 `/.well-known/security.txt` disclosure policies, and `/robots.txt` Disallowed entries.
- **Wayback Machine Historical Milestones:** Historical inception date, snapshot frequencies, and CDX timeline milestones.

### 👤 Hub 5: Personal Data & Digital Footprint Hub (Merged & Expanded)
- **Email Breach Analytics & Avatar Leaks:** Queries XposedOrNot public zero-key API for breach names, breach dates, and exposed data classes. Checks Gravatar and OpenPGP keyservers for leaked profiles and avatars.
- **Phone Carrier, VoIP & Messaging Deep Links:** Numbering plan compliance, carrier identification, line type (**Mobile** vs **VoIP/Disposable** vs **Landline**), and clickable verification deep links for WhatsApp (`wa.me`) and Telegram (`t.me`).
- **40+ Platform Social/Handle Matrix:** Passive handle check across developer, social, and gaming networks with OpenGraph title and metadata extraction.
- **Smart Username Permutator & Linkability Risk:** Automatically generates handle variations and calculates cross-platform identity linkability risk (0–100).
- **Document & Photo Privacy Scrubber:** Inspects local media for GPS coordinates and camera serials, featuring a **"Sanitize & Save Clean Copy"** button that strips 100% of metadata.

### 📜 Utility: Live Activity Logs & Raw JSON Inspector
- Real-time color-coded terminal log stream and syntax-formatted raw JSON inspector with one-click clipboard copying and file export.

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
