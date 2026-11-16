"""Report generator supporting structured JSON, GitHub-flavored Markdown, and standalone dark-themed HTML.

Produces professional, executive-ready attack surface audit reports with
zero external network dependencies for complete offline rendering and printing.
"""

from __future__ import annotations

import datetime
import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class ReconExporter:
    """Exports consolidated OSINT reconnaissance data into JSON, Markdown, and HTML formats."""

    @staticmethod
    def _sanitize(val: Any) -> str:
        """Sanitizes text for safe HTML rendering."""
        if val is None:
            return ""
        return html.escape(str(val))

    @classmethod
    def export_json(cls, data: Dict[str, Any], filepath: str) -> None:
        """Writes audit report to formatted JSON file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def export_markdown(cls, data: Dict[str, Any], filepath: str) -> None:
        """Generates an executive-ready Markdown report encompassing all OSINT modules."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        domain = data.get("domain", "Unknown Domain")
        scan_time = data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
        scorecard = data.get("scorecard", {})
        dns_data = data.get("dns", {})
        takeover_data = data.get("takeover", {})
        rdap_data = data.get("rdap", {})
        web_data = data.get("web", {})
        archive_data = data.get("archive", {})
        internetdb_data = data.get("internetdb", {})
        ip_intel_data = data.get("ip_intel", {})
        urlscan_data = data.get("urlscan", {})
        email_sec_data = data.get("email_sec", {})
        tech_data = data.get("tech_stack", {})
        github_data = data.get("github", {})
        pgp_data = data.get("pgp", {})
        user_data = data.get("username", {})

        md: List[str] = []

        md.append(f"# Passive OSINT & Attack Surface Audit: {domain}\n")
        md.append(f"**Audit Timestamp:** `{scan_time}`  ")
        md.append("**Audit Type:** Strictly Passive (Zero Active Port Scans / Zero Attack Injections)  ")
        md.append(f"**Overall Posture Grade:** **{scorecard.get('grade', 'N/A')}** ({scorecard.get('score', 0)}/100)\n")
        md.append("---\n")

        # 1. Executive Summary & Scorecard
        md.append("## 1. Executive Summary & Security Scorecard\n")
        md.append("| Metric | Evaluation | Status |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Overall Security Grade** | {scorecard.get('grade', 'N/A')} ({scorecard.get('score', 0)}/100) | {'PASS' if scorecard.get('score', 0) >= 80 else 'ATTENTION'} |")

        vuln_takeover = takeover_data.get("vulnerable_count", 0)
        md.append(f"| **Subdomain Takeover Risk** | {vuln_takeover} Vulnerable Targets | {'FAIL' if vuln_takeover > 0 else 'PASS'} |")

        email_grade = email_sec_data.get("spoofing_grade", "F")
        md.append(f"| **Email Spoofing Resistance** | Grade {email_grade} ({email_sec_data.get('spoofing_score', 0)}/100) | {'PASS' if email_grade in ('A', 'A+', 'B') else 'WARN'} |")

        spf_status = email_sec_data.get("spf_status") or dns_data.get("spf", {}).get("status", "Missing")
        md.append(f"| **SPF Enforcement** | {spf_status} | {'PASS' if spf_status == 'Strong' else 'WARN'} |")

        dmarc_status = email_sec_data.get("dmarc_status") or dns_data.get("dmarc", {}).get("status", "Missing")
        md.append(f"| **DMARC Policy** | {dmarc_status} (p={email_sec_data.get('dmarc_policy', 'none')}) | {'PASS' if dmarc_status == 'Strong' else 'WARN'} |")

        dnssec_status = dns_data.get("dnssec", {}).get("status", "Disabled")
        md.append(f"| **DNSSEC Integrity** | {dnssec_status} | {'PASS' if 'Active' in str(dnssec_status) else 'WARN'} |")

        tls = web_data.get("tls_certificate", {})
        tls_exp = tls.get("days_until_expiration")
        tls_status_str = f"Expires in {tls_exp} days" if tls_exp is not None else "Unknown"
        md.append(f"| **TLS / SSL Certificate** | {tls.get('issuer_org', 'Unknown')} ({tls_status_str}) | {'FAIL' if tls.get('is_expired') else 'PASS'} |")

        sec_grade = web_data.get("security_grade", "N/A")
        md.append(f"| **Web Security Headers** | Grade {sec_grade} ({web_data.get('security_score', 0)}/100) | {'PASS' if sec_grade in ('A+', 'A') else 'WARN'} |")

        cves = internetdb_data.get("all_cves", [])
        md.append(f"| **Shodan Indexed CVEs** | {len(cves)} Public CVEs | {'FAIL' if len(cves) > 0 else 'PASS'} |")

        clouds = ip_intel_data.get("cloud_providers_detected", [])
        cloud_str = ", ".join(clouds) if clouds else "Direct IP hosting"
        md.append(f"| **Cloud Infrastructure / CDN** | {cloud_str} | INFO |")
        md.append(f"| **CT Subdomains Discovered** | {dns_data.get('subdomain_count', 0)} subdomains | INFO |")
        md.append(f"| **Domain Age** | {rdap_data.get('domain_age_days', 'Unknown')} days | INFO |\n")

        # Actionable Findings
        findings = scorecard.get("findings", [])
        if findings:
            md.append("### Key Audit Findings & Remediation Guidance\n")
            for f in findings:
                severity = f.get("severity", "INFO")
                title = f.get("title", "")
                remed = f.get("remediation", "")
                md.append(f"- **[{severity}]** **{title}**")
                if remed:
                    md.append(f"  - *Remediation:* {remed}")
            md.append("")

        # 2. Dangling CNAMEs & Takeover Audit
        records = takeover_data.get("records", [])
        if records:
            md.append(f"## 2. Dangling CNAMEs & Subdomain Takeover Audit ({len(records)} CNAMEs Analyzed)\n")
            md.append("| Subdomain | CNAME Target | Provider | Status | Risk Level | Description |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for r in records:
                md.append(f"| `{r.get('subdomain')}` | `{r.get('cname_target')}` | {r.get('provider')} | `{r.get('status')}` | **{r.get('risk_level')}** | {r.get('description')} |")
            md.append("")

        # 3. Threat History (URLScan.io & AlienVault OTX)
        scans = urlscan_data.get("urlscan_records", [])
        otx = urlscan_data.get("otx_records", [])
        if scans or otx:
            md.append(f"## 3. Threat Archives & Passive DNS History\n")
            md.append(f"- **Total Historical URLScan Scans Found:** {urlscan_data.get('total_scans_found', 0)}")
            md.append(f"- **Historical IPs Observed:** {', '.join(urlscan_data.get('historical_ips_observed', [])) or 'None'}")
            md.append(f"- **Historical ASNs Observed:** {', '.join(urlscan_data.get('historical_asns_observed', [])) or 'None'}\n")
            if scans:
                md.append("### URLScan.io Records (Recent Samples)\n")
                md.append("| Date | Target URL | IP | ASN | Page Title | Report Link |")
                md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
                for s in scans[:15]:
                    title = (s.get("page_title") or "").replace("|", "-")
                    md.append(f"| {s.get('scan_date', '')[:10]} | `{s.get('target_url')}` | `{s.get('ip')}` | {s.get('asn')} | {title} | [View Scan]({s.get('result_url')}) |")
                md.append("")

        # 4. GitHub Org Footprint
        if github_data.get("entity_type") in ("Organization", "User"):
            md.append(f"## 4. GitHub Footprint: {github_data.get('name', github_data.get('handle'))}\n")
            md.append(f"- **Handle / Type:** `{github_data.get('handle')}` ({github_data.get('entity_type')})")
            md.append(f"- **Public Repositories:** {github_data.get('public_repos_count', 0)}")
            md.append(f"- **Total Stars / Forks:** ⭐ {github_data.get('total_stars', 0)} / 🍴 {github_data.get('total_forks', 0)}")
            md.append(f"- **SECURITY.md Policy:** {'Yes (Configured)' if github_data.get('has_security_policy') else 'No (Missing)'}")
            md.append(f"- **Profile URL:** {github_data.get('html_url')}\n")
            gh_repos = github_data.get("repos", [])
            if gh_repos:
                md.append("### Public Repositories (Recent)\n")
                md.append("| Repository | Language | Stars | Forks | Open Issues | Description |")
                md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
                for r in gh_repos[:12]:
                    desc = (r.get("description") or "").replace("|", "-")
                    md.append(f"| [{r.get('name')}]({r.get('html_url')}) | {r.get('language')} | {r.get('stars')} | {r.get('forks')} | {r.get('open_issues')} | {desc} |")
                md.append("")

        # 5. Public PGP Keyserver Contacts
        pgp_keys = pgp_data.get("keys", [])
        if pgp_keys:
            md.append(f"## 5. Public PGP Keyserver Discovered Contacts ({len(pgp_keys)} keys)\n")
            md.append(f"- **Discovered Domain Emails:** {', '.join(pgp_data.get('domain_specific_emails', [])) or 'None'}\n")
            md.append("| Key ID | Algorithm | Bits | Created | Expires | Identities (Name & Email) |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for k in pgp_keys[:20]:
                uids_str = ", ".join([f"{i.get('name', '')} <{i.get('email', '')}>" for i in k.get("identities", [])])
                md.append(f"| `{k.get('key_id')}` | {k.get('algorithm')} | {k.get('key_length')} | {k.get('created_at')} | {k.get('expires_at')} | {uids_str} |")
            md.append("")

        # 6. Brand / Username Checker
        user_results = user_data.get("results", [])
        if user_results:
            md.append(f"## 6. Brand / Username Footprint across Platforms ({user_data.get('claimed_count', 0)} Claimed)\n")
            md.append("| Platform | Category | Status | URL |")
            md.append("| :--- | :--- | :--- | :--- |")
            for u in user_results:
                md.append(f"| **{u.get('platform')}** | {u.get('category')} | `{u.get('status')}` | [{u.get('profile_url')}]({u.get('profile_url')}) |")
            md.append("")

        # 7. Passive Exposure (InternetDB)
        hosts = internetdb_data.get("hosts", [])
        if hosts:
            md.append("## 7. Passive Attack Surface: Shodan InternetDB\n")
            md.append("| IP Address | Historical Ports | CPE Software Identifiers | Known CVEs |")
            md.append("| :--- | :--- | :--- | :--- |")
            for h in hosts:
                ports = ", ".join(str(p) for p in h.get("ports", [])) or "None"
                cpes = ", ".join(h.get("cpes", [])) or "None"
                cves_str = ", ".join(h.get("vulns", [])) or "None"
                md.append(f"| `{h.get('ip')}` | `{ports}` | `{cpes}` | {cves_str} |")
            md.append("")

        # 8. IP Geolocation, ASN & Cloud
        ips = ip_intel_data.get("ips", [])
        if ips:
            md.append("## 8. IP Geolocation, ASN & Infrastructure\n")
            md.append("| IP Address | Organization / ISP | ASN | Country | City | Cloud / CDN |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for ip_info in ips:
                asn_str = f"AS{ip_info.get('asn')}" if ip_info.get("asn") else "Unknown"
                cloud = ip_info.get("cloud_provider") or "Direct"
                md.append(f"| `{ip_info.get('ip')}` | {ip_info.get('org', ip_info.get('isp', 'Unknown'))} | {asn_str} | {ip_info.get('country')} | {ip_info.get('city')} | {cloud} |")
            md.append("")

        # 9. Email Security Posture
        md.append("## 9. Email Security & Anti-Spoofing Posture\n")
        md.append(f"- **Overall Grade:** Grade {email_sec_data.get('spoofing_grade', 'F')} ({email_sec_data.get('spoofing_score', 0)}/100)")
        md.append(f"- **SPF Record:** `{email_sec_data.get('spf_record', 'None')}` (Enforcement: {email_sec_data.get('spf_status', 'None')})")
        md.append(f"- **DMARC Record:** `{email_sec_data.get('dmarc_record', 'None')}` (Policy: p={email_sec_data.get('dmarc_policy', 'none')})")
        md.append(f"- **BIMI Configured:** {'Yes' if email_sec_data.get('bimi_found') else 'No'}")
        md.append(f"- **MTA-STS Policy:** {'Yes' if email_sec_data.get('mta_sts_found') else 'No'}\n")

        # 10. Web Technologies & Manifests
        techs = tech_data.get("technologies", [])
        if techs:
            md.append("## 10. Web Technologies & Manifests\n")
            md.append("| Technology | Category | Detection Evidence |")
            md.append("| :--- | :--- | :--- |")
            for t in techs:
                md.append(f"| **{t.get('name')}** | {t.get('category')} | `{t.get('evidence')}` |")
            md.append("")

        # 11. RDAP Registration
        md.append("## 11. RDAP Domain Registration Lifecycle\n")
        md.append(f"- **Registrar:** {rdap_data.get('registrar_name', 'Unknown')}")
        md.append(f"- **Created:** {rdap_data.get('created_date', 'Unknown')}")
        md.append(f"- **Expires:** {rdap_data.get('expiration_date', 'Unknown')}")
        md.append(f"- **Privacy Protected:** {'Yes' if rdap_data.get('is_privacy_protected') else 'No'}")
        md.append(f"- **Nameservers:** {', '.join(rdap_data.get('nameservers', [])) or 'None'}\n")

        # 12. Web Security Headers
        headers = web_data.get("security_headers", [])
        if headers:
            md.append("## 12. Web Security Headers\n")
            md.append("| Header | Status | Current Value | Recommendation |")
            md.append("| :--- | :--- | :--- | :--- |")
            for h in headers:
                val = h.get("value", "").replace("|", "\\|")
                md.append(f"| **{h.get('header')}** | `{h.get('status')}` | `{val}` | {h.get('recommendation')} |")
            md.append("")

        # 13. Wayback Machine
        md.append("## 13. Internet Archive (Wayback Machine)\n")
        md.append(f"- **First Recorded Capture:** {archive_data.get('first_seen', 'Never')}")
        md.append(f"- **Latest Recorded Capture:** {archive_data.get('latest_seen', 'Never')}")
        md.append(f"- **Milestone Captures:** {archive_data.get('total_samples', 0)}\n")

        md.append("---\n")
        md.append("*Report generated by OSINT Recon Studio - Strictly Passive Attack Surface Auditing.*")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(md))

    @classmethod
    def export_html(cls, data: Dict[str, Any], filepath: str) -> None:
        """Generates a standalone, dark-themed HTML report with printable styling."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        domain = cls._sanitize(data.get("domain", "Unknown Domain"))
        scan_time = cls._sanitize(data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()))
        scorecard = data.get("scorecard", {})
        dns_data = data.get("dns", {})
        takeover_data = data.get("takeover", {})
        rdap_data = data.get("rdap", {})
        web_data = data.get("web", {})
        archive_data = data.get("archive", {})
        internetdb_data = data.get("internetdb", {})
        ip_intel_data = data.get("ip_intel", {})
        urlscan_data = data.get("urlscan", {})
        email_sec_data = data.get("email_sec", {})
        tech_data = data.get("tech_stack", {})
        github_data = data.get("github", {})
        pgp_data = data.get("pgp", {})
        user_data = data.get("username", {})

        score = scorecard.get("score", 0)
        grade = cls._sanitize(scorecard.get("grade", "N/A"))

        if score >= 90:
            badge_color = "#a6e3a1"
        elif score >= 75:
            badge_color = "#89b4fa"
        elif score >= 60:
            badge_color = "#fab387"
        else:
            badge_color = "#f38ba8"

        html_out: List[str] = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            f"<title>OSINT Recon Studio - {domain}</title>",
            "<style>",
            """
            :root {
                --bg: #1e1e2e;
                --surface: #25273a;
                --surface2: #313244;
                --overlay: #45475a;
                --text: #cdd6f4;
                --subtext: #a6adc8;
                --blue: #89b4fa;
                --green: #a6e3a1;
                --peach: #fab387;
                --red: #f38ba8;
                --mauve: #cba6f7;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                background-color: var(--bg);
                color: var(--text);
                line-height: 1.5;
                padding: 30px;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid var(--overlay);
                padding-bottom: 20px;
                margin-bottom: 25px;
            }
            .header-title h1 { font-size: 26px; color: var(--blue); margin-bottom: 4px; }
            .header-title p { color: var(--subtext); font-size: 13px; }
            .grade-badge {
                display: inline-flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                background: var(--surface2);
                border: 2px solid """ + badge_color + """;
                border-radius: 12px;
                padding: 10px 22px;
                text-align: center;
            }
            .grade-letter { font-size: 32px; font-weight: 800; color: """ + badge_color + """; line-height: 1; }
            .grade-score { font-size: 12px; color: var(--subtext); margin-top: 4px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 25px; }
            .card {
                background: var(--surface);
                border: 1px solid var(--overlay);
                border-radius: 8px;
                padding: 16px;
            }
            .card h3 { font-size: 13px; color: var(--subtext); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
            .card .val { font-size: 17px; font-weight: 600; color: var(--text); }
            .section {
                background: var(--surface);
                border: 1px solid var(--overlay);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 25px;
            }
            .section h2 { font-size: 18px; color: var(--mauve); margin-bottom: 15px; border-bottom: 1px solid var(--overlay); padding-bottom: 8px; }
            table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
            th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--overlay); }
            th { background: var(--surface2); color: var(--subtext); font-weight: 600; }
            tr:hover td { background: rgba(255, 255, 255, 0.02); }
            .badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
            }
            .badge-pass { background: rgba(166, 227, 161, 0.2); color: var(--green); border: 1px solid var(--green); }
            .badge-warn { background: rgba(250, 179, 135, 0.2); color: var(--peach); border: 1px solid var(--peach); }
            .badge-fail { background: rgba(243, 139, 168, 0.2); color: var(--red); border: 1px solid var(--red); }
            .badge-info { background: rgba(137, 180, 250, 0.2); color: var(--blue); border: 1px solid var(--blue); }
            .finding-item {
                border-left: 3px solid var(--blue);
                padding: 10px 15px;
                margin-bottom: 10px;
                background: var(--surface2);
                border-radius: 0 6px 6px 0;
            }
            .finding-item.CRITICAL { border-left-color: #f38ba8; background: rgba(243, 139, 168, 0.1); }
            .finding-item.HIGH { border-left-color: var(--red); }
            .finding-item.MEDIUM { border-left-color: var(--peach); }
            .finding-item.LOW { border-left-color: var(--blue); }
            footer { text-align: center; color: var(--subtext); font-size: 12px; margin-top: 30px; }
            @media print {
                body { background: #fff !important; color: #111 !important; padding: 15px; }
                .card, .section { background: #fff !important; border-color: #ddd !important; }
                th { background: #f0f0f0 !important; color: #333 !important; }
                td { border-color: #eee !important; color: #222 !important; }
                .grade-badge { border-color: #444 !important; background: #fafafa !important; }
                .grade-letter { color: #111 !important; }
            }
            """,
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<header>",
            "<div class='header-title'>",
            f"<h1>Passive OSINT Reconnaissance: {domain}</h1>",
            f"<p>Generated at {scan_time} &bull; Native Windows OSINT Recon Studio</p>",
            "</div>",
            "<div class='grade-badge'>",
            f"<div class='grade-letter'>{grade}</div>",
            f"<div class='grade-score'>{score}/100 Posture</div>",
            "</div>",
            "</header>",
        ]

        # Metric cards
        email_gr = cls._sanitize(email_sec_data.get("spoofing_grade", "F"))
        cves = internetdb_data.get("all_cves", [])
        clouds = ip_intel_data.get("cloud_providers_detected", [])
        cloud_str = ", ".join(clouds) if clouds else "Direct IP"
        vuln_takeover = takeover_data.get("vulnerable_count", 0)

        html_out.extend([
            "<div class='grid'>",
            f"<div class='card'><h3>Takeover Risk</h3><div class='val' style='color:{'#f38ba8' if vuln_takeover > 0 else '#a6e3a1'}'>{vuln_takeover} Vulnerable</div><div style='font-size:12px;color:var(--subtext)'>{takeover_data.get('cname_count', 0)} CNAMEs Analyzed</div></div>",
            f"<div class='card'><h3>Email Spoofing Defense</h3><div class='val'>Grade {email_gr}</div><div style='font-size:12px;color:var(--subtext)'>SPF: {cls._sanitize(email_sec_data.get('spf_status', 'Missing'))} | DMARC: {cls._sanitize(email_sec_data.get('dmarc_status', 'Missing'))}</div></div>",
            f"<div class='card'><h3>Shodan InternetDB</h3><div class='val'>{len(cves)} Indexed CVEs</div><div style='font-size:12px;color:var(--subtext)'>{len(internetdb_data.get('all_open_ports', []))} Historical Ports</div></div>",
            f"<div class='card'><h3>Cloud & Infrastructure</h3><div class='val'>{cls._sanitize(cloud_str)}</div><div style='font-size:12px;color:var(--subtext)'>{cls._sanitize(', '.join(ip_intel_data.get('unique_countries', [])) or 'Unknown')}</div></div>",
            f"<div class='card'><h3>Web Security Headers</h3><div class='val'>Grade {cls._sanitize(web_data.get('security_grade', 'N/A'))}</div><div style='font-size:12px;color:var(--subtext)'>{web_data.get('security_score', 0)}/100 Score</div></div>",
            f"<div class='card'><h3>CT Subdomains</h3><div class='val'>{dns_data.get('subdomain_count', 0)} Discovered</div><div style='font-size:12px;color:var(--subtext)'>Public CT Logs & DNS</div></div>",
            "</div>",
        ])

        # Findings
        findings = scorecard.get("findings", [])
        if findings:
            html_out.append("<div class='section'><h2>Identified Attack Surface Findings</h2>")
            for f in findings:
                sev = cls._sanitize(f.get("severity", "LOW"))
                title = cls._sanitize(f.get("title", ""))
                remed = cls._sanitize(f.get("remediation", ""))
                badge_class = "badge-fail" if sev in ("CRITICAL", "HIGH") else ("badge-warn" if sev == "MEDIUM" else "badge-info")
                html_out.append(f"<div class='finding-item {sev}'><div style='font-weight:600;'><span class='badge {badge_class}'>{sev}</span> {title}</div>")
                if remed:
                    html_out.append(f"<div style='font-size:12px;color:var(--subtext);margin-top:4px;'><b>Remediation:</b> {remed}</div>")
                html_out.append("</div>")
            html_out.append("</div>")

        # Dangling CNAMEs & Takeovers
        records = takeover_data.get("records", [])
        if records:
            html_out.append(f"<div class='section'><h2>Subdomain Takeover & Dangling CNAME Audit ({len(records)} CNAMEs)</h2>")
            html_out.append("<table><thead><tr><th>Subdomain</th><th>CNAME Target</th><th>Provider</th><th>Status</th><th>Risk Level</th><th>Description</th></tr></thead><tbody>")
            for r in records:
                risk = r.get("risk_level", "INFO")
                badge_c = "badge-fail" if risk in ("CRITICAL", "HIGH") else ("badge-warn" if risk == "MEDIUM" else "badge-info")
                html_out.append(f"<tr><td><b>{cls._sanitize(r.get('subdomain'))}</b></td><td><code>{cls._sanitize(r.get('cname_target'))}</code></td><td>{cls._sanitize(r.get('provider'))}</td><td><code>{cls._sanitize(r.get('status'))}</code></td><td><span class='badge {badge_c}'>{risk}</span></td><td>{cls._sanitize(r.get('description'))}</td></tr>")
            html_out.append("</tbody></table></div>")

        # Threat Archives (URLScan)
        scans = urlscan_data.get("urlscan_records", [])
        if scans:
            html_out.append(f"<div class='section'><h2>URLScan.io Historical Scans ({len(scans)} records)</h2>")
            html_out.append("<table><thead><tr><th>Date</th><th>Target URL</th><th>IP</th><th>ASN</th><th>Title</th><th>Link</th></tr></thead><tbody>")
            for s in scans[:15]:
                html_out.append(f"<tr><td>{cls._sanitize(s.get('scan_date', '')[:10])}</td><td><code>{cls._sanitize(s.get('target_url'))}</code></td><td><code>{cls._sanitize(s.get('ip'))}</code></td><td>{cls._sanitize(s.get('asn'))}</td><td>{cls._sanitize(s.get('page_title'))}</td><td><a href='{cls._sanitize(s.get('result_url'))}' target='_blank' style='color:var(--blue);'>Report</a></td></tr>")
            html_out.append("</tbody></table></div>")

        # GitHub Footprint
        if github_data.get("entity_type") in ("Organization", "User"):
            html_out.append(f"<div class='section'><h2>GitHub Footprint: {cls._sanitize(github_data.get('name', github_data.get('handle')))}</h2>")
            html_out.append(f"<p style='color:var(--subtext);margin-bottom:10px;'>Handle: <b>{cls._sanitize(github_data.get('handle'))}</b> &bull; Public Repos: <b>{github_data.get('public_repos_count', 0)}</b> &bull; Stars: <b>⭐ {github_data.get('total_stars', 0)}</b> &bull; SECURITY.md: <b>{'Yes' if github_data.get('has_security_policy') else 'No'}</b></p>")
            gh_repos = github_data.get("repos", [])
            if gh_repos:
                html_out.append("<table><thead><tr><th>Repository</th><th>Language</th><th>Stars</th><th>Forks</th><th>Description</th></tr></thead><tbody>")
                for r in gh_repos[:10]:
                    html_out.append(f"<tr><td><a href='{cls._sanitize(r.get('html_url'))}' target='_blank' style='color:var(--blue);font-weight:600;'>{cls._sanitize(r.get('name'))}</a></td><td>{cls._sanitize(r.get('language'))}</td><td>⭐ {r.get('stars', 0)}</td><td>🍴 {r.get('forks', 0)}</td><td>{cls._sanitize(r.get('description'))}</td></tr>")
                html_out.append("</tbody></table>")
            html_out.append("</div>")

        # Public PGP Keyserver Contacts
        pgp_keys = pgp_data.get("keys", [])
        if pgp_keys:
            html_out.append(f"<div class='section'><h2>Public PGP Keyserver Contacts ({len(pgp_keys)} keys found)</h2>")
            html_out.append("<table><thead><tr><th>Key ID</th><th>Algorithm</th><th>Length</th><th>Created</th><th>Expires</th><th>Associated Identities</th></tr></thead><tbody>")
            for k in pgp_keys[:15]:
                uids_str = "<br>".join([cls._sanitize(f"{i.get('name', '')} <{i.get('email', '')}>") for i in k.get("identities", [])])
                html_out.append(f"<tr><td><code>{cls._sanitize(k.get('key_id'))}</code></td><td>{cls._sanitize(k.get('algorithm'))}</td><td>{k.get('key_length')}</td><td>{cls._sanitize(k.get('created_at'))}</td><td>{cls._sanitize(k.get('expires_at'))}</td><td>{uids_str}</td></tr>")
            html_out.append("</tbody></table></div>")

        # Passive Exposure (InternetDB)
        hosts = internetdb_data.get("hosts", [])
        if hosts:
            html_out.append("<div class='section'><h2>Passive Exposure: Shodan InternetDB Services</h2>")
            html_out.append("<table><thead><tr><th>IP Address</th><th>Historical Open Ports</th><th>CPE Identifiers</th><th>Indexed CVEs</th></tr></thead><tbody>")
            for h in hosts:
                ports = ", ".join(str(p) for p in h.get("ports", [])) or "None"
                cpes = "<br>".join(cls._sanitize(c) for c in h.get("cpes", [])) or "None"
                cves_str = ", ".join(cls._sanitize(v) for v in h.get("vulns", [])) or "None"
                html_out.append(f"<tr><td><code>{cls._sanitize(h.get('ip'))}</code></td><td><code>{cls._sanitize(ports)}</code></td><td>{cpes}</td><td>{cves_str}</td></tr>")
            html_out.append("</tbody></table></div>")

        # Web Technologies
        techs = tech_data.get("technologies", [])
        if techs:
            html_out.append("<div class='section'><h2>Fingerprinted Web Technologies</h2>")
            html_out.append("<table><thead><tr><th>Technology</th><th>Category</th><th>Evidence</th></tr></thead><tbody>")
            for t in techs:
                html_out.append(f"<tr><td><b>{cls._sanitize(t.get('name'))}</b></td><td>{cls._sanitize(t.get('category'))}</td><td>{cls._sanitize(t.get('evidence'))}</td></tr>")
            html_out.append("</tbody></table></div>")

        # Security Headers
        headers = web_data.get("security_headers", [])
        if headers:
            html_out.append("<div class='section'><h2>HTTP Security Headers Audit</h2>")
            html_out.append("<table><thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Guidance</th></tr></thead><tbody>")
            for h in headers:
                stat_raw = h.get("status", "FAIL")
                badge_class = "badge-pass" if stat_raw == "PASS" else ("badge-warn" if stat_raw == "WARN" else "badge-fail")
                html_out.append(f"<tr><td><b>{cls._sanitize(h.get('header'))}</b></td><td><span class='badge {badge_class}'>{cls._sanitize(stat_raw)}</span></td><td><code>{cls._sanitize(h.get('value'))}</code></td><td>{cls._sanitize(h.get('recommendation'))}</td></tr>")
            html_out.append("</tbody></table></div>")

        # DNS Records
        records = dns_data.get("records", [])
        if records:
            html_out.append(f"<div class='section'><h2>DNS Records ({len(records)} entries)</h2>")
            html_out.append("<table><thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr></thead><tbody>")
            for r in records:
                html_out.append(f"<tr><td><span class='badge badge-info'>{cls._sanitize(r.get('record_type'))}</span></td><td>{cls._sanitize(r.get('name'))}</td><td><code>{cls._sanitize(r.get('value'))}</code></td><td>{r.get('ttl')}s</td></tr>")
            html_out.append("</tbody></table></div>")

        html_out.append("<footer>OSINT Recon Studio &bull; Passive Attack Surface Auditing</footer></div></body></html>")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_out))


# Alias for backward compatibility and test diagnostics
Exporter = ReconExporter
