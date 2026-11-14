"""Background concurrency management using PySide6 QRunnable and QThreadPool.

Executes passive network queries asynchronously while strictly enforcing configurable
rate-limiting, request timeouts, threading.Event cancellation, and transparent User-Agent headers.
Guarantees 100% thread safety by communicating solely through Qt Signals with zero direct UI widget access.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from PySide6.QtCore import QObject, QRunnable, Signal

from osint_studio.core.archive_engine import ArchiveEngine
from osint_studio.core.cache_manager import get_cached, set_cached
from osint_studio.core.dns_engine import DNSEngine
from osint_studio.core.domain_utils import normalize_domain
from osint_studio.core.email_security_engine import EmailSecurityEngine
from osint_studio.core.github_osint_engine import audit_github_footprint
from osint_studio.core.internetdb_engine import InternetDBEngine
from osint_studio.core.ip_intel_engine import IPIntelEngine
from osint_studio.core.local_llm_engine import DEFAULT_OLLAMA_BASE_URL, pull_model_stream
from osint_studio.core.pgp_osint_engine import search_pgp_keys
from osint_studio.core.rdap_engine import RDAPEngine
from osint_studio.core.takeover_audit_engine import audit_subdomain_takeover
from osint_studio.core.tech_stack_engine import TechStackEngine
from osint_studio.core.urlscan_engine import search_threat_archives
from osint_studio.core.username_engine import check_brand_handles
from osint_studio.core.web_engine import WebEngine

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"


class WorkerSignals(QObject):
    """Signals bridge for background reconnaissance worker."""
    started = Signal(str)                          # domain
    progress = Signal(str, int)                    # stage_description, percentage (0-100)
    log = Signal(str, str)                         # level (INFO, SUCCESS, WARNING, ERROR), message
    module_complete = Signal(str, dict)            # module_name, data_dict
    error = Signal(str, str)                       # module_name, error_description
    finished = Signal(dict)                        # consolidated_report_dict


class ReconWorker(QRunnable):
    """Asynchronous worker executing passive intelligence collection pipelines."""

    def __init__(
        self,
        domain: str,
        enabled_modules: Optional[Dict[str, bool]] = None,
        rate_limit_rps: float = 2.0,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
        github_token: str = "",
        force_refresh: bool = False,
    ) -> None:
        super().__init__()
        self.domain = normalize_domain(domain)
        self.enabled_modules = enabled_modules or {
            "dns": True,
            "ct": True,
            "takeover": True,
            "rdap": True,
            "web": True,
            "archive": True,
            "internetdb": True,
            "ip_intel": True,
            "urlscan": True,
            "email_sec": True,
            "tech_stack": True,
            "github": True,
            "pgp": True,
            "username": True,
        }
        self.rate_limit_rps = max(0.2, min(10.0, rate_limit_rps))
        self.timeout = max(2.0, min(60.0, timeout))
        self.user_agent = user_agent
        self.github_token = github_token
        self.force_refresh = force_refresh
        self.signals = WorkerSignals()
        self.cancel_event = threading.Event()
        self.setAutoDelete(True)

    def cancel(self) -> None:
        """Sets cancellation event flag to cleanly halt in-flight loops."""
        self.cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def _sleep_rate_limit(self) -> None:
        """Enforces polite inter-request delay while monitoring cancellation event."""
        delay = 1.0 / self.rate_limit_rps
        end_time = time.time() + delay
        while time.time() < end_time:
            if self.is_cancelled:
                break
            time.sleep(0.05)

    def _execute_with_cache(
        self,
        module_name: str,
        cache_key: str,
        fetch_fn: Callable[[], Dict[str, Any]],
        ttl_hours: float = 24.0,
    ) -> Dict[str, Any]:
        """Loads cached intelligence or executes fetch and persists to SQLite TTL cache."""
        if not self.force_refresh:
            cached = get_cached(cache_key)
            if cached is not None:
                self.signals.log.emit("INFO", f"⚡ [Cache Hit] Loaded {module_name} (<5ms)")
                return cached
        res = fetch_fn()
        if res:
            try:
                set_cached(cache_key, res, ttl_hours=ttl_hours)
            except Exception as e:
                logger.debug("Cache store failed for %s: %s", cache_key, e)
        return res

    def _calculate_scorecard(
        self,
        dns_dict: Dict[str, Any],
        rdap_dict: Dict[str, Any],
        web_dict: Dict[str, Any],
        internetdb_dict: Dict[str, Any],
        email_sec_dict: Dict[str, Any],
        takeover_dict: Dict[str, Any],
        github_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Calculates consolidated domain security posture score and actionable findings."""
        score = 100
        findings: List[Dict[str, str]] = []

        # 1. Subdomain Takeover Vulnerability (Critical)
        vuln_takeover = takeover_dict.get("vulnerable_count", 0)
        dangling_count = takeover_dict.get("dangling_count", 0)
        if vuln_takeover > 0:
            score -= 30
            findings.append({
                "severity": "CRITICAL",
                "title": f"Subdomain Takeover Detected ({vuln_takeover} Dangling Cloud CNAMEs)",
                "remediation": "Immediately re-provision or delete the dangling DNS CNAME records to prevent takeover by unauthorized third parties.",
            })
        elif dangling_count > 0:
            score -= 15
            findings.append({
                "severity": "HIGH",
                "title": f"Dangling CNAME Records Found ({dangling_count} pointers resolving to NXDOMAIN)",
                "remediation": "Audit CNAME records pointing to decommissioned hosts and remove dead DNS aliases.",
            })

        # 2. Email Anti-Spoofing (DMARC & SPF)
        dmarc_policy = email_sec_dict.get("dmarc_policy", "missing").lower()
        spf_status = email_sec_dict.get("spf_status", "missing").lower()

        if dmarc_policy in ("missing", "none", "unknown"):
            deduct = 20 if dmarc_policy == "missing" else 10
            score -= deduct
            findings.append({
                "severity": "HIGH" if dmarc_policy == "missing" else "MEDIUM",
                "title": f"DMARC Policy is {dmarc_policy.upper()}",
                "remediation": "Configure a strict DMARC TXT record (_dmarc.domain) with 'p=reject' or 'p=quarantine'.",
            })

        if spf_status in ("missing", "neutral (?all)", "+all"):
            score -= 15
            findings.append({
                "severity": "HIGH" if spf_status == "missing" else "MEDIUM",
                "title": f"SPF Record is {spf_status.upper()}",
                "remediation": "Publish a valid v=spf1 record with strict enforcement mechanism '-all' (HardFail).",
            })

        # 3. Web Security Headers
        missing_headers = web_dict.get("missing_headers", [])
        if "Strict-Transport-Security" in missing_headers:
            score -= 10
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing HSTS Header (Strict-Transport-Security)",
                "remediation": "Enable HSTS with max-age >= 31536000 and includeSubDomains to prevent SSL stripping.",
            })
        if "Content-Security-Policy" in missing_headers:
            score -= 5
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing Content-Security-Policy (CSP)",
                "remediation": "Implement a restrictive CSP to mitigate Cross-Site Scripting (XSS) and code injection.",
            })

        # 4. TLS Certificate Expiration
        tls = web_dict.get("tls_certificate", {})
        if tls.get("is_expired"):
            score -= 25
            findings.append({
                "severity": "CRITICAL",
                "title": "SSL/TLS Certificate is Expired",
                "remediation": "Immediately renew and rebind the SSL/TLS certificate.",
            })
        elif tls.get("days_until_expiration") is not None and tls.get("days_until_expiration", 100) < 30:
            score -= 5
            findings.append({
                "severity": "MEDIUM",
                "title": f"TLS Certificate Expiring Soon ({tls.get('days_until_expiration')} days left)",
                "remediation": "Schedule certificate renewal before expiration.",
            })

        # 5. Passive Exposure (InternetDB CVEs)
        cves = internetdb_dict.get("all_cves", [])
        if cves:
            score -= min(25, len(cves) * 5)
            findings.append({
                "severity": "HIGH",
                "title": f"Public CVEs Linked to IP Assets ({len(cves)} CVEs indexed in Shodan)",
                "remediation": f"Audit exposed services. Referenced CVEs: {', '.join(cves[:5])}",
            })

        # 6. Domain Expiration
        days_exp = rdap_dict.get("days_until_expiration")
        if days_exp is not None and days_exp < 30:
            findings.append({
                "severity": "HIGH" if days_exp < 7 else "MEDIUM",
                "title": f"Domain Registration Expiring in {days_exp} Days",
                "remediation": "Enable registrar auto-renew to avoid domain loss or hijack.",
            })

        # 7. GitHub Security Policy
        if github_dict.get("entity_type") in ("Organization", "User") and not github_dict.get("has_security_policy"):
            score -= 5
            findings.append({
                "severity": "LOW",
                "title": "Missing GitHub SECURITY.md Vulnerability Policy",
                "remediation": "Publish a SECURITY.md file in the organization or .github repository to document coordinated disclosure.",
            })

        score = max(0, min(100, score))
        if score >= 90:
            grade = "A+" if score >= 95 else "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": score,
            "grade": grade,
            "findings": findings,
        }

    def run(self) -> None:
        """Executes full multi-module reconnaissance pipeline."""
        self.signals.started.emit(self.domain)
        self.signals.log.emit("INFO", f"Initiating passive reconnaissance for target: {self.domain}")
        self.signals.log.emit(
            "INFO",
            f"Rate limit: {self.rate_limit_rps} req/sec, Timeout: {self.timeout}s, User-Agent: {self.user_agent}",
        )

        consolidated: Dict[str, Any] = {
            "domain": self.domain,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "dns": {},
            "takeover": {},
            "rdap": {},
            "web": {},
            "archive": {},
            "internetdb": {},
            "ip_intel": {},
            "urlscan": {},
            "email_sec": {},
            "tech_stack": {},
            "github": {},
            "pgp": {},
            "username": {},
            "scorecard": {},
        }

        try:
            resolved_ips: List[str] = []
            discovered_subdomains: List[str] = []

            # 1. DNS Reconnaissance & Certificate Transparency
            if self.enabled_modules.get("dns", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Resolving DNS records & querying Certificate Transparency...", 8)
                include_ct = self.enabled_modules.get("ct", True)

                def _fetch_dns() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Resolving standard DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA)...")
                    dns_eng = DNSEngine(timeout=self.timeout, user_agent=self.user_agent)
                    dns_report = dns_eng.analyze(self.domain, include_ct=include_ct)
                    return dns_report.to_dict()

                dns_dict = self._execute_with_cache("dns", f"dns:{self.domain}:{include_ct}", _fetch_dns)
                consolidated["dns"] = dns_dict
                resolved_ips = dns_dict.get("resolved_ips", [])
                discovered_subdomains = dns_dict.get("subdomains", [])

                self.signals.module_complete.emit("dns", dns_dict)
                self.signals.log.emit(
                    "SUCCESS",
                    f"Discovered {len(dns_dict.get('records', {}))} DNS records, {len(resolved_ips)} IP addresses.",
                )
                if include_ct:
                    self.signals.log.emit(
                        "SUCCESS",
                        f"Discovered {len(discovered_subdomains)} subdomains via CT logs & passive DNS fallback.",
                    )

                self._sleep_rate_limit()

            # 2. Dangling CNAMEs & Subdomain Takeover Audit
            if self.enabled_modules.get("takeover", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Auditing CNAME pointers for subdomain takeover risks...", 16)

                def _fetch_takeover() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Fingerprinting cloud CNAME targets (AWS, Azure, GitHub, Heroku, etc.)...")
                    takeover_report = audit_subdomain_takeover(
                        self.domain,
                        subdomains=discovered_subdomains,
                        timeout=min(5.0, self.timeout),
                    )
                    return takeover_report.to_dict()

                takeover_dict = self._execute_with_cache("takeover", f"takeover:{self.domain}", _fetch_takeover)
                consolidated["takeover"] = takeover_dict

                self.signals.module_complete.emit("takeover", takeover_dict)
                vuln_count = takeover_dict.get("vulnerable_count", 0)
                if vuln_count > 0:
                    self.signals.log.emit(
                        "ERROR",
                        f"CRITICAL: {vuln_count} potential subdomain takeover vulnerability detected!",
                    )
                else:
                    self.signals.log.emit(
                        "SUCCESS",
                        f"Takeover audit complete: Checked {takeover_dict.get('total_checked', 0)} hosts. {takeover_dict.get('cname_count', 0)} CNAMEs, {vuln_count} vulnerable.",
                    )

                self._sleep_rate_limit()

            # 3. RDAP Registration Metadata
            if self.enabled_modules.get("rdap", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Querying Registration Data Access Protocol (RDAP)...", 24)

                def _fetch_rdap() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Fetching registration lifecycle and registrar metadata via RDAP...")
                    rdap_eng = RDAPEngine(timeout=self.timeout, user_agent=self.user_agent)
                    rdap_report = rdap_eng.query(self.domain)
                    return rdap_report.to_dict()

                rdap_dict = self._execute_with_cache("rdap", f"rdap:{self.domain}", _fetch_rdap)
                consolidated["rdap"] = rdap_dict

                self.signals.module_complete.emit("rdap", rdap_dict)
                if rdap_dict.get("is_success"):
                    self.signals.log.emit(
                        "SUCCESS",
                        f"RDAP data retrieved: Registrar '{rdap_dict.get('registrar_name', 'N/A')}', Created: {rdap_dict.get('created_date') or 'N/A'}",
                    )

                self._sleep_rate_limit()

            # 4. Web & Security Headers
            if self.enabled_modules.get("web", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Inspecting HTTP response headers & TLS certificate...", 32)

                def _fetch_web() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Performing polite HTTP headers and TLS certificate handshake...")
                    web_eng = WebEngine(timeout=self.timeout, user_agent=self.user_agent)
                    web_report = web_eng.analyze(self.domain)
                    return web_report.to_dict()

                web_dict = self._execute_with_cache("web", f"web:{self.domain}", _fetch_web)
                consolidated["web"] = web_dict

                self.signals.module_complete.emit("web", web_dict)
                if web_dict.get("is_success"):
                    self.signals.log.emit(
                        "SUCCESS",
                        f"Web audit complete: HTTP {web_dict.get('status_code')}, Security Grade: {web_dict.get('security_grade')} ({web_dict.get('security_score')}/100)",
                    )

                self._sleep_rate_limit()

            # 5. Wayback Machine History
            if self.enabled_modules.get("archive", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Checking Internet Archive (Wayback Machine) footprint...", 40)

                def _fetch_archive() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Querying Wayback Machine availability and historical milestones...")
                    archive_eng = ArchiveEngine(timeout=self.timeout, user_agent=self.user_agent)
                    archive_report = archive_eng.analyze(self.domain)
                    return archive_report.to_dict()

                archive_dict = self._execute_with_cache("archive", f"archive:{self.domain}", _fetch_archive)
                consolidated["archive"] = archive_dict

                self.signals.module_complete.emit("archive", archive_dict)
                if archive_dict.get("is_archived"):
                    self.signals.log.emit(
                        "SUCCESS",
                        f"Wayback footprint found: First recorded {archive_dict.get('first_seen')}, Samples: {archive_dict.get('total_samples')}",
                    )

                self._sleep_rate_limit()

            # 6. Passive Exposure (Shodan InternetDB)
            if self.enabled_modules.get("internetdb", True) and resolved_ips:
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Querying Shodan InternetDB for passive exposure...", 48)

                def _fetch_internetdb() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Passively checking Shodan InternetDB for open ports and CVEs...")
                    idb_eng = InternetDBEngine(timeout=self.timeout, user_agent=self.user_agent)
                    idb_report = idb_eng.analyze(self.domain, resolved_ips)
                    return idb_report.to_dict()

                idb_dict = self._execute_with_cache("internetdb", f"internetdb:{resolved_ips[0]}", _fetch_internetdb)
                consolidated["internetdb"] = idb_dict

                self.signals.module_complete.emit("internetdb", idb_dict)
                self.signals.log.emit(
                    "SUCCESS",
                    f"InternetDB lookup: {len(idb_dict.get('all_open_ports', []))} ports, {len(idb_dict.get('all_cves', []))} CVEs indexed.",
                )

                self._sleep_rate_limit()

            # 7. IP Geolocation, ASN & Cloud Provider
            if self.enabled_modules.get("ip_intel", True) and resolved_ips:
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Gathering IP Geolocation, ASN, and Cloud info...", 56)

                def _fetch_ip_intel() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Fingerprinting ASN, ISP, country, and CDN/cloud providers...")
                    ip_eng = IPIntelEngine(timeout=self.timeout, user_agent=self.user_agent)
                    ip_report = ip_eng.analyze(self.domain, resolved_ips)
                    return ip_report.to_dict()

                ip_dict = self._execute_with_cache("ip_intel", f"ip_intel:{self.domain}", _fetch_ip_intel)
                consolidated["ip_intel"] = ip_dict

                self.signals.module_complete.emit("ip_intel", ip_dict)
                cloud_str = f"Behind {', '.join(ip_dict.get('cloud_providers_detected', []))}" if ip_dict.get("is_behind_cdn_or_cloud") else "Direct IP hosting"
                self.signals.log.emit("SUCCESS", f"IP Geolocation: {', '.join(ip_dict.get('unique_countries', [])) or 'Unknown'} | {cloud_str}")

                self._sleep_rate_limit()

            # 8. Threat Archives (URLScan.io & AlienVault OTX)
            if self.enabled_modules.get("urlscan", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Searching URLScan.io and AlienVault OTX threat archives...", 64)

                def _fetch_urlscan() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Retrieving historical passive DNS shifts and URLScan.io records...")
                    urlscan_report = search_threat_archives(self.domain, timeout=self.timeout)
                    return urlscan_report.to_dict()

                urlscan_dict = self._execute_with_cache("urlscan", f"urlscan:{self.domain}", _fetch_urlscan)
                consolidated["urlscan"] = urlscan_dict

                self.signals.module_complete.emit("urlscan", urlscan_dict)
                self.signals.log.emit(
                    "SUCCESS",
                    f"Threat archives: Found {urlscan_dict.get('total_scans_found', 0)} historical scans, {len(urlscan_dict.get('historical_ips_observed', []))} observed IPs.",
                )

                self._sleep_rate_limit()

            # 9. Email Security & Anti-Spoofing Posture
            if self.enabled_modules.get("email_sec", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Auditing Email Security & Anti-Spoofing Posture...", 72)

                def _fetch_email_sec() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Evaluating SPF, DMARC, DKIM selectors, BIMI, and MTA-STS...")
                    em_eng = EmailSecurityEngine(timeout=self.timeout)
                    em_report = em_eng.analyze(self.domain)
                    return em_report.to_dict()

                em_dict = self._execute_with_cache("email_sec", f"email_sec:{self.domain}", _fetch_email_sec)
                consolidated["email_sec"] = em_dict

                self.signals.module_complete.emit("email_sec", em_dict)
                self.signals.log.emit(
                    "SUCCESS",
                    f"Email Security: Grade {em_dict.get('spoofing_grade')} ({em_dict.get('spoofing_score')}/100) | SPF: {em_dict.get('spf_status')}, DMARC: {em_dict.get('dmarc_policy')}",
                )

                self._sleep_rate_limit()

            # 10. Web Technology Stack & Manifests
            if self.enabled_modules.get("tech_stack", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Auditing Technology Stack & Manifests...", 80)

                def _fetch_tech() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Checking security.txt, robots.txt, and technology signatures...")
                    tech_eng = TechStackEngine(timeout=self.timeout, user_agent=self.user_agent)
                    tech_report = tech_eng.analyze(self.domain)
                    return tech_report.to_dict()

                tech_dict = self._execute_with_cache("tech_stack", f"tech:{self.domain}", _fetch_tech)
                consolidated["tech_stack"] = tech_dict

                self.signals.module_complete.emit("tech_stack", tech_dict)
                sec_str = "Found" if tech_dict.get("security_txt", {}).get("found") else "Missing"
                self.signals.log.emit(
                    "SUCCESS",
                    f"Discovered {len(tech_dict.get('technologies', []))} technologies. security.txt: {sec_str}.",
                )

                self._sleep_rate_limit()

            # 11. GitHub Organization & Code Footprint
            if self.enabled_modules.get("github", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Auditing GitHub Organization & public repositories...", 86)

                def _fetch_github() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Querying GitHub public REST API for org profile and repos...")
                    gh_report = audit_github_footprint(self.domain, token=self.github_token, timeout=self.timeout)
                    return gh_report.to_dict()

                gh_dict = self._execute_with_cache("github", f"github:{self.domain}", _fetch_github)
                consolidated["github"] = gh_dict

                self.signals.module_complete.emit("github", gh_dict)
                sec_status = "SECURITY.md present" if gh_dict.get("has_security_policy") else "No SECURITY.md"
                self.signals.log.emit(
                    "SUCCESS",
                    f"GitHub: {gh_dict.get('entity_type')} '{gh_dict.get('handle')}' ({gh_dict.get('public_repos_count')} repos, {gh_dict.get('total_stars')} stars, {sec_status}).",
                )

                self._sleep_rate_limit()

            # 12. Public PGP Keyserver Contacts
            if self.enabled_modules.get("pgp", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Searching public PGP keyservers for corporate contacts...", 92)

                def _fetch_pgp() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Querying Ubuntu/MIT HKP keyservers for public keys and emails...")
                    pgp_report = search_pgp_keys(self.domain, timeout=self.timeout)
                    return pgp_report.to_dict()

                pgp_dict = self._execute_with_cache("pgp", f"pgp:{self.domain}", _fetch_pgp)
                consolidated["pgp"] = pgp_dict

                self.signals.module_complete.emit("pgp", pgp_dict)
                self.signals.log.emit(
                    "SUCCESS",
                    f"PGP Keyservers: Found {pgp_dict.get('total_keys', 0)} keys and {len(pgp_dict.get('domain_specific_emails', []))} domain-specific email identities.",
                )

                self._sleep_rate_limit()

            # 13. Brand & Username Checker
            if self.enabled_modules.get("username", True):
                if self.is_cancelled:
                    self.signals.log.emit("WARNING", "Reconnaissance cancelled by user.")
                    return

                self.signals.progress.emit("Checking brand name / handle across 20 platforms...", 96)

                def _fetch_username() -> Dict[str, Any]:
                    self.signals.log.emit("INFO", "Auditing social, developer, and registry presence across 20 platforms...")
                    user_report = check_brand_handles(self.domain, timeout=self.timeout)
                    return user_report.to_dict()

                user_dict = self._execute_with_cache("username", f"username:{self.domain}", _fetch_username)
                consolidated["username"] = user_dict

                self.signals.module_complete.emit("username", user_dict)
                self.signals.log.emit(
                    "SUCCESS",
                    f"Brand Checker: {user_dict.get('claimed_count', 0)} claimed / {user_dict.get('available_count', 0)} available out of {user_dict.get('total_checked', 0)} platforms.",
                )
                consolidated["username"] = user_dict

                self.signals.module_complete.emit("username", user_dict)
                self.signals.log.emit(
                    "SUCCESS",
                    f"Brand Checker: {user_report.claimed_count} claimed / {user_report.available_count} available out of {user_report.total_checked} platforms.",
                )

            # 14. Consolidated Scorecard
            self.signals.progress.emit("Synthesizing consolidated security scorecard...", 98)
            scorecard = self._calculate_scorecard(
                consolidated["dns"],
                consolidated["rdap"],
                consolidated["web"],
                consolidated["internetdb"],
                consolidated["email_sec"],
                consolidated["takeover"],
                consolidated["github"],
            )
            consolidated["scorecard"] = scorecard

            self.signals.progress.emit("Passive reconnaissance complete.", 100)
            self.signals.log.emit(
                "SUCCESS",
                f"Audit completed. Overall Posture Score: {scorecard['grade']} ({scorecard['score']}/100). Found {len(scorecard['findings'])} action items.",
            )

            self.signals.finished.emit(consolidated)

        except Exception as e:
            logger.exception("Unexpected error in ReconWorker")
            self.signals.error.emit("worker", f"Fatal reconnaissance pipeline error: {str(e)}")
            self.signals.log.emit("ERROR", f"Fatal error: {str(e)}")


class TaskSignals(QObject):
    """Signals for generic asynchronous task worker."""
    started = Signal()
    finished = Signal(object)
    error = Signal(str)


class AsyncTaskWorker(QRunnable):
    """Executes an isolated audit task (username check, github lookup, privacy audit) in background.

    Guarantees 100% responsive GUI by offloading blocking network calls and CPU tasks
    away from the PySide6 main Qt thread.
    """

    def __init__(self, fn: Callable, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = TaskSignals()
        self.setAutoDelete(True)

    def run(self) -> None:
        try:
            try:
                self.signals.started.emit()
            except RuntimeError:
                pass
            res = self.fn(*self.args, **self.kwargs)
            try:
                self.signals.finished.emit(res)
            except RuntimeError:
                pass
        except Exception as exc:
            logger.exception("Error executing async task worker")
            try:
                self.signals.error.emit(str(exc))
            except RuntimeError:
                pass


class LLMStreamSignals(QObject):
    """Signals for streaming local LLM generation to the GUI."""
    started = Signal()
    token = Signal(str)
    finished = Signal(str)
    error = Signal(str)


class LLMStreamWorker(QRunnable):
    """Runs an asynchronous token generator inside a thread worker."""

    def __init__(self, gen_factory: Callable[[], Any]) -> None:
        super().__init__()
        self.gen_factory = gen_factory
        self.signals = LLMStreamSignals()
        self.setAutoDelete(True)

    def run(self) -> None:
        async def _run_stream() -> None:
            self.signals.started.emit()
            collected = []
            try:
                gen = self.gen_factory()
                async for chunk in gen:
                    collected.append(chunk)
                    self.signals.token.emit(chunk)
                self.signals.finished.emit("".join(collected))
            except Exception as exc:
                logger.exception("Error in LLMStreamWorker")
                self.signals.error.emit(str(exc))

        try:
            asyncio.run(_run_stream())
        except Exception as exc:
            self.signals.error.emit(str(exc))


class ModelPullSignals(QObject):
    """Signals for monitoring local model download progress."""
    started = Signal()
    progress = Signal(str, float)   # status, percent (0-100)
    finished = Signal(str)
    error = Signal(str)


class ModelPullWorker(QRunnable):
    """Asynchronously pulls an Ollama model with progress feedback."""

    def __init__(self, model_name: str, base_url: str = DEFAULT_OLLAMA_BASE_URL) -> None:
        super().__init__()
        self.model_name = model_name
        self.base_url = base_url
        self.signals = ModelPullSignals()
        self.setAutoDelete(True)

    def run(self) -> None:
        async def _run_pull() -> None:
            self.signals.started.emit()
            try:
                async for item in pull_model_stream(self.model_name, self.base_url):
                    status = item.get("status", "")
                    pct = float(item.get("percent", 0.0))
                    self.signals.progress.emit(status, pct)
                self.signals.finished.emit(f"Model '{self.model_name}' successfully downloaded and loaded.")
            except Exception as exc:
                logger.exception("Error in ModelPullWorker")
                self.signals.error.emit(str(exc))

        try:
            asyncio.run(_run_pull())
        except Exception as exc:
            self.signals.error.emit(str(exc))

