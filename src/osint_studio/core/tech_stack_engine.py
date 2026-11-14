"""Passive web technology fingerprinting and well-known manifest audit engine.

Inspects public response bodies and standard well-known discovery paths:
- `/.well-known/security.txt` (RFC 9116 Vulnerability Disclosure Policy)
- `/robots.txt` (Crawling directives & exposed path patterns)
- `/sitemap.xml` (Publicly advertised document indexes)
- `/.well-known/openid-configuration` (Public OpenID Connect endpoints)
Fingerprints frameworks, CMS, CDNs, analytics, and server software without invasive testing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"

TECH_SIGNATURES: List[Dict[str, Any]] = [
    # CMS / Site Builders
    {"name": "WordPress", "category": "CMS", "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"], "meta": [r"WordPress"]},
    {"name": "Shopify", "category": "E-Commerce", "html": [r"cdn\.shopify\.com", r"Shopify\.theme"]},
    {"name": "Drupal", "category": "CMS", "html": [r"Drupal\.settings", r"/sites/default/files"]},
    {"name": "Joomla", "category": "CMS", "html": [r"/media/jui/", r"content=\"Joomla!\""]},
    {"name": "Ghost", "category": "CMS", "html": [r"ghost-portal", r"content=\"Ghost\""]},
    # Frontend Frameworks
    {"name": "Next.js", "category": "Frontend Framework", "html": [r"/_next/static/", r"__NEXT_DATA__"]},
    {"name": "Nuxt.js", "category": "Frontend Framework", "html": [r"/_nuxt/", r"__NUXT__"]},
    {"name": "React", "category": "JavaScript Library", "html": [r"react-root", r"data-reactroot", r"_reactInternalInstance"]},
    {"name": "Vue.js", "category": "JavaScript Framework", "html": [r"data-v-[a-f0-9]", r"vue-router"]},
    {"name": "Angular", "category": "Frontend Framework", "html": [r"ng-version=", r"ng-app="]},
    {"name": "Tailwind CSS", "category": "UI Framework", "html": [r"tailwind", r"class=\"[^\"]*(?:flex|grid|p-\d|m-\d|text-[a-z]+-[0-9]{3})"]},
    {"name": "Bootstrap", "category": "UI Framework", "html": [r"bootstrap(?:\.min)?\.css", r"navbar-expand"]},
    {"name": "jQuery", "category": "JavaScript Library", "html": [r"jquery(?:\.min)?\.js"]},
    # CDNs & Hosting
    {"name": "Cloudflare", "category": "CDN / Security", "headers": {"server": r"cloudflare", "cf-ray": r".+"}},
    {"name": "Amazon CloudFront", "category": "CDN", "headers": {"via": r"CloudFront", "x-amz-cf-id": r".+"}},
    {"name": "Varnish", "category": "Caching Proxy", "headers": {"x-varnish": r".+", "via": r"varnish"}},
    {"name": "Fastly", "category": "CDN", "headers": {"x-fastly-request-id": r".+"}},
    # Analytics
    {"name": "Google Analytics", "category": "Analytics", "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-[0-9]+-[0-9]+"]},
    {"name": "Google Tag Manager", "category": "Tag Management", "html": [r"googletagmanager\.com/gtm\.js"]},
    {"name": "Hotjar", "category": "Analytics", "html": [r"static\.hotjar\.com"]},
]


@dataclass
class TechItem:
    """Discovered technology stack component."""
    name: str
    category: str
    version: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityTxtReport:
    """RFC 9116 security.txt vulnerability disclosure metadata."""
    found: bool = False
    url: str = ""
    contact: str = ""
    encryption: str = ""
    policy: str = ""
    hiring: str = ""
    expires: str = ""
    raw_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TechStackReport:
    """Consolidated web technology and manifest audit report."""
    domain: str
    technologies: List[TechItem] = field(default_factory=list)
    security_txt: SecurityTxtReport = field(default_factory=SecurityTxtReport)
    robots_found: bool = False
    robots_disallowed_paths: List[str] = field(default_factory=list)
    robots_sitemaps: List[str] = field(default_factory=list)
    sitemap_found: bool = False
    sitemap_sample_urls: List[str] = field(default_factory=list)
    openid_configured: bool = False
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "technologies": [t.to_dict() for t in self.technologies],
            "security_txt": self.security_txt.to_dict(),
            "robots_found": self.robots_found,
            "robots_disallowed_paths": self.robots_disallowed_paths,
            "robots_sitemaps": self.robots_sitemaps,
            "sitemap_found": self.sitemap_found,
            "sitemap_sample_urls": self.sitemap_sample_urls,
            "openid_configured": self.openid_configured,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class TechStackEngine:
    """Passively fingerprints web technologies and well-known security manifests."""

    def __init__(self, timeout: float = 10.0, user_agent: str = USER_AGENT) -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def clean_domain(self, domain: str) -> str:
        d = domain.strip().lower()
        if "://" in d:
            parsed = urllib.parse.urlparse(d)
            d = parsed.netloc or parsed.path
        return d.split("/")[0].split(":")[0].strip(".")

    def fingerprint_html_and_headers(
        self, html_body: str, headers: Dict[str, str]
    ) -> List[TechItem]:
        """Matches passive signatures across HTML source and HTTP headers."""
        discovered: Dict[str, TechItem] = {}
        h_lower = {k.lower(): v for k, v in headers.items()}

        # Server & X-Powered-By explicit headers
        server_val = h_lower.get("server")
        if server_val:
            discovered[f"Server-{server_val}"] = TechItem(
                name=server_val, category="Web Server", evidence="Server header"
            )

        powered_by = h_lower.get("x-powered-by")
        if powered_by:
            discovered[f"Powered-{powered_by}"] = TechItem(
                name=powered_by, category="Backend Framework", evidence="X-Powered-By header"
            )

        # Signature matching
        for sig in TECH_SIGNATURES:
            name = sig["name"]
            category = sig["category"]

            # Header match
            header_match = False
            if "headers" in sig:
                for h_name, pattern in sig["headers"].items():
                    val = h_lower.get(h_name.lower(), "")
                    if re.search(pattern, val, re.IGNORECASE):
                        header_match = True
                        break

            # HTML match
            html_match = False
            if "html" in sig and html_body:
                for pattern in sig["html"]:
                    if re.search(pattern, html_body, re.IGNORECASE):
                        html_match = True
                        break

            if header_match or html_match:
                ev = "HTTP Header match" if header_match else "HTML pattern signature"
                discovered[name] = TechItem(name=name, category=category, evidence=ev)

        return sorted(discovered.values(), key=lambda t: (t.category, t.name))

    def check_security_txt(self, domain: str) -> SecurityTxtReport:
        """Fetches and parses RFC 9116 security.txt."""
        report = SecurityTxtReport()
        urls_to_try = [
            f"https://{domain}/.well-known/security.txt",
            f"https://{domain}/security.txt",
        ]
        headers = {"User-Agent": self.user_agent}

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                for url in urls_to_try:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200 and "contact:" in resp.text.lower():
                        report.found = True
                        report.url = str(resp.url)
                        lines = resp.text.splitlines()
                        report.raw_lines = [line.strip() for line in lines if line.strip() and not line.startswith("#")][:20]

                        for line in lines:
                            line = line.strip()
                            if ":" in line and not line.startswith("#"):
                                field_name, field_val = line.split(":", 1)
                                k = field_name.strip().lower()
                                v = field_val.strip()
                                if k == "contact" and not report.contact:
                                    report.contact = v
                                elif k == "encryption" and not report.encryption:
                                    report.encryption = v
                                elif k == "policy" and not report.policy:
                                    report.policy = v
                                elif k == "hiring" and not report.hiring:
                                    report.hiring = v
                                elif k == "expires" and not report.expires:
                                    report.expires = v
                        break
        except Exception as e:
            logger.debug(f"security.txt lookup failed for {domain}: {e}")

        return report

    def check_robots_txt(self, domain: str) -> tuple[bool, List[str], List[str]]:
        """Politely retrieves robots.txt and extracts disallow paths and sitemaps."""
        url = f"https://{domain}/robots.txt"
        headers = {"User-Agent": self.user_agent}
        disallow: List[str] = []
        sitemaps: List[str] = []

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200 and "text" in resp.headers.get("content-type", ""):
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if ":" in line and not line.startswith("#"):
                            d_name, d_val = line.split(":", 1)
                            k = d_name.strip().lower()
                            v = d_val.strip()
                            if k == "disallow" and v and v != "/":
                                if v not in disallow and len(disallow) < 50:
                                    disallow.append(v)
                            elif k == "sitemap":
                                if v not in sitemaps:
                                    sitemaps.append(v)
                    return True, disallow, sitemaps
        except Exception:
            pass

        return False, disallow, sitemaps

    def check_openid_configuration(self, domain: str) -> bool:
        """Checks if OpenID Connect configuration is publicly advertised."""
        url = f"https://{domain}/.well-known/openid-configuration"
        headers = {"User-Agent": self.user_agent}
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200 and "issuer" in resp.text:
                    return True
        except Exception:
            pass
        return False

    def analyze(self, domain: str) -> TechStackReport:
        """Executes full passive web technology and manifest audit."""
        clean_d = self.clean_domain(domain)
        report = TechStackReport(domain=clean_d)

        # 1. Root page fetch for passive fingerprinting
        html_body = ""
        headers: Dict[str, str] = {}
        req_headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml"}

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(f"https://{clean_d}", headers=req_headers)
                if resp.status_code == 200:
                    html_body = resp.text[:500000]  # Read first 500KB
                    headers = dict(resp.headers)
        except Exception:
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    resp = client.get(f"http://{clean_d}", headers=req_headers)
                    if resp.status_code == 200:
                        html_body = resp.text[:500000]
                        headers = dict(resp.headers)
            except Exception as e:
                logger.debug(f"Could not fetch root page for {clean_d}: {e}")

        report.technologies = self.fingerprint_html_and_headers(html_body, headers)

        # 2. security.txt
        report.security_txt = self.check_security_txt(clean_d)

        # 3. robots.txt
        robots_found, disallow_paths, sitemaps = self.check_robots_txt(clean_d)
        report.robots_found = robots_found
        report.robots_disallowed_paths = disallow_paths
        report.robots_sitemaps = sitemaps

        # 4. OpenID Connect
        report.openid_configured = self.check_openid_configuration(clean_d)

        report.is_success = True
        return report
