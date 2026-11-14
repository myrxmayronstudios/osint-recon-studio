"""Passive HTTP security headers, TLS certificate, and web posture audit engine.

Performs polite, non-intrusive HTTP inspection to evaluate security headers
(HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy),
TLS certificate parameters, cookie security flags, and public robots.txt metadata.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"


@dataclass
class HeaderAuditItem:
    """Represents the audit result for a single security header."""
    header: str
    status: str  # PASS, WARN, FAIL
    value: str
    description: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CookieAuditItem:
    """Audit of a single Set-Cookie header."""
    name: str
    has_secure: bool
    has_httponly: bool
    samesite: str  # Strict, Lax, None, Missing
    raw: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSCertificateReport:
    """Details of the public TLS/SSL certificate."""
    subject_cn: str = ""
    san_list: List[str] = field(default_factory=list)
    issuer_org: str = ""
    issuer_cn: str = ""
    valid_from: str = ""
    valid_until: str = ""
    days_until_expiration: Optional[int] = None
    tls_version: str = ""
    cipher_suite: str = ""
    is_expired: bool = False
    is_valid: bool = False
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RobotsTxtReport:
    """Summary of publicly advertised robots.txt."""
    found: bool = False
    url: str = ""
    disallow_count: int = 0
    allow_count: int = 0
    sitemaps: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    sample_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebEngineReport:
    """Consolidated Web & Security Headers reconnaissance output."""
    domain: str
    canonical_url: str = ""
    status_code: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    server_header: str = ""
    powered_by_header: str = ""
    technology_indicators: Dict[str, str] = field(default_factory=dict)
    security_headers: List[HeaderAuditItem] = field(default_factory=list)
    security_grade: str = "N/A"  # A+, A, B, C, D, F
    security_score: int = 0       # 0 - 100
    cookies: List[CookieAuditItem] = field(default_factory=list)
    tls: TLSCertificateReport = field(default_factory=TLSCertificateReport)
    robots: RobotsTxtReport = field(default_factory=RobotsTxtReport)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "canonical_url": self.canonical_url,
            "status_code": self.status_code,
            "redirect_chain": self.redirect_chain,
            "server_header": self.server_header,
            "powered_by_header": self.powered_by_header,
            "technology_indicators": self.technology_indicators,
            "security_headers": [h.to_dict() for h in self.security_headers],
            "security_grade": self.security_grade,
            "security_score": self.security_score,
            "cookies": [c.to_dict() for c in self.cookies],
            "tls": self.tls.to_dict(),
            "robots": self.robots.to_dict(),
            "raw_headers": self.raw_headers,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class WebEngine:
    """Performs passive HTTP header and SSL/TLS security audits."""

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def clean_domain(self, domain: str) -> str:
        d = domain.strip().lower()
        if "://" in d:
            parsed = urllib.parse.urlparse(d)
            d = parsed.netloc or parsed.path
        return d.split("/")[0].split(":")[0].strip(".")

    def inspect_tls_certificate(self, domain: str) -> TLSCertificateReport:
        """Passively inspects the server's public TLS certificate via SNI handshake."""
        target_domain = self.clean_domain(domain)
        report = TLSCertificateReport()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # For reconnaissance, inspect even self-signed/expired certs

        try:
            with socket.create_connection((target_domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target_domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    report.tls_version = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        report.cipher_suite = f"{cipher[0]} ({cipher[1]} bits)"

                    if not cert:
                        # Binary form fallback
                        der = ssock.getpeercert(binary_form=True)
                        if der:
                            report.is_valid = True
                            report.subject_cn = target_domain
                        return report

                    # Subject
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    report.subject_cn = subject.get("commonName", "")

                    # Issuer
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    report.issuer_org = issuer.get("organizationName", "")
                    report.issuer_cn = issuer.get("commonName", "")

                    # SANs
                    sans = cert.get("subjectAltName", ())
                    report.san_list = [str(name) for typ, name in sans if typ.lower() == "dns"]

                    # Dates
                    not_before_str = cert.get("notBefore", "")
                    not_after_str = cert.get("notAfter", "")
                    report.valid_from = not_before_str
                    report.valid_until = not_after_str

                    if not_after_str:
                        # Format: 'May 10 12:00:00 2025 GMT'
                        try:
                            expiry_dt = datetime.datetime.strptime(
                                not_after_str, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=datetime.timezone.utc)
                            now = datetime.datetime.now(datetime.timezone.utc)
                            diff = (expiry_dt - now).days
                            report.days_until_expiration = diff
                            if diff < 0:
                                report.is_expired = True
                                report.warnings.append("CRITICAL: TLS certificate has expired!")
                            elif diff < 30:
                                report.warnings.append(
                                    f"WARNING: TLS certificate expires soon ({diff} days remaining)."
                                )
                        except Exception as e:
                            logger.debug(f"Failed to parse cert date: {e}")

                    report.is_valid = not report.is_expired

        except socket.timeout:
            report.warnings.append("Connection timed out connecting to port 443 for TLS audit.")
        except Exception as e:
            report.warnings.append(f"Unable to retrieve TLS certificate: {e}")

        return report

    def audit_security_headers(
        self, headers: Dict[str, str]
    ) -> Tuple[List[HeaderAuditItem], int, str]:
        """Audits OWASP-recommended security headers and computes a posture grade."""
        h_lower = {k.lower(): v for k, v in headers.items()}
        items: List[HeaderAuditItem] = []
        score = 100

        # 1. HSTS (Strict-Transport-Security)
        hsts = h_lower.get("strict-transport-security")
        if hsts:
            val_lower = hsts.lower()
            if "max-age=" in val_lower:
                try:
                    ma_str = val_lower.split("max-age=")[1].split(";")[0].strip()
                    max_age = int(ma_str)
                    if max_age >= 15768000:  # 6 months or 1 year
                        items.append(
                            HeaderAuditItem(
                                header="Strict-Transport-Security (HSTS)",
                                status="PASS",
                                value=hsts,
                                description="Forces HTTPS and protects against downgrade/SSL-stripping attacks.",
                                recommendation="Configured properly.",
                            )
                        )
                    else:
                        items.append(
                            HeaderAuditItem(
                                header="Strict-Transport-Security (HSTS)",
                                status="WARN",
                                value=hsts,
                                description="HSTS is enabled but max-age is shorter than recommended (< 6 months).",
                                recommendation="Increase max-age to at least 31536000 (1 year) and includeSubDomains.",
                            )
                        )
                        score -= 5
                except ValueError:
                    items.append(
                        HeaderAuditItem(
                            header="Strict-Transport-Security (HSTS)",
                            status="WARN",
                            value=hsts,
                            description="HSTS header present but max-age value is unparseable.",
                            recommendation="Ensure max-age=31536000; includeSubDomains.",
                        )
                    )
                    score -= 5
            else:
                items.append(
                    HeaderAuditItem(
                        header="Strict-Transport-Security (HSTS)",
                        status="WARN",
                        value=hsts,
                        description="HSTS header present without max-age directive.",
                        recommendation="Add max-age=31536000.",
                    )
                )
                score -= 10
        else:
            items.append(
                HeaderAuditItem(
                    header="Strict-Transport-Security (HSTS)",
                    status="FAIL",
                    value="Missing",
                    description="Domain does not enforce strict HTTPS transport.",
                    recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                )
            )
            score -= 20

        # 2. Content-Security-Policy (CSP)
        csp = h_lower.get("content-security-policy")
        if csp:
            val_lower = csp.lower()
            if "'unsafe-inline'" in val_lower or "'unsafe-eval'" in val_lower or " *" in val_lower:
                items.append(
                    HeaderAuditItem(
                        header="Content-Security-Policy (CSP)",
                        status="WARN",
                        value=csp[:120] + ("..." if len(csp) > 120 else ""),
                        description="CSP header is active but contains permissive directives (unsafe-inline / unsafe-eval / wildcard).",
                        recommendation="Refactor scripts to use nonces or hashes rather than unsafe-inline.",
                    )
                )
                score -= 10
            else:
                items.append(
                    HeaderAuditItem(
                        header="Content-Security-Policy (CSP)",
                        status="PASS",
                        value=csp[:120] + ("..." if len(csp) > 120 else ""),
                        description="Strict CSP protects against Cross-Site Scripting (XSS) and data injection.",
                        recommendation="Strong policy maintained.",
                    )
                )
        else:
            items.append(
                HeaderAuditItem(
                    header="Content-Security-Policy (CSP)",
                    status="FAIL",
                    value="Missing",
                    description="No Content Security Policy detected. Vulnerable to XSS and code injection.",
                    recommendation="Define a robust default-src 'self' Content-Security-Policy.",
                )
            )
            score -= 25

        # 3. X-Frame-Options
        xfo = h_lower.get("x-frame-options")
        if xfo:
            val_upper = xfo.strip().upper()
            if val_upper in ("DENY", "SAMEORIGIN"):
                items.append(
                    HeaderAuditItem(
                        header="X-Frame-Options (XFO)",
                        status="PASS",
                        value=xfo,
                        description="Prevents clickjacking attacks by controlling iframe embedding.",
                        recommendation="Configured properly.",
                    )
                )
            else:
                items.append(
                    HeaderAuditItem(
                        header="X-Frame-Options (XFO)",
                        status="WARN",
                        value=xfo,
                        description=f"Unusual X-Frame-Options value: {xfo}",
                        recommendation="Use DENY or SAMEORIGIN (or frame-ancestors in CSP).",
                    )
                )
                score -= 5
        else:
            items.append(
                HeaderAuditItem(
                    header="X-Frame-Options (XFO)",
                    status="FAIL",
                    value="Missing",
                    description="Missing anti-clickjacking header.",
                    recommendation="Add: X-Frame-Options: DENY or SAMEORIGIN",
                )
            )
            score -= 15

        # 4. X-Content-Type-Options
        xcto = h_lower.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            items.append(
                HeaderAuditItem(
                    header="X-Content-Type-Options",
                    status="PASS",
                    value=xcto,
                    description="Prevents browsers from MIME-sniffing responses away from the declared content-type.",
                    recommendation="Configured properly.",
                )
            )
        else:
            items.append(
                HeaderAuditItem(
                    header="X-Content-Type-Options",
                    status="FAIL",
                    value=xcto or "Missing",
                    description="Missing nosniff flag. Browsers may execute maliciously morphed assets.",
                    recommendation="Add: X-Content-Type-Options: nosniff",
                )
            )
            score -= 10

        # 5. Referrer-Policy
        ref = h_lower.get("referrer-policy")
        if ref:
            items.append(
                HeaderAuditItem(
                    header="Referrer-Policy",
                    status="PASS",
                    value=ref,
                    description="Controls how much referrer information is leaked in outgoing requests.",
                    recommendation="Configured properly.",
                )
            )
        else:
            items.append(
                HeaderAuditItem(
                    header="Referrer-Policy",
                    status="WARN",
                    value="Missing",
                    description="No explicit Referrer-Policy set. Browser defaults may leak path data to third parties.",
                    recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
                )
            )
            score -= 10

        # 6. Permissions-Policy
        perm = h_lower.get("permissions-policy") or h_lower.get("feature-policy")
        if perm:
            items.append(
                HeaderAuditItem(
                    header="Permissions-Policy",
                    status="PASS",
                    value=perm[:100] + ("..." if len(perm) > 100 else ""),
                    description="Restricts browser hardware APIs (camera, microphone, geolocation).",
                    recommendation="Configured properly.",
                )
            )
        else:
            items.append(
                HeaderAuditItem(
                    header="Permissions-Policy",
                    status="WARN",
                    value="Missing",
                    description="No Permissions-Policy declared to restrict browser features.",
                    recommendation="Add Permissions-Policy: camera=(), microphone=(), geolocation=()",
                )
            )
            score -= 5

        # 7. Cross-Origin Headers (COOP / CORP)
        coop = h_lower.get("cross-origin-opener-policy")
        if coop:
            items.append(
                HeaderAuditItem(
                    header="Cross-Origin-Opener-Policy (COOP)",
                    status="PASS",
                    value=coop,
                    description="Isolates browsing context to protect against Spectre-like cross-origin attacks.",
                    recommendation="Configured properly.",
                )
            )
        else:
            items.append(
                HeaderAuditItem(
                    header="Cross-Origin-Opener-Policy (COOP)",
                    status="WARN",
                    value="Missing",
                    description="Missing COOP header.",
                    recommendation="Consider adding: Cross-Origin-Opener-Policy: same-origin",
                )
            )
            score -= 5

        # Bound score
        score = max(0, min(100, score))

        # Assign letter grade
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

        return items, score, grade

    def inspect_cookies(self, response: httpx.Response) -> List[CookieAuditItem]:
        """Audits Set-Cookie headers for Secure, HttpOnly, and SameSite hygiene."""
        items: List[CookieAuditItem] = []
        raw_set_cookies = response.headers.get_list("set-cookie")

        for raw in raw_set_cookies:
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=")[0] if parts else "Unknown"

            parts_lower = [p.lower() for p in parts]
            has_secure = "secure" in parts_lower
            has_httponly = "httponly" in parts_lower

            samesite = "Missing"
            for p in parts_lower:
                if p.startswith("samesite="):
                    samesite = p.split("=", 1)[1].capitalize()
                    break

            items.append(
                CookieAuditItem(
                    name=name,
                    has_secure=has_secure,
                    has_httponly=has_httponly,
                    samesite=samesite,
                    raw=raw,
                )
            )

        return items

    def inspect_robots_txt(self, domain: str) -> RobotsTxtReport:
        """Politely checks public robots.txt for disallowed directories and sitemaps."""
        clean_d = self.clean_domain(domain)
        url = f"https://{clean_d}/robots.txt"
        report = RobotsTxtReport(url=url)

        headers = {"User-Agent": self.user_agent}

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200 and "text" in resp.headers.get("content-type", ""):
                    report.found = True
                    lines = resp.text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if ":" in line:
                            directive, val = line.split(":", 1)
                            d_clean = directive.strip().lower()
                            v_clean = val.strip()

                            if d_clean == "disallow":
                                report.disallow_count += 1
                                if len(report.sample_rules) < 10 and v_clean:
                                    report.sample_rules.append(f"Disallow: {v_clean}")
                            elif d_clean == "allow":
                                report.allow_count += 1
                            elif d_clean == "sitemap":
                                if v_clean not in report.sitemaps:
                                    report.sitemaps.append(v_clean)
                            elif d_clean == "user-agent":
                                if v_clean not in report.user_agents:
                                    report.user_agents.append(v_clean)
        except Exception as e:
            logger.debug(f"robots.txt retrieval failed for {clean_d}: {e}")

        return report

    def analyze(self, domain: str) -> WebEngineReport:
        """Executes full polite HTTP & security headers audit."""
        clean_d = self.clean_domain(domain)
        report = WebEngineReport(domain=clean_d)

        # Inspect TLS first
        report.tls = self.inspect_tls_certificate(clean_d)

        # Probe HTTP(S) politely
        urls_to_try = [f"https://{clean_d}", f"http://{clean_d}"]
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        resp: Optional[httpx.Response] = None
        redirect_chain: List[str] = []

        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            for url in urls_to_try:
                try:
                    r = client.get(url, headers=headers)
                    resp = r
                    redirect_chain = [str(hist.url) for hist in r.history]
                    redirect_chain.append(str(r.url))
                    break
                except httpx.ConnectError:
                    continue
                except Exception as e:
                    logger.debug(f"HTTP request failed for {url}: {e}")

        if not resp:
            report.warnings.append(f"Could not establish HTTP/HTTPS connection to '{clean_d}'. Web server may be offline.")
            return report

        report.is_success = True
        report.status_code = resp.status_code
        report.canonical_url = str(resp.url)
        report.redirect_chain = redirect_chain

        # Extract raw headers
        raw_h = dict(resp.headers)
        report.raw_headers = raw_h

        # Fingerprint headers
        report.server_header = raw_h.get("server", "")
        report.powered_by_header = raw_h.get("x-powered-by", "")

        tech: Dict[str, str] = {}
        for k, v in raw_h.items():
            k_low = k.lower()
            if k_low in (
                "server",
                "x-powered-by",
                "x-aspnet-version",
                "x-generator",
                "via",
                "cf-ray",
                "cf-cache-status",
                "x-amz-cf-id",
                "x-github-request-id",
                "x-varnish",
            ):
                tech[k] = v
        report.technology_indicators = tech

        # Audit security headers
        items, score, grade = self.audit_security_headers(raw_h)
        report.security_headers = items
        report.security_score = score
        report.security_grade = grade

        # Cookies
        report.cookies = self.inspect_cookies(resp)

        # Robots.txt
        report.robots = self.inspect_robots_txt(clean_d)

        return report
