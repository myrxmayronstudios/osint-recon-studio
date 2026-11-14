"""Personal Email Privacy, Breach & Avatar Exposure Auditor.

Performs strictly passive, zero-key personal email exposure assessments:
validates RFC syntax, queries DNS MX records, flags burner/disposable email providers,
computes cryptographic hashes (MD5, SHA-256), inspects public avatar and profile leaks
(Gravatar, Libravatar), and queries public breach repositories (XposedOrNot public API)
for exposed historical credentials and data classes.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import email.utils
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional
import urllib.parse

import certifi
import dns.resolver
import httpx

from osint_studio.core.domain_utils import extract_root_domain, normalize_domain

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINTReconStudio-PassiveAudit/1.0"

# Common disposable / temporary email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "temp-mail.org",
    "10minutemail.com", "throwawaymail.com", "yopmail.com", "sharklasers.com",
    "trashmail.com", "dispostable.com", "getairmail.com", "mytemp.email",
    "nada.ltd", "burnermail.io", "maildrop.cc", "mohmal.com",
}


@dataclass
class EmailBreachRecord:
    """Historical public breach exposure record."""
    breach_name: str
    domain: str = ""
    breach_date: str = ""
    description: str = ""
    data_classes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EmailPrivacyReport:
    """Consolidated email exposure and identity linkability audit report."""
    email: str
    is_valid_format: bool = False
    domain: str = ""
    is_disposable: bool = False
    mx_records_found: bool = False
    mx_hosts: List[str] = field(default_factory=list)
    md5_hash: str = ""
    sha256_hash: str = ""
    gravatar_found: bool = False
    gravatar_display_name: str = ""
    gravatar_profile_url: str = ""
    gravatar_avatar_url: str = ""
    gravatar_accounts_linked: List[str] = field(default_factory=list)
    libravatar_found: bool = False
    breaches_count: int = 0
    breaches: List[EmailBreachRecord] = field(default_factory=list)
    exposed_data_classes: List[str] = field(default_factory=list)
    privacy_risk_level: str = "LOW"     # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    privacy_score: int = 100            # 0-100 (100 = unexposed / high privacy)
    recommendations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EmailPrivacyEngine:
    """Passive personal email privacy, identity correlation, and breach exposure auditor."""

    @classmethod
    def audit_email(cls, email_address: str, timeout: float = 8.0) -> EmailPrivacyReport:
        try:
            return asyncio.run(cls.audit_email_async(email_address, timeout=timeout))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(cls.audit_email_async(email_address, timeout=timeout))
            finally:
                loop.close()

    @classmethod
    async def audit_email_async(cls, email_address: str, timeout: float = 8.0) -> EmailPrivacyReport:
        clean_email = email_address.strip().lower()
        report = EmailPrivacyReport(email=clean_email)

        if not clean_email or "@" not in clean_email:
            report.warnings.append("Invalid or empty email address provided.")
            return report

        # 1. Format validation
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if re.match(email_regex, clean_email):
            report.is_valid_format = True
        else:
            report.warnings.append("Email address does not adhere to standard RFC 5322 format.")

        parts = clean_email.split("@", 1)
        domain = parts[1] if len(parts) > 1 else ""
        report.domain = domain

        # 2. Disposable check
        if domain in DISPOSABLE_DOMAINS:
            report.is_disposable = True
            report.recommendations.append("Disposable/burner email domain detected. Do not use for important accounts.")

        # 3. DNS MX Verification
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
            resolver.lifetime = 4.0
            answers = resolver.resolve(domain, "MX")
            report.mx_records_found = True
            report.mx_hosts = [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            report.mx_records_found = False

        # 4. Cryptographic hashes (used by public avatar & identity providers)
        email_bytes = clean_email.encode("utf-8")
        report.md5_hash = hashlib.md5(email_bytes).hexdigest()
        report.sha256_hash = hashlib.sha256(email_bytes).hexdigest()

        # 5. Public Avatar & Profile Leaks (Gravatar / Libravatar)
        async with httpx.AsyncClient(
            verify=certifi.where(),
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        ) as client:
            await cls._check_gravatar(client, report)
            await cls._check_libravatar(client, report)
            await cls._check_xposedornot_breaches(client, report)

        # 6. Calculate Privacy Risk Score & Actionable Remediation
        cls._calculate_privacy_score(report)

        report.is_success = True
        return report

    @classmethod
    async def _check_gravatar(cls, client: httpx.AsyncClient, report: EmailPrivacyReport) -> None:
        """Checks if email hash is linked to a public Gravatar profile."""
        url = f"https://en.gravatar.com/{report.md5_hash}.json"
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entry", [])
                if entries:
                    ent = entries[0]
                    report.gravatar_found = True
                    report.gravatar_display_name = ent.get("displayName") or ent.get("name", {}).get("formatted", "")
                    report.gravatar_profile_url = ent.get("profileUrl") or f"https://gravatar.com/{report.md5_hash}"
                    report.gravatar_avatar_url = ent.get("thumbnailUrl") or f"https://gravatar.com/avatar/{report.md5_hash}"

                    # Linked accounts (Twitter, GitHub, etc.)
                    accounts = ent.get("accounts", [])
                    linked = [f"{a.get('shortname')}: {a.get('url')}" for a in accounts if a.get("url")]
                    report.gravatar_accounts_linked = linked
            elif resp.status_code == 404:
                # Also test if image exists even without full JSON profile
                img_url = f"https://gravatar.com/avatar/{report.md5_hash}?d=404"
                img_resp = await client.head(img_url)
                if img_resp.status_code == 200:
                    report.gravatar_found = True
                    report.gravatar_avatar_url = f"https://gravatar.com/avatar/{report.md5_hash}"
        except Exception as exc:
            logger.debug("Gravatar lookup exception: %s", exc)

    @classmethod
    async def _check_libravatar(cls, client: httpx.AsyncClient, report: EmailPrivacyReport) -> None:
        """Checks if email hash is linked to Libravatar federated profile."""
        url = f"https://seccdn.libravatar.org/avatar/{report.md5_hash}?d=404"
        try:
            resp = await client.head(url)
            if resp.status_code == 200:
                report.libravatar_found = True
        except Exception:
            pass

    @classmethod
    async def _check_xposedornot_breaches(cls, client: httpx.AsyncClient, report: EmailPrivacyReport) -> None:
        """Queries public zero-key breach repository XposedOrNot for compromised data classes."""
        url = f"https://api.xposedornot.com/v1/check-email/{report.email}"
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                # XposedOrNot returns breaches as an array inside "breaches" list
                raw_breaches = data.get("breaches", [])
                if isinstance(raw_breaches, list) and raw_breaches:
                    # In some API responses, raw_breaches is list of lists: [["Breach1", "Breach2"]]
                    flat_names = []
                    for item in raw_breaches:
                        if isinstance(item, list):
                            flat_names.extend([str(x) for x in item])
                        elif isinstance(item, str):
                            flat_names.append(item)

                    all_classes = set()
                    for bname in flat_names:
                        b_rec = EmailBreachRecord(breach_name=bname)
                        report.breaches.append(b_rec)

                    report.breaches_count = len(report.breaches)
            elif resp.status_code == 404:
                # No breaches found in XposedOrNot database
                report.breaches_count = 0
        except Exception as exc:
            logger.debug("XposedOrNot breach lookup exception: %s", exc)
            report.warnings.append("Breach lookup endpoint was unreachable or timed out.")

    @classmethod
    def _calculate_privacy_score(cls, report: EmailPrivacyReport) -> None:
        """Calculates email privacy score and delivers defensive self-audit recommendations."""
        score = 100

        # Breaches penalty
        if report.breaches_count > 0:
            penalty = min(50, report.breaches_count * 10)
            score -= penalty
            report.recommendations.append(
                f"Historical public breaches detected ({report.breaches_count} breaches). Ensure passwords associated with these services have been rotated and are unique."
            )

        # Gravatar profile correlation penalty
        if report.gravatar_found:
            score -= 15
            report.recommendations.append(
                f"Public Gravatar profile found linked to your email MD5 hash ({report.md5_hash}). Anyone who knows your email can retrieve your display name and photo."
            )

        if report.gravatar_accounts_linked:
            score -= 15
            report.recommendations.append(
                f"Linked third-party accounts ({len(report.gravatar_accounts_linked)}) exposed via Gravatar profile. Consider unlinking sensitive profiles if you desire anonymity."
            )

        # Missing MX
        if not report.mx_records_found:
            score -= 10
            report.recommendations.append("Domain has no published DNS MX records; cannot receive incoming email.")

        score = max(0, min(100, score))
        report.privacy_score = score

        if score >= 85:
            report.privacy_risk_level = "LOW"
        elif score >= 65:
            report.privacy_risk_level = "MEDIUM"
        elif score >= 40:
            report.privacy_risk_level = "HIGH"
        else:
            report.privacy_risk_level = "CRITICAL"
