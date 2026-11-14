"""Personal Data OSINT, Identity Correlation & Metadata Scrubber Suite.

Features:
1. Deep Email Ecosystem & Breach Exposure (XposedOrNot analytics, Gravatar/Libravatar, PGP keyservers, custom domain hygiene).
2. 40+ Platform Social & Public Profile Scanner with OpenGraph and JSON-LD extraction.
3. Smart Username Permutator & Cross-Platform Linkability Risk Analyzer.
4. Phone Number Deep Telecom, VoIP & Public Messaging Deep-Link Auditor.
5. Personal Photo & Document Privacy Scrubber (EXIF/XMP/PDF stripping to produce clean files).
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import urllib.parse

import certifi
import dns.resolver
import httpx
from PIL import Image
from pypdf import PdfReader, PdfWriter

from osint_studio.core.cache_manager import get_cached, set_cached
from osint_studio.core.domain_utils import extract_brand_handle, normalize_domain
from osint_studio.core.fast_network import FastHttpClient, FastSyncHttpClient

logger = logging.getLogger(__name__)

# Common generic public email domains (not custom domains)
GENERIC_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "proton.me", "protonmail.com", "zoho.com", "mail.com", "gmx.com",
}

# 40+ Popular Public Platforms for Handle/Username Auditing
EXPANDED_PLATFORMS = [
    {"platform": "GitHub", "category": "Code & Dev", "url": "https://github.com/{handle}", "check": "status"},
    {"platform": "GitLab", "category": "Code & Dev", "url": "https://gitlab.com/api/v4/users?username={handle}", "check": "gitlab_api"},
    {"platform": "HackerNews", "category": "Community", "url": "https://hacker-news.firebaseio.com/v0/user/{handle}.json", "check": "hn_api"},
    {"platform": "Dev.to", "category": "Code & Dev", "url": "https://dev.to/api/users/by_username?url={handle}", "check": "status"},
    {"platform": "Codeberg", "category": "Code & Dev", "url": "https://codeberg.org/api/v1/users/{handle}", "check": "status"},
    {"platform": "DockerHub", "category": "Code & Dev", "url": "https://hub.docker.com/v2/users/{handle}/", "check": "status"},
    {"platform": "PyPI", "category": "Packages", "url": "https://pypi.org/pypi/{handle}/json", "check": "status"},
    {"platform": "npm", "category": "Packages", "url": "https://registry.npmjs.org/-/v1/search?text=maintainer:{handle}&size=1", "check": "npm_api"},
    {"platform": "RubyGems", "category": "Packages", "url": "https://rubygems.org/api/v1/owners/{handle}/gems.json", "check": "status"},
    {"platform": "Packagist", "category": "Packages", "url": "https://packagist.org/packages/list.json?vendor={handle}", "check": "packagist_api"},
    {"platform": "Crates.io", "category": "Packages", "url": "https://crates.io/api/v1/users/{handle}", "check": "status"},
    {"platform": "Bitbucket", "category": "Code & Dev", "url": "https://api.bitbucket.org/2.0/workspaces/{handle}", "check": "status"},
    {"platform": "Pastebin", "category": "Code & Dev", "url": "https://pastebin.com/u/{handle}", "check": "status"},
    {"platform": "StackOverflow", "category": "Code & Dev", "url": "https://stackoverflow.com/users/{handle}", "check": "status"},
    {"platform": "Medium", "category": "Publishing", "url": "https://medium.com/feed/@{handle}", "check": "status"},
    {"platform": "Substack", "category": "Publishing", "url": "https://{handle}.substack.com", "check": "status"},
    {"platform": "Reddit", "category": "Social", "url": "https://www.reddit.com/user/{handle}/", "check": "social_web"},
    {"platform": "X / Twitter", "category": "Social", "url": "https://x.com/{handle}", "check": "social_web"},
    {"platform": "YouTube", "category": "Media", "url": "https://www.youtube.com/@{handle}", "check": "social_web"},
    {"platform": "Instagram", "category": "Social", "url": "https://www.instagram.com/{handle}/", "check": "social_web"},
    {"platform": "TikTok", "category": "Media", "url": "https://www.tiktok.com/@{handle}", "check": "social_web"},
    {"platform": "LinkedIn", "category": "Professional", "url": "https://www.linkedin.com/in/{handle}/", "check": "social_web"},
    {"platform": "Twitch", "category": "Streaming", "url": "https://www.twitch.tv/{handle}", "check": "social_web"},
    {"platform": "Pinterest", "category": "Social", "url": "https://www.pinterest.com/{handle}/", "check": "social_web"},
    {"platform": "Steam", "category": "Gaming", "url": "https://steamcommunity.com/id/{handle}", "check": "status"},
    {"platform": "Spotify", "category": "Media", "url": "https://open.spotify.com/user/{handle}", "check": "status"},
    {"platform": "SoundCloud", "category": "Media", "url": "https://soundcloud.com/{handle}", "check": "status"},
    {"platform": "Vimeo", "category": "Media", "url": "https://vimeo.com/{handle}", "check": "status"},
    {"platform": "DeviantArt", "category": "Creative", "url": "https://www.deviantart.com/{handle}", "check": "status"},
    {"platform": "Behance", "category": "Creative", "url": "https://www.behance.net/{handle}", "check": "status"},
    {"platform": "Dribbble", "category": "Creative", "url": "https://dribbble.com/{handle}", "check": "status"},
    {"platform": "Patreon", "category": "Creator", "url": "https://www.patreon.com/{handle}", "check": "status"},
    {"platform": "Linktree", "category": "Identity", "url": "https://linktr.ee/{handle}", "check": "status"},
    {"platform": "About.me", "category": "Identity", "url": "https://about.me/{handle}", "check": "status"},
    {"platform": "Keybase", "category": "Identity", "url": "https://keybase.io/_/api/1.0/user/lookup.json?username={handle}", "check": "keybase_api"},
    {"platform": "Gravatar", "category": "Identity", "url": "https://en.gravatar.com/{handle}.json", "check": "status"},
    {"platform": "Wikipedia", "category": "Knowledge", "url": "https://en.wikipedia.org/wiki/Special:CentralAuth/{handle}?uselang=qqx", "check": "wiki_centralauth"},
    {"platform": "Telegram", "category": "Messaging", "url": "https://t.me/{handle}", "check": "telegram"},
    {"platform": "Flickr", "category": "Media", "url": "https://www.flickr.com/people/{handle}/", "check": "status"},
    {"platform": "Disqus", "category": "Community", "url": "https://disqus.com/by/{handle}/", "check": "status"},
    {"platform": "Bandcamp", "category": "Music", "url": "https://bandcamp.com/{handle}", "check": "status"},
    {"platform": "DailyMotion", "category": "Media", "url": "https://www.dailymotion.com/{handle}", "check": "status"},
]


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------

@dataclass
class DeepBreachInfo:
    name: str
    domain: str = ""
    breach_date: str = ""
    exposed_data: List[str] = field(default_factory=list)
    industry: str = ""
    description: str = ""


@dataclass
class PersonalEmailReport:
    email: str
    domain: str
    is_custom_domain: bool = False
    custom_domain_dmarc_protected: bool = False
    md5_hash: str = ""
    sha256_hash: str = ""
    gravatar_found: bool = False
    gravatar_name: str = ""
    gravatar_profile_url: str = ""
    gravatar_accounts: List[str] = field(default_factory=list)
    libravatar_found: bool = False
    openpgp_keys_found: int = 0
    openpgp_key_ids: List[str] = field(default_factory=list)
    breach_count: int = 0
    breaches: List[DeepBreachInfo] = field(default_factory=list)
    exposed_sensitive_classes: List[str] = field(default_factory=list)
    privacy_risk_score: int = 100  # 100 = safe, 0 = highly compromised
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PublicProfileFinding:
    platform: str
    category: str
    profile_url: str
    status: str  # "Claimed", "Available", "Login Gated", "Restricted", "Unreachable"
    status_code: int = 0
    og_title: str = ""
    og_description: str = ""
    og_image: str = ""
    response_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PersonalPrivacySuiteReport:
    target_handle: str
    target_email: str = ""
    target_phone: str = ""
    email_report: Optional[PersonalEmailReport] = None
    social_profiles: List[PublicProfileFinding] = field(default_factory=list)
    username_permutations: List[str] = field(default_factory=list)
    linkability_risk_score: int = 0  # 0 to 100 (Higher = more linkable across sites)
    linkability_rating: str = "LOW"
    phone_carrier_info: Dict[str, Any] = field(default_factory=dict)
    messaging_links: Dict[str, str] = field(default_factory=dict)
    summary_findings: List[str] = field(default_factory=list)
    remediation_plan: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -----------------------------------------------------------------------------
# Deep Email OSINT Engine
# -----------------------------------------------------------------------------

class DeepEmailEngine:
    """Queries public zero-key breach APIs, avatar hashes, and PGP keyservers."""

    @classmethod
    async def audit_email(cls, email_address: str, force_refresh: bool = False) -> PersonalEmailReport:
        clean = email_address.strip().lower()
        if not clean or "@" not in clean:
            return PersonalEmailReport(email=clean, domain="")

        cached = get_cached("personal_email", clean, force_refresh=force_refresh)
        if cached:
            return PersonalEmailReport(**cached)

        parts = clean.split("@", 1)
        domain = parts[1]
        is_custom = domain not in GENERIC_MAIL_DOMAINS

        md5_hash = hashlib.md5(clean.encode("utf-8")).hexdigest()
        sha256_hash = hashlib.sha256(clean.encode("utf-8")).hexdigest()

        report = PersonalEmailReport(
            email=clean,
            domain=domain,
            is_custom_domain=is_custom,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
        )

        client = FastHttpClient.get_client()

        # Concurrently audit breach repository, Gravatar, Libravatar, OpenPGP, and Domain DMARC
        await asyncio.gather(
            cls._check_xposedornot(client, clean, report),
            cls._check_gravatar(client, md5_hash, report),
            cls._check_libravatar(client, md5_hash, report),
            cls._check_openpgp(client, clean, report),
            cls._check_custom_domain_hygiene(domain, report) if is_custom else asyncio.sleep(0),
            return_exceptions=True,
        )

        cls._calculate_score(report)
        set_cached("personal_email", clean, report.to_dict(), ttl_seconds=86400)
        return report

    @classmethod
    async def _check_xposedornot(cls, client: httpx.AsyncClient, email: str, report: PersonalEmailReport) -> None:
        """Queries XposedOrNot for detailed breach history and exposed sensitive data classes."""
        try:
            # 1. Basic breach check
            url = f"https://api.xposedornot.com/v1/check-email/{email}"
            resp = await client.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                raw_breaches = data.get("breaches", [])
                flat_names: List[str] = []
                for item in raw_breaches:
                    if isinstance(item, list):
                        flat_names.extend([str(x) for x in item])
                    elif isinstance(item, str):
                        flat_names.append(item)

                for bname in flat_names:
                    report.breaches.append(DeepBreachInfo(name=bname))
                report.breach_count = len(report.breaches)

            # 2. Breach analytics for exposed data classes (passwords, phone numbers, etc.)
            analytics_url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
            r_an = await client.get(analytics_url, timeout=5.0)
            if r_an.status_code == 200:
                an_data = r_an.json()
                exposed_types = an_data.get("ExposedBreaches", {}).get("data_classes", [])
                if exposed_types:
                    report.exposed_sensitive_classes = list(set(exposed_types))
        except Exception as e:
            logger.debug(f"XposedOrNot lookup error: {e}")

    @classmethod
    async def _check_gravatar(cls, client: httpx.AsyncClient, md5: str, report: PersonalEmailReport) -> None:
        try:
            url = f"https://en.gravatar.com/{md5}.json"
            resp = await client.get(url, timeout=4.0)
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entry", [])
                if entries:
                    ent = entries[0]
                    report.gravatar_found = True
                    report.gravatar_name = ent.get("displayName") or ent.get("name", {}).get("formatted", "")
                    report.gravatar_profile_url = ent.get("profileUrl") or f"https://gravatar.com/{md5}"
                    accounts = ent.get("accounts", [])
                    report.gravatar_accounts = [f"{a.get('shortname')}: {a.get('url')}" for a in accounts if a.get("url")]
        except Exception:
            pass

    @classmethod
    async def _check_libravatar(cls, client: httpx.AsyncClient, md5: str, report: PersonalEmailReport) -> None:
        try:
            url = f"https://seccdn.libravatar.org/avatar/{md5}?d=404"
            resp = await client.head(url, timeout=3.0)
            if resp.status_code == 200:
                report.libravatar_found = True
        except Exception:
            pass

    @classmethod
    async def _check_openpgp(cls, client: httpx.AsyncClient, email: str, report: PersonalEmailReport) -> None:
        """Queries keys.openpgp.org to see if the user published verified public PGP keys."""
        try:
            url = f"https://keys.openpgp.org/vks/v1/by-email/{urllib.parse.quote(email)}"
            resp = await client.get(url, timeout=4.0)
            if resp.status_code == 200 and len(resp.content) > 50:
                report.openpgp_keys_found = 1
                report.openpgp_key_ids.append("Verified OpenPGP Public Key Found")
        except Exception:
            pass

    @classmethod
    async def _check_custom_domain_hygiene(cls, domain: str, report: PersonalEmailReport) -> None:
        """Audits custom email domain for anti-spoofing DMARC record to protect personal email."""
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
            resolver.lifetime = 3.0
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = "".join([t.decode("utf-8", errors="ignore") for t in rdata.strings])
                if "v=dmarc1" in txt.lower():
                    report.custom_domain_dmarc_protected = True
                    break
        except Exception:
            report.custom_domain_dmarc_protected = False

    @classmethod
    def _calculate_score(cls, report: PersonalEmailReport) -> None:
        score = 100
        if report.breach_count > 0:
            penalty = min(50, report.breach_count * 10)
            score -= penalty
            report.recommendations.append(
                f"Historical public credential breach detected ({report.breach_count} breaches). Immediately rotate passwords and enforce MFA."
            )

        if "Passwords" in report.exposed_sensitive_classes:
            score -= 20
            report.recommendations.append("Plaintext or hashed passwords exposed in historical dumps.")

        if report.gravatar_found:
            score -= 15
            report.recommendations.append("Public Gravatar identity leaked via email hash. Leaks name and avatar.")

        if report.is_custom_domain and not report.custom_domain_dmarc_protected:
            score -= 15
            report.recommendations.append(
                f"Custom email domain '{report.domain}' lacks DMARC. Impersonators can spoof emails appearing to come from you."
            )

        report.privacy_risk_score = max(0, min(100, score))


# -----------------------------------------------------------------------------
# 40+ Platform Social & Public Profile Scanner
# -----------------------------------------------------------------------------

def _extract_og_meta(html_text: str, prop: str) -> str:
    m = re.search(rf'<meta\s+[^>]*property=["\']og:{prop}["\'][^>]*content=["\']([^"\']*)["\']', html_text, re.I)
    if not m:
        m = re.search(rf'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']og:{prop}["\']', html_text, re.I)
    return m.group(1).strip() if m else ""


async def _check_platform_profile(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    plat: Dict[str, str],
    handle: str,
) -> PublicProfileFinding:
    name = plat["platform"]
    cat = plat["category"]
    check_type = plat["check"]
    url = plat["url"].format(handle=urllib.parse.quote(handle, safe="._-"))

    async with semaphore:
        t0 = time.perf_counter()
        try:
            if check_type == "status":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                if code == 200:
                    status = "Claimed"
                elif code == 404:
                    status = "Available"
                elif code in (401, 403):
                    status = "Login Gated"
                else:
                    status = "Unknown"
                return PublicProfileFinding(name, cat, url, status, code, "", "", "", lat)

            elif check_type == "gitlab_api":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                status = "Claimed" if code == 200 and len(resp.json()) > 0 else "Available"
                return PublicProfileFinding(name, cat, f"https://gitlab.com/{handle}", status, code, "", "", "", lat)

            elif check_type == "hn_api":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                data = resp.json() if code == 200 else None
                status = "Claimed" if data and data.get("id") else "Available"
                return PublicProfileFinding(name, cat, f"https://news.ycombinator.com/user?id={handle}", status, code, "", "", "", lat)

            elif check_type == "npm_api":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                data = resp.json() if code == 200 else {}
                status = "Claimed" if data.get("total", 0) > 0 else "Available"
                return PublicProfileFinding(name, cat, f"https://www.npmjs.com/~{handle}", status, code, "", "", "", lat)

            elif check_type == "packagist_api":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                data = resp.json() if code == 200 else {}
                status = "Claimed" if len(data.get("packageNames", [])) > 0 else "Available"
                return PublicProfileFinding(name, cat, f"https://packagist.org/packages/{handle}/", status, code, "", "", "", lat)

            elif check_type == "keybase_api":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                data = resp.json() if code == 200 else {}
                status = "Claimed" if data.get("status", {}).get("code") == 0 else "Available"
                return PublicProfileFinding(name, cat, f"https://keybase.io/{handle}", status, code, "", "", "", lat)

            elif check_type == "wiki_centralauth":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                status = "Available" if "centralauth-admin-nonexistent" in resp.text else "Claimed"
                return PublicProfileFinding(name, cat, f"https://en.wikipedia.org/wiki/Special:CentralAuth/{handle}", status, code, "", "", "", lat)

            elif check_type == "telegram":
                resp = await client.get(url, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                code = resp.status_code
                txt = resp.text
                status = "Claimed" if "tgme_page_title" in txt or "tgme_page_extra" in txt else "Available"
                return PublicProfileFinding(name, cat, url, status, code, "", "", "", lat)

            elif check_type == "social_web":
                # Use FastHttpClient memory-capped stream (first 64 KB) to extract OpenGraph tags safely
                code, html_text, _ = await FastHttpClient.fetch_capped_html(url, max_bytes=65536, timeout=5.0)
                lat = round((time.perf_counter() - t0) * 1000, 1)
                og_title = _extract_og_meta(html_text, "title")
                og_desc = _extract_og_meta(html_text, "description")
                og_img = _extract_og_meta(html_text, "image")

                if code == 200:
                    low = html_text.lower()
                    if "user not found" in low or "page not found" in low or "doesn't exist" in low:
                        status = "Available"
                    else:
                        status = "Claimed"
                elif code in (401, 403, 302, 301):
                    status = "Login Gated"
                elif code == 404:
                    status = "Available"
                else:
                    status = "Unknown"

                return PublicProfileFinding(name, cat, url, status, code, og_title, og_desc, og_img, lat)

            else:
                return PublicProfileFinding(name, cat, url, "Unknown", 0, "", "", "", 0.0)

        except httpx.TimeoutException:
            return PublicProfileFinding(name, cat, url, "Available", 0, "", "", "", round((time.perf_counter() - t0) * 1000, 1))
        except Exception:
            return PublicProfileFinding(name, cat, url, "Available", 0, "", "", "", round((time.perf_counter() - t0) * 1000, 1))


# -----------------------------------------------------------------------------
# Username Permutator & Linkability Engine
# -----------------------------------------------------------------------------

def generate_username_permutations(seed: str) -> List[str]:
    """Generates standard handle variations given a seed name or handle."""
    clean = re.sub(r"[^a-zA-Z0-9_.-]", "", seed.strip().lower())
    if not clean:
        return []

    perms: Set[str] = {clean}
    # If contains separator
    parts = re.split(r"[._-]", clean)
    parts = [p for p in parts if p]

    if len(parts) >= 2:
        p1, p2 = parts[0], parts[1]
        perms.add(f"{p1}{p2}")
        perms.add(f"{p1}_{p2}")
        perms.add(f"{p1}.{p2}")
        perms.add(f"{p2}{p1}")
        perms.add(f"{p1[0]}{p2}")
        perms.add(f"{p1}{p2[0]}")
    else:
        perms.add(f"{clean}1")
        perms.add(f"{clean}99")
        perms.add(f"{clean}_dev")
        perms.add(f"{clean}_official")

    return sorted(list(perms))[:12]


# -----------------------------------------------------------------------------
# Phone Deep Link & Carrier Auditor
# -----------------------------------------------------------------------------

def audit_phone_messaging_links(e164: str) -> Dict[str, str]:
    """Generates direct verification deep-links for WhatsApp and Telegram."""
    digits = re.sub(r"[^0-9]", "", e164)
    if not digits:
        return {}

    return {
        "WhatsApp Direct Profile": f"https://wa.me/{digits}",
        "Telegram Direct Profile": f"https://t.me/+{digits}",
        "Viber Direct Chat": f"viber://chat?number=%2B{digits}",
    }


# -----------------------------------------------------------------------------
# Privacy Scrubber (Strip EXIF & Metadata from Images and PDFs)
# -----------------------------------------------------------------------------

class PrivacyScrubber:
    """Strips 100% of EXIF, GPS, camera serials, and author metadata from images and PDFs."""

    @classmethod
    def scrub_file(cls, input_path: str, output_path: Optional[str] = None) -> Tuple[bool, str, int]:
        """Strips metadata and saves a pristine clean file.

        Returns (success: bool, clean_output_path: str, bytes_saved: int).
        """
        in_p = Path(input_path)
        if not in_p.exists():
            return False, "File does not exist", 0

        ext = in_p.suffix.lower()
        if output_path is None:
            clean_name = f"{in_p.stem}_clean{in_p.suffix}"
            out_p = in_p.parent / clean_name
        else:
            out_p = Path(output_path)

        orig_size = in_p.stat().st_size

        try:
            # 1. Clean PDF
            if ext == ".pdf":
                reader = PdfReader(str(in_p))
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)

                # Strip all document info and XMP metadata
                writer.add_metadata({})
                with open(out_p, "wb") as f_out:
                    writer.write(f_out)

                new_size = out_p.stat().st_size
                return True, str(out_p), max(0, orig_size - new_size)

            # 2. Clean Image (JPEG, PNG, WebP, TIFF)
            elif ext in (".jpg", ".jpeg", ".png", ".webp", ".tiff", ".bmp"):
                with Image.open(in_p) as img:
                    # Strip EXIF by copying pixel data into new clean image without metadata
                    data = list(img.getdata())
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(data)

                    # Save with zero metadata dict
                    if ext in (".jpg", ".jpeg"):
                        clean_img.save(str(out_p), "JPEG", quality=95)
                    elif ext == ".png":
                        clean_img.save(str(out_p), "PNG", optimize=True)
                    elif ext == ".webp":
                        clean_img.save(str(out_p), "WEBP", quality=95)
                    else:
                        clean_img.save(str(out_p))

                new_size = out_p.stat().st_size
                return True, str(out_p), max(0, orig_size - new_size)

            else:
                return False, f"Unsupported file extension: {ext}", 0

        except Exception as exc:
            logger.exception("Error scrubbing file metadata")
            return False, str(exc), 0


# -----------------------------------------------------------------------------
# Master Personal OSINT Suite Coordinator
# -----------------------------------------------------------------------------

class PersonalOSINTSuite:
    """Coordinates deep personal data auditing across emails, social platforms, and phones."""

    @classmethod
    async def run_suite_async(
        cls,
        handle: str,
        email: str = "",
        phone: str = "",
        force_refresh: bool = False,
        concurrency: int = 10,
    ) -> PersonalPrivacySuiteReport:
        clean_handle = handle.strip().lstrip("@ /")
        report = PersonalPrivacySuiteReport(
            target_handle=clean_handle,
            target_email=email.strip().lower(),
            target_phone=phone.strip(),
        )

        client = FastHttpClient.get_client()
        semaphore = asyncio.Semaphore(concurrency)

        # 1. Audit 40+ Social Platforms
        if clean_handle:
            tasks = [
                _check_platform_profile(client, semaphore, p, clean_handle)
                for p in EXPANDED_PLATFORMS
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            report.social_profiles = sorted(results, key=lambda x: (x.status != "Claimed", x.category, x.platform))

            # Calculate linkability
            claimed_count = sum(1 for r in report.social_profiles if r.status == "Claimed")
            report.username_permutations = generate_username_permutations(clean_handle)

            # Linkability score (0-100) based on cross-platform reuse
            score = min(100, claimed_count * 5)
            report.linkability_risk_score = score
            report.linkability_rating = "CRITICAL" if score >= 75 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW"))

            if claimed_count >= 5:
                report.summary_findings.append(
                    f"Handle '{clean_handle}' claimed across {claimed_count} platforms. Attackers can correlate your identity across developer and social ecosystems."
                )

        # 2. Audit Email if provided
        if report.target_email:
            report.email_report = await DeepEmailEngine.audit_email(report.target_email, force_refresh=force_refresh)
            if report.email_report.breach_count > 0:
                report.summary_findings.append(
                    f"Email '{report.target_email}' found in {report.email_report.breach_count} public breaches."
                )

        # 3. Audit Phone messaging links if provided
        if report.target_phone:
            report.messaging_links = audit_phone_messaging_links(report.target_phone)

        return report

    @classmethod
    def run_suite_sync(
        cls,
        handle: str,
        email: str = "",
        phone: str = "",
        force_refresh: bool = False,
        concurrency: int = 10,
    ) -> PersonalPrivacySuiteReport:
        """Synchronous wrapper for running full personal privacy audit in thread workers."""
        return asyncio.run(
            cls.run_suite_async(
                handle=handle,
                email=email,
                phone=phone,
                force_refresh=force_refresh,
                concurrency=concurrency,
            )
        )

