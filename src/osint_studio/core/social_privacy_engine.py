"""Social Media Public Exposure & OpenGraph Metadata Auditor.

Performs strictly legal, unauthenticated public profile inspections across major social platforms
(Instagram, Facebook, X/Twitter, TikTok, LinkedIn, Reddit, YouTube, GitHub) to discover
exposed OpenGraph metadata (og:title, og:description, og:image) and calculate a
Personal Dossier Linkability Score with defensive privacy hardening recommendations.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import logging
import re
from typing import Any, Dict, List, Optional

import certifi
import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Definition of the 8 major social platforms
SOCIAL_PLATFORMS = [
    {
        "platform": "GitHub",
        "url_template": "https://github.com/{handle}",
        "category": "Developer & Code",
    },
    {
        "platform": "Reddit",
        "url_template": "https://www.reddit.com/user/{handle}/",
        "category": "Discussion & Community",
    },
    {
        "platform": "YouTube",
        "url_template": "https://www.youtube.com/@{handle}",
        "category": "Video & Media",
    },
    {
        "platform": "X / Twitter",
        "url_template": "https://x.com/{handle}",
        "category": "Microblogging",
    },
    {
        "platform": "LinkedIn",
        "url_template": "https://www.linkedin.com/in/{handle}/",
        "category": "Professional",
    },
    {
        "platform": "Instagram",
        "url_template": "https://www.instagram.com/{handle}/",
        "category": "Photos & Social",
    },
    {
        "platform": "TikTok",
        "url_template": "https://www.tiktok.com/@{handle}",
        "category": "Short Video",
    },
    {
        "platform": "Facebook",
        "url_template": "https://www.facebook.com/{handle}",
        "category": "Social Network",
    },
]


@dataclass
class SocialProfileFinding:
    """Publicly exposed metadata from a single social network profile."""
    platform: str
    category: str
    profile_url: str
    status: str            # "Publicly Reachable", "Available / Not Found", "Login Wall / Gated", "Rate Limited", "Error"
    status_code: int = 0
    og_title: str = ""
    og_description: str = ""
    og_image: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SocialPrivacyReport:
    """Consolidated cross-platform profile exposure and linkability analysis report."""
    handle: str
    total_platforms_checked: int = 0
    public_profiles_found: int = 0
    gated_profiles_found: int = 0
    profiles: List[SocialProfileFinding] = field(default_factory=list)
    linkability_score: int = 0        # 0-100 (Higher = more linkable / higher privacy correlation risk)
    linkability_rating: str = "LOW"   # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    cross_correlation_risks: List[str] = field(default_factory=list)
    hardening_tips: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_og_tag(html_text: str, property_name: str) -> str:
    """Safely extracts OpenGraph meta content from HTML string via regex without third-party parser."""
    pattern = rf'<meta\s+[^>]*property=["\']og:{property_name}["\'][^>]*content=["\']([^"\']*)["\']'
    match = re.search(pattern, html_text, re.IGNORECASE)
    if not match:
        pattern_rev = rf'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']og:{property_name}["\']'
        match = re.search(pattern_rev, html_text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


async def _inspect_social_platform(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    platform_def: Dict[str, str],
    handle: str,
) -> SocialProfileFinding:
    """Inspects a single social platform for public exposure and OpenGraph metadata."""
    name = platform_def["platform"]
    cat = platform_def["category"]
    url = platform_def["url_template"].format(handle=handle)

    async with semaphore:
        try:
            resp = await client.get(url, follow_redirects=True)
            code = resp.status_code

            if code == 200:
                html_body = resp.text
                og_title = _extract_og_tag(html_body, "title")
                og_desc = _extract_og_tag(html_body, "description")
                og_img = _extract_og_tag(html_body, "image")

                # Basic validation: check if page indicates not found in text
                lower_text = html_body.lower()
                if "page not found" in lower_text or "this account doesn't exist" in lower_text or "user not found" in lower_text:
                    return SocialProfileFinding(
                        platform=name,
                        category=cat,
                        profile_url=url,
                        status="Available / Not Found",
                        status_code=404,
                        notes="Page returned 404 / User Not Found message in body",
                    )

                return SocialProfileFinding(
                    platform=name,
                    category=cat,
                    profile_url=url,
                    status="Publicly Reachable",
                    status_code=code,
                    og_title=og_title,
                    og_description=og_desc,
                    og_image=og_img,
                    notes="Profile is publicly accessible without authentication",
                )

            elif code in (404, 410):
                return SocialProfileFinding(
                    platform=name,
                    category=cat,
                    profile_url=url,
                    status="Available / Not Found",
                    status_code=code,
                    notes="Profile not found or username available",
                )

            elif code in (401, 403, 302, 301):
                return SocialProfileFinding(
                    platform=name,
                    category=cat,
                    profile_url=url,
                    status="Login Wall / Gated",
                    status_code=code,
                    notes=f"HTTP {code} - Access requires authentication or is restricted",
                )

            elif code == 429:
                return SocialProfileFinding(
                    platform=name,
                    category=cat,
                    profile_url=url,
                    status="Rate Limited",
                    status_code=code,
                    notes="Platform rate limit encountered",
                )

            else:
                return SocialProfileFinding(
                    platform=name,
                    category=cat,
                    profile_url=url,
                    status="Unknown",
                    status_code=code,
                    notes=f"HTTP status {code}",
                )

        except httpx.TimeoutException:
            return SocialProfileFinding(
                platform=name,
                category=cat,
                profile_url=url,
                status="Unreachable",
                status_code=0,
                notes="Platform timed out or slow to respond",
            )
        except Exception:
            return SocialProfileFinding(
                platform=name,
                category=cat,
                profile_url=url,
                status="Available / Not Found",
                status_code=0,
                notes="Service unreachable",
            )


class SocialPrivacyEngine:
    """Audits cross-platform username handle reuse and unauthenticated metadata leaks."""

    @classmethod
    def audit_social_handle(cls, handle: str, timeout: float = 8.0) -> SocialPrivacyReport:
        try:
            return asyncio.run(cls.audit_social_handle_async(handle, timeout=timeout))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(cls.audit_social_handle_async(handle, timeout=timeout))
            finally:
                loop.close()

    @classmethod
    async def audit_social_handle_async(cls, handle: str, timeout: float = 8.0) -> SocialPrivacyReport:
        clean_handle = handle.strip().lstrip("@ /")
        report = SocialPrivacyReport(handle=clean_handle)

        if not clean_handle:
            report.warnings.append("No username handle supplied for social audit.")
            return report

        semaphore = asyncio.Semaphore(4)
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with httpx.AsyncClient(
            verify=certifi.where(),
            timeout=timeout,
            headers=headers,
            follow_redirects=True,
        ) as client:
            tasks = [
                _inspect_social_platform(client, semaphore, pdef, clean_handle)
                for pdef in SOCIAL_PLATFORMS
            ]
            results = await asyncio.gather(*tasks)

        report.profiles = list(results)
        report.total_platforms_checked = len(results)

        reachable = [r for r in results if r.status == "Publicly Reachable"]
        gated = [r for r in results if r.status == "Login Wall / Gated"]

        report.public_profiles_found = len(reachable)
        report.gated_profiles_found = len(gated)

        # Calculate Linkability Score (0-100)
        # Higher score = more correlated / higher exposure risk
        found_count = len(reachable) + len(gated)
        link_score = int(min(100, (found_count / len(SOCIAL_PLATFORMS)) * 100))
        report.linkability_score = link_score

        if link_score >= 70:
            report.linkability_rating = "CRITICAL"
        elif link_score >= 50:
            report.linkability_rating = "HIGH"
        elif link_score >= 25:
            report.linkability_rating = "MEDIUM"
        else:
            report.linkability_rating = "LOW"

        # Cross-Correlation & Hardening Guidance
        platforms_claimed = [r.platform for r in reachable]

        if len(platforms_claimed) >= 3:
            report.cross_correlation_risks.append(
                f"Identical handle '{clean_handle}' is publicly active across {len(platforms_claimed)} platforms: {', '.join(platforms_claimed)}."
            )
            report.hardening_tips.append(
                "Cross-Platform Identity Correlation: Using the exact same handle across personal platforms (Instagram, TikTok) and professional/code platforms (GitHub, LinkedIn) enables automated OSINT tracking. Consider separating personal and public handles."
            )

        # Check for exposed bios/descriptions in OpenGraph
        exposed_descriptions = [r for r in reachable if r.og_description]
        if exposed_descriptions:
            report.cross_correlation_risks.append(
                f"{len(exposed_descriptions)} platform profiles publicly broadcast unauthenticated bios/descriptions in OpenGraph headers without requiring a login."
            )

        report.hardening_tips.append(
            "Review public profile visibility settings on each claimed service to disable public search engine indexing if personal anonymity is desired."
        )

        report.is_success = True
        return report
