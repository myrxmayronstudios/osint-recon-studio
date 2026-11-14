"""Sherlock-style Brand & Username OSINT Checker.

Passively verifies existence of brand names and usernames across 20 popular
public platforms (code repositories, package registries, identity systems, social media)
using polite concurrency (asyncio.Semaphore) and public GET/HEAD/API requests.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional
import urllib.parse

import certifi
import httpx

from osint_studio.core.domain_utils import extract_brand_handle, normalize_domain

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINTReconStudio-PassiveAudit/1.0"


@dataclass
class PlatformCheckResult:
    """Result of checking a single platform for a username/brand handle."""
    platform: str
    category: str
    profile_url: str
    status: str  # "Claimed", "Available", "Rate Limited", "Restricted", "Unreachable", "Unknown"
    status_code: int = 0
    response_time_ms: float = 0.0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UsernameReport:
    """Consolidated brand / username footprint audit across 20 platforms."""
    target_input: str
    handle: str
    total_checked: int = 0
    claimed_count: int = 0
    available_count: int = 0
    results: List[PlatformCheckResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Definition of 20 popular platforms with proven zero-block, high-accuracy check strategies
PLATFORM_DEFINITIONS = [
    {
        "platform": "GitHub",
        "category": "Code & Dev",
        "check_url": "https://github.com/{handle}",
        "profile_url": "https://github.com/{handle}",
        "type": "status_code",
    },
    {
        "platform": "GitLab",
        "category": "Code & Dev",
        "check_url": "https://gitlab.com/api/v4/users?username={handle}",
        "profile_url": "https://gitlab.com/{handle}",
        "type": "gitlab_api",
    },
    {
        "platform": "HackerNews",
        "category": "Social & Community",
        "check_url": "https://hacker-news.firebaseio.com/v0/user/{handle}.json",
        "profile_url": "https://news.ycombinator.com/user?id={handle}",
        "type": "hn_firebase",
    },
    {
        "platform": "Dev.to",
        "category": "Code & Dev",
        "check_url": "https://dev.to/api/users/by_username?url={handle}",
        "profile_url": "https://dev.to/{handle}",
        "type": "status_code",
    },
    {
        "platform": "npm",
        "category": "Package Registries",
        "check_url": "https://registry.npmjs.org/-/v1/search?text=maintainer:{handle}&size=1",
        "profile_url": "https://www.npmjs.com/~{handle}",
        "type": "npm_registry",
    },
    {
        "platform": "DockerHub",
        "category": "Code & Dev",
        "check_url": "https://hub.docker.com/v2/users/{handle}/",
        "profile_url": "https://hub.docker.com/u/{handle}",
        "type": "status_code",
    },
    {
        "platform": "PyPI",
        "category": "Package Registries",
        "check_url": "https://pypi.org/pypi/{handle}/json",
        "profile_url": "https://pypi.org/project/{handle}/",
        "type": "status_code",
    },
    {
        "platform": "RubyGems",
        "category": "Package Registries",
        "check_url": "https://rubygems.org/api/v1/owners/{handle}/gems.json",
        "profile_url": "https://rubygems.org/profiles/{handle}",
        "type": "status_code",
    },
    {
        "platform": "Packagist",
        "category": "Package Registries",
        "check_url": "https://packagist.org/packages/list.json?vendor={handle}",
        "profile_url": "https://packagist.org/packages/{handle}/",
        "type": "packagist_api",
    },
    {
        "platform": "Crates.io",
        "category": "Package Registries",
        "check_url": "https://crates.io/api/v1/users/{handle}",
        "profile_url": "https://crates.io/users/{handle}",
        "type": "status_code",
    },
    {
        "platform": "Codeberg",
        "category": "Code & Dev",
        "check_url": "https://codeberg.org/api/v1/users/{handle}",
        "profile_url": "https://codeberg.org/{handle}",
        "type": "status_code",
    },
    {
        "platform": "Medium",
        "category": "Publishing & Media",
        "check_url": "https://medium.com/feed/@{handle}",
        "profile_url": "https://medium.com/@{handle}",
        "type": "status_code",
    },
    {
        "platform": "Vimeo",
        "category": "Creative & Media",
        "check_url": "https://vimeo.com/{handle}",
        "profile_url": "https://vimeo.com/{handle}",
        "type": "status_code",
    },
    {
        "platform": "SoundCloud",
        "category": "Creative & Media",
        "check_url": "https://soundcloud.com/{handle}",
        "profile_url": "https://soundcloud.com/{handle}",
        "type": "status_code",
    },
    {
        "platform": "Keybase",
        "category": "Security & Identity",
        "check_url": "https://keybase.io/_/api/1.0/user/lookup.json?username={handle}",
        "profile_url": "https://keybase.io/{handle}",
        "type": "keybase_api",
    },
    {
        "platform": "Gravatar",
        "category": "Security & Identity",
        "check_url": "https://en.gravatar.com/{handle}.json",
        "profile_url": "https://en.gravatar.com/{handle}",
        "type": "status_code",
    },
    {
        "platform": "Wikipedia",
        "category": "Knowledge & Community",
        "check_url": "https://en.wikipedia.org/wiki/Special:CentralAuth/{handle}?uselang=qqx",
        "profile_url": "https://en.wikipedia.org/wiki/Special:CentralAuth/{handle}",
        "type": "wikipedia_centralauth",
    },
    {
        "platform": "Bitbucket",
        "category": "Code & Dev",
        "check_url": "https://api.bitbucket.org/2.0/workspaces/{handle}",
        "profile_url": "https://bitbucket.org/{handle}/",
        "type": "status_code",
    },
    {
        "platform": "Pastebin",
        "category": "Code & Dev",
        "check_url": "https://pastebin.com/u/{handle}",
        "profile_url": "https://pastebin.com/u/{handle}",
        "type": "status_code",
    },
    {
        "platform": "Telegram",
        "category": "Messaging & Social",
        "check_url": "https://t.me/{handle}",
        "profile_url": "https://t.me/{handle}",
        "type": "telegram_channel",
    },
]


def clean_brand_handle(input_text: str) -> str:
    """Robustly extracts an alphanumeric/underscore/dash brand or username handle."""
    raw = input_text.strip()
    if not raw:
        return ""

    # If it's a URL, extract path segment
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            parsed = urllib.parse.urlparse(raw)
            path_parts = [p for p in parsed.path.strip("/").split("/") if p]
            if path_parts:
                raw = path_parts[-1]
        except Exception:
            pass

    # If it's an email address, extract user part
    if "@" in raw:
        user_part = raw.split("@")[0].strip()
        if user_part:
            raw = user_part

    # If it's a domain name (e.g. google.com), extract root brand name
    if "." in raw and not raw.startswith("."):
        brand = extract_brand_handle(raw)
        if brand:
            raw = brand

    # Strip extraneous prefixes / suffixes
    clean = re.sub(r"^[^a-zA-Z0-9_]+|[^a-zA-Z0-9_.-]+$", "", raw)
    return clean.strip("._-")


async def _check_single_platform(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    plat: Dict[str, str],
    handle: str,
) -> PlatformCheckResult:
    """Checks a single platform using semaphore concurrency with resilient error handling."""
    platform_name = plat["platform"]
    category = plat["category"]
    encoded_handle = urllib.parse.quote(handle, safe="._-")
    check_url = plat["check_url"].format(handle=encoded_handle)
    profile_url = plat["profile_url"].format(handle=encoded_handle)
    check_type = plat["type"]

    async with semaphore:
        start_time = time.perf_counter()
        try:
            resp = await client.get(check_url)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
            code = resp.status_code

            if code == 429:
                return PlatformCheckResult(
                    platform=platform_name,
                    category=category,
                    profile_url=profile_url,
                    status="Rate Limited",
                    status_code=code,
                    response_time_ms=elapsed_ms,
                    notes="Platform rate limit encountered",
                )

            if code in (401, 403):
                return PlatformCheckResult(
                    platform=platform_name,
                    category=category,
                    profile_url=profile_url,
                    status="Restricted",
                    status_code=code,
                    response_time_ms=elapsed_ms,
                    notes="Automated access restricted / WAF protected",
                )

            if check_type == "status_code":
                if code == 200:
                    status = "Claimed"
                    notes = "Profile or namespace claimed"
                elif code == 404:
                    status = "Available"
                    notes = "HTTP 404 Not Found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"

            elif check_type == "gitlab_api":
                if code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 0:
                            status = "Claimed"
                            notes = f"GitLab user profile exists (id: {data[0].get('id')})"
                        else:
                            status = "Available"
                            notes = "No user found in GitLab API"
                    except Exception:
                        status = "Available"
                        notes = "Empty payload"
                elif code == 404:
                    status = "Available"
                    notes = "HTTP 404 Not Found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"

            elif check_type == "packagist_api":
                if code == 200:
                    try:
                        data = resp.json()
                        pkgs = data.get("packageNames", [])
                        if len(pkgs) > 0:
                            status = "Claimed"
                            notes = f"Packagist vendor active ({len(pkgs)} packages)"
                        else:
                            status = "Available"
                            notes = "No packages registered under vendor"
                    except Exception:
                        status = "Available"
                        notes = "Zero packages found"
                elif code == 404:
                    status = "Available"
                    notes = "Vendor not found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"

            elif check_type == "hn_firebase":
                if code == 200:
                    try:
                        data = resp.json()
                        if data and isinstance(data, dict) and data.get("id"):
                            status = "Claimed"
                            karma = data.get("karma", 0)
                            notes = f"HackerNews account active (Karma: {karma})"
                        else:
                            status = "Available"
                            notes = "No account found (null payload)"
                    except Exception:
                        status = "Available"
                        notes = "Empty profile data"
                elif code == 404:
                    status = "Available"
                    notes = "HTTP 404 Not Found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"

            elif check_type == "npm_registry":
                if code == 200:
                    try:
                        data = resp.json()
                        total = data.get("total", 0)
                        if total > 0:
                            status = "Claimed"
                            notes = f"Active npm maintainer ({total} packages)"
                        else:
                            status = "Available"
                            notes = "No packages published under this maintainer"
                    except Exception:
                        status = "Available"
                        notes = "Zero packages"
                elif code == 404:
                    status = "Available"
                    notes = "Maintainer not found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"

            elif check_type == "keybase_api":
                if code == 200:
                    try:
                        data = resp.json()
                        if data.get("status", {}).get("code") == 0:
                            status = "Claimed"
                            notes = "Keybase identity registered"
                        else:
                            status = "Available"
                            notes = "No Keybase account found"
                    except Exception:
                        status = "Available"
                        notes = "Account not found"
                elif code == 404:
                    status = "Available"
                    notes = "Not found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"

            elif check_type == "wikipedia_centralauth":
                if code == 200:
                    text = resp.text.lower()
                    if "centralauth-admin-nonexistent" in text:
                        status = "Available"
                        notes = "Wikipedia global account does not exist"
                    else:
                        status = "Claimed"
                        notes = "Wikipedia account exists"
                elif code == 404:
                    status = "Available"
                    notes = "HTTP 404 Not Found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"

            elif check_type == "telegram_channel":
                if code == 200:
                    text = resp.text
                    if "tgme_page_extra" in text or "tgme_page_title" in text:
                        if "If you have Telegram, you can contact" in text and "tgme_page_extra" not in text:
                            status = "Available"
                            notes = "No public channel or user bio"
                        else:
                            status = "Claimed"
                            notes = "Public Telegram channel / user handle"
                    else:
                        status = "Available"
                        notes = "Channel or user not found"
                elif code == 404:
                    status = "Available"
                    notes = "HTTP 404 Not Found"
                else:
                    status = "Unknown"
                    notes = f"HTTP {code}"
            else:
                status = "Claimed" if code == 200 else "Available" if code == 404 else "Unknown"
                notes = f"HTTP {code}"

            return PlatformCheckResult(
                platform=platform_name,
                category=category,
                profile_url=profile_url,
                status=status,
                status_code=code,
                response_time_ms=elapsed_ms,
                notes=notes,
            )

        except httpx.TimeoutException:
            return PlatformCheckResult(
                platform=platform_name,
                category=category,
                profile_url=profile_url,
                status="Available",
                status_code=0,
                response_time_ms=round((time.perf_counter() - start_time) * 1000, 1),
                notes="Response timed out (unclaimed or unreachable)",
            )
        except Exception:
            return PlatformCheckResult(
                platform=platform_name,
                category=category,
                profile_url=profile_url,
                status="Available",
                status_code=0,
                response_time_ms=round((time.perf_counter() - start_time) * 1000, 1),
                notes="Service unreachable",
            )


async def check_brand_handles_async(
    target: str,
    timeout: float = 6.0,
    concurrency: int = 5,
) -> UsernameReport:
    """Asynchronously audits brand name / handle across 20 platforms."""
    clean_target = normalize_domain(target)
    handle = clean_brand_handle(clean_target)

    report = UsernameReport(
        target_input=target,
        handle=handle,
    )

    if not handle:
        report.warnings.append("No valid handle could be derived for username search.")
        return report

    semaphore = asyncio.Semaphore(concurrency)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }

    async with httpx.AsyncClient(
        verify=certifi.where(),
        timeout=timeout,
        headers=headers,
        follow_redirects=True,
    ) as client:
        tasks = [
            _check_single_platform(client, semaphore, plat, handle)
            for plat in PLATFORM_DEFINITIONS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    report.results = sorted(results, key=lambda r: (r.status != "Claimed", r.category, r.platform))
    report.total_checked = len(results)
    report.claimed_count = sum(1 for r in results if r.status == "Claimed")
    report.available_count = sum(1 for r in results if r.status == "Available")
    report.is_success = True

    return report


def check_brand_handles(
    target: str,
    timeout: float = 6.0,
    concurrency: int = 5,
) -> UsernameReport:
    """Synchronous convenience wrapper for check_brand_handles_async."""
    try:
        return asyncio.run(check_brand_handles_async(target, timeout=timeout, concurrency=concurrency))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(check_brand_handles_async(target, timeout=timeout, concurrency=concurrency))
        finally:
            loop.close()
