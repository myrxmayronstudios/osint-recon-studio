"""GitHub Organization and Public Code Footprint OSINT Engine.

Passively inventories public repositories, languages, stars, forks, and disclosure
policies (SECURITY.md) via GitHub's official REST API without any active scraping.
Supports optional personal access tokens to elevate rate limits from 60 to 5,000 req/hr.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import logging
from typing import Any, Dict, List, Optional

import certifi
import httpx

from osint_studio.core.domain_utils import extract_brand_handle, normalize_domain

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
GITHUB_API_BASE = "https://api.github.com"


@dataclass
class GitHubRepo:
    """Public repository metadata."""
    name: str
    full_name: str
    html_url: str
    description: str = ""
    language: str = "Unknown"
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    updated_at: str = ""
    is_fork: bool = False
    is_archived: bool = False
    topics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GitHubOrgReport:
    """Consolidated GitHub organization / account footprint report."""
    target_input: str
    handle: str
    entity_type: str = "Unknown"  # "Organization", "User", or "Not Found"
    name: str = ""
    description: str = ""
    blog: str = ""
    location: str = ""
    email: str = ""
    twitter_username: str = ""
    public_repos_count: int = 0
    followers: int = 0
    created_at: str = ""
    html_url: str = ""
    avatar_url: str = ""
    has_security_policy: bool = False
    security_policy_url: str = ""
    repos: List[GitHubRepo] = field(default_factory=list)
    total_stars: int = 0
    total_forks: int = 0
    languages_summary: Dict[str, int] = field(default_factory=dict)
    rate_limit_remaining: Optional[int] = None
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


async def audit_github_footprint_async(
    target: str,
    token: Optional[str] = None,
    timeout: float = 10.0,
) -> GitHubOrgReport:
    """Asynchronously gathers GitHub public organization footprint."""
    clean_target = normalize_domain(target)
    handle = extract_brand_handle(clean_target) if "." in clean_target else clean_target.strip("@ /")

    report = GitHubOrgReport(
        target_input=target,
        handle=handle,
    )

    if not handle:
        report.warnings.append("Empty or invalid brand handle derived from target.")
        return report

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github.v3+json",
    }
    if token and token.strip():
        auth_val = token.strip()
        headers["Authorization"] = f"Bearer {auth_val}" if not auth_val.startswith(("Bearer ", "token ")) else auth_val

    async with httpx.AsyncClient(
        verify=certifi.where(),
        timeout=timeout,
        headers=headers,
        follow_redirects=True,
    ) as client:
        # Step 1: Query Organization endpoint first
        org_url = f"{GITHUB_API_BASE}/orgs/{handle}"
        user_url = f"{GITHUB_API_BASE}/users/{handle}"
        entity_data: Dict[str, Any] = {}
        entity_type = "Organization"

        try:
            resp = await client.get(org_url)
            _record_rate_limit(report, resp)

            if resp.status_code == 200:
                entity_data = resp.json()
                entity_type = "Organization"
            elif resp.status_code == 404:
                # Fall back to user endpoint
                user_resp = await client.get(user_url)
                _record_rate_limit(report, user_resp)
                if user_resp.status_code == 200:
                    entity_data = user_resp.json()
                    entity_type = "User"
                elif user_resp.status_code == 404:
                    report.entity_type = "Not Found"
                    report.warnings.append(f"No public GitHub Organization or User found matching handle '{handle}'.")
                    report.is_success = True
                    return report
                elif user_resp.status_code == 403:
                    _handle_rate_limit_error(report, user_resp)
                    return report
            elif resp.status_code == 403:
                _handle_rate_limit_error(report, resp)
                return report
            else:
                report.warnings.append(f"GitHub API returned HTTP {resp.status_code}: {resp.text[:120]}")
                return report

        except Exception as exc:
            logger.warning("Error querying GitHub profile for '%s': %s", handle, exc)
            report.warnings.append(f"Network error querying GitHub profile: {exc}")
            return report

        # Populate profile information
        report.entity_type = entity_type
        report.name = entity_data.get("name") or handle
        report.description = entity_data.get("description") or entity_data.get("bio") or ""
        report.blog = entity_data.get("blog") or ""
        report.location = entity_data.get("location") or ""
        report.email = entity_data.get("email") or ""
        report.twitter_username = entity_data.get("twitter_username") or ""
        report.public_repos_count = entity_data.get("public_repos") or 0
        report.followers = entity_data.get("followers") or 0
        report.created_at = entity_data.get("created_at") or ""
        report.html_url = entity_data.get("html_url") or f"https://github.com/{handle}"
        report.avatar_url = entity_data.get("avatar_url") or ""

        # Step 2: Query public repos
        repos_url = f"{GITHUB_API_BASE}/orgs/{handle}/repos" if entity_type == "Organization" else f"{GITHUB_API_BASE}/users/{handle}/repos"
        try:
            repos_resp = await client.get(repos_url, params={"per_page": 30, "sort": "updated"})
            if repos_resp.status_code == 200:
                raw_repos = repos_resp.json()
                if isinstance(raw_repos, list):
                    for r in raw_repos:
                        repo = GitHubRepo(
                            name=r.get("name") or "",
                            full_name=r.get("full_name") or "",
                            html_url=r.get("html_url") or "",
                            description=r.get("description") or "",
                            language=r.get("language") or "Unknown",
                            stars=r.get("stargazers_count") or 0,
                            forks=r.get("forks_count") or 0,
                            open_issues=r.get("open_issues_count") or 0,
                            updated_at=r.get("updated_at") or "",
                            is_fork=bool(r.get("fork")),
                            is_archived=bool(r.get("archived")),
                            topics=r.get("topics") or [],
                        )
                        report.repos.append(repo)
                        report.total_stars += repo.stars
                        report.total_forks += repo.forks

                        lang = repo.language
                        if lang and lang != "Unknown":
                            report.languages_summary[lang] = report.languages_summary.get(lang, 0) + 1
        except Exception as exc:
            logger.warning("Error retrieving GitHub repos for '%s': %s", handle, exc)
            report.warnings.append(f"Failed to query repository list: {exc}")

        # Step 3: Check for SECURITY.md policy
        await _check_security_policy(client, handle, entity_type, report)

        report.is_success = True
        return report


async def _check_security_policy(
    client: httpx.AsyncClient,
    handle: str,
    entity_type: str,
    report: GitHubOrgReport,
) -> None:
    """Checks whether the organization or account publishes a security vulnerability policy."""
    # Check 1: Org community profile endpoint
    if entity_type == "Organization":
        try:
            comm_resp = await client.get(f"{GITHUB_API_BASE}/orgs/{handle}/community/profile")
            if comm_resp.status_code == 200:
                data = comm_resp.json()
                files = data.get("files") or {}
                sec = files.get("security_policy")
                if sec and isinstance(sec, dict) and sec.get("url"):
                    report.has_security_policy = True
                    report.security_policy_url = sec.get("html_url") or sec.get("url") or ""
                    return
        except Exception:
            pass

    # Check 2: Raw GitHub content check for .github/SECURITY.md
    candidates = [
        f"https://raw.githubusercontent.com/{handle}/.github/main/SECURITY.md",
        f"https://raw.githubusercontent.com/{handle}/.github/master/SECURITY.md",
        f"https://raw.githubusercontent.com/{handle}/{handle}/main/SECURITY.md",
    ]
    for cand in candidates:
        try:
            cand_resp = await client.head(cand)
            if cand_resp.status_code == 200:
                report.has_security_policy = True
                report.security_policy_url = cand.replace("raw.githubusercontent.com", "github.com").replace("/main/", "/blob/main/").replace("/master/", "/blob/master/")
                return
        except Exception:
            pass


def _record_rate_limit(report: GitHubOrgReport, resp: httpx.Response) -> None:
    rem = resp.headers.get("x-ratelimit-remaining")
    if rem is not None:
        try:
            report.rate_limit_remaining = int(rem)
        except ValueError:
            pass


def _handle_rate_limit_error(report: GitHubOrgReport, resp: httpx.Response) -> None:
    rem = resp.headers.get("x-ratelimit-remaining", "0")
    reset_epoch = resp.headers.get("x-ratelimit-reset", "")
    report.warnings.append(
        f"GitHub API rate limit reached (Remaining: {rem}). Add a GitHub Personal Access Token in Settings to raise limit to 5,000 req/hr."
    )


def audit_github_footprint(
    target: str,
    token: Optional[str] = None,
    timeout: float = 10.0,
) -> GitHubOrgReport:
    """Synchronous convenience wrapper for audit_github_footprint_async."""
    try:
        return asyncio.run(audit_github_footprint_async(target, token=token, timeout=timeout))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(audit_github_footprint_async(target, token=token, timeout=timeout))
        finally:
            loop.close()
