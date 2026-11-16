"""Expanded Legal Personal OSINT Suite for OSINT Recon Studio.

Provides 5 strictly legal, passive personal intelligence engines operating on
public APIs and open registries without requiring API keys or unauthorized scraping:
1. DevFootprintEngine: Public Git commit emails, author names, and package maintainer metadata.
2. AcademicIdentityEngine: OpenAlex & ORCID v3.0 public author and research affiliations.
3. ActivityCadenceEngine: 24-hour temporal activity histogram and probable timezone estimator.
4. PublicRecordsEngine: Wikidata entity search, ProPublica nonprofit officer registry, and portfolio snapshots.
5. Web3IdentityEngine: Public Ethereum Name Service (ENS) .eth resolver and decentralized identity mapping.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import datetime
import logging
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

import certifi
import httpx

from osint_studio.core.domain_utils import extract_brand_handle, normalize_domain

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"


# =============================================================================
# 1. Dev & Package Maintainer Footprint Engine
# =============================================================================

@dataclass
class PackageItem:
    """Public software package maintained by the target."""
    registry: str  # PyPI, npm, Crates.io, DockerHub
    name: str
    version: str = ""
    summary: str = ""
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DevFootprintReport:
    """Developer, commit history, and package maintainer footprint."""
    handle: str
    commit_emails: List[str] = field(default_factory=list)
    commit_authors: List[str] = field(default_factory=list)
    packages: List[PackageItem] = field(default_factory=list)
    public_events_count: int = 0
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handle": self.handle,
            "commit_emails": self.commit_emails,
            "commit_authors": self.commit_authors,
            "packages": [p.to_dict() for p in self.packages],
            "public_events_count": self.public_events_count,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class DevFootprintEngine:
    """Passively uncovers publicly committed author identities and package registry profiles."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    async def analyze(self, client: httpx.AsyncClient, handle: str) -> DevFootprintReport:
        clean_handle = handle.strip().lstrip("@").split("/")[0]
        report = DevFootprintReport(handle=clean_handle)
        if not clean_handle:
            report.warnings.append("Empty developer handle provided.")
            return report

        # Step A: Query GitHub Public Events for commit emails & author names
        try:
            gh_url = f"https://api.github.com/users/{clean_handle}/events/public"
            r = await client.get(gh_url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github.v3+json"}, timeout=self.timeout)
            if r.status_code == 200:
                events = r.json()
                if isinstance(events, list):
                    report.public_events_count = len(events)
                    emails_set = set()
                    authors_set = set()
                    for ev in events:
                        if not isinstance(ev, dict):
                            continue
                        if ev.get("type") == "PushEvent":
                            payload = ev.get("payload") or {}
                            commits = payload.get("commits") or []
                            for c in commits:
                                if isinstance(c, dict):
                                    author = c.get("author") or {}
                                    em = author.get("email") or ""
                                    nm = author.get("name") or ""
                                    if em and "@" in em and "noreply.github.com" not in em:
                                        emails_set.add(em.strip().lower())
                                    if nm and len(nm) > 1:
                                        authors_set.add(nm.strip())
                    report.commit_emails = sorted(list(emails_set))
                    report.commit_authors = sorted(list(authors_set))
                    report.is_success = True
            elif r.status_code == 403:
                report.warnings.append("GitHub API rate-limit reached for public events.")
        except Exception as exc:
            logger.debug("GitHub events mining error for %s: %s", clean_handle, exc)

        # Step B: Package Registries (PyPI, npm, Crates.io)
        # 1. PyPI
        try:
            pypi_url = f"https://pypi.org/pypi/{clean_handle}/json"
            r_pypi = await client.get(pypi_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_pypi.status_code == 200:
                p_data = r_pypi.json() or {}
                info = p_data.get("info") or {}
                report.packages.append(
                    PackageItem(
                        registry="PyPI",
                        name=info.get("name") or clean_handle,
                        version=info.get("version") or "",
                        summary=info.get("summary") or "Python Package",
                        url=info.get("package_url") or f"https://pypi.org/project/{clean_handle}/",
                    )
                )
                report.is_success = True
        except Exception:
            pass

        # 2. npm (maintainer search)
        try:
            npm_url = f"https://registry.npmjs.org/-/v1/search?text=maintainer:{clean_handle}&size=5"
            r_npm = await client.get(npm_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_npm.status_code == 200:
                npm_data = r_npm.json() or {}
                objects = npm_data.get("objects") or []
                for obj in objects:
                    pkg = obj.get("package") or {}
                    p_name = pkg.get("name") or ""
                    if p_name:
                        report.packages.append(
                            PackageItem(
                                registry="npm",
                                name=p_name,
                                version=pkg.get("version") or "",
                                summary=pkg.get("description") or "npm package",
                                url=pkg.get("links", {}).get("npm") or f"https://www.npmjs.com/package/{p_name}",
                            )
                        )
                        report.is_success = True
        except Exception:
            pass

        # 3. Crates.io
        try:
            crates_url = f"https://crates.io/api/v1/users/{clean_handle}"
            r_crates = await client.get(crates_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_crates.status_code == 200:
                c_data = r_crates.json() or {}
                user = c_data.get("user") or {}
                if user.get("login"):
                    report.packages.append(
                        PackageItem(
                            registry="Crates.io",
                            name=f"User: {user.get('login')}",
                            summary=user.get("name") or "Rust Crate Author",
                            url=user.get("url") or f"https://crates.io/users/{clean_handle}",
                        )
                    )
                    report.is_success = True
        except Exception:
            pass

        return report


# =============================================================================
# 2. Academic & Institutional Affiliation Engine
# =============================================================================

@dataclass
class AcademicItem:
    """Academic paper or scholarly output."""
    title: str
    year: str = ""
    doi: str = ""
    citations_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AcademicReport:
    """Academic publications and institutional affiliations."""
    query: str
    display_name: str = ""
    orcid: str = ""
    affiliations: List[str] = field(default_factory=list)
    works_count: int = 0
    cited_by_count: int = 0
    top_topics: List[str] = field(default_factory=list)
    recent_works: List[AcademicItem] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "display_name": self.display_name,
            "orcid": self.orcid,
            "affiliations": self.affiliations,
            "works_count": self.works_count,
            "cited_by_count": self.cited_by_count,
            "top_topics": self.top_topics,
            "recent_works": [w.to_dict() for w in self.recent_works],
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class AcademicIdentityEngine:
    """Queries OpenAlex and ORCID v3.0 public APIs for institutional affiliations and research."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    async def analyze(self, client: httpx.AsyncClient, name_or_query: str) -> AcademicReport:
        clean_q = name_or_query.strip().lstrip("@")
        report = AcademicReport(query=clean_q)
        if not clean_q:
            report.warnings.append("No academic query provided.")
            return report

        # Step 1: OpenAlex API
        try:
            encoded_q = urllib.parse.quote(clean_q)
            openalex_url = f"https://api.openalex.org/authors?search={encoded_q}&per-page=3"
            r = await client.get(openalex_url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json() or {}
                results = data.get("results") or []
                if results and isinstance(results, list):
                    primary = results[0]
                    report.display_name = primary.get("display_name") or clean_q
                    raw_orcid = primary.get("orcid") or (primary.get("ids") or {}).get("orcid") or ""
                    report.orcid = raw_orcid.replace("https://orcid.org/", "") if raw_orcid else ""
                    report.works_count = primary.get("works_count") or 0
                    report.cited_by_count = primary.get("cited_by_count") or 0

                    last_inst = primary.get("last_known_institution") or {}
                    inst_name = last_inst.get("display_name") or ""
                    inst_country = last_inst.get("country_code") or ""
                    if inst_name:
                        report.affiliations.append(f"{inst_name} ({inst_country})" if inst_country else inst_name)

                    topics = primary.get("topics") or []
                    for t in topics[:4]:
                        t_name = t.get("display_name") or ""
                        if t_name and t_name not in report.top_topics:
                            report.top_topics.append(t_name)

                    report.is_success = True
        except Exception as exc:
            logger.debug("OpenAlex query error for %s: %s", clean_q, exc)

        # Step 2: ORCID Public API v3.0 Expanded Search
        try:
            orcid_query = clean_q
            orcid_url = f"https://pub.orcid.org/v3.0/expanded-search/?q={urllib.parse.quote(orcid_query)}&rows=3"
            r_orcid = await client.get(orcid_url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, timeout=self.timeout)
            if r_orcid.status_code == 200:
                o_data = r_orcid.json() or {}
                expanded = o_data.get("expanded-result") or []
                if expanded and isinstance(expanded, list):
                    first = expanded[0]
                    o_id = first.get("orcid-id") or ""
                    if o_id and not report.orcid:
                        report.orcid = o_id
                    inst_names = first.get("institution-name") or []
                    for inst in inst_names:
                        if inst and inst not in report.affiliations:
                            report.affiliations.append(inst)
                    report.is_success = True
        except Exception as exc:
            logger.debug("ORCID query error for %s: %s", clean_q, exc)

        return report


# =============================================================================
# 3. Temporal Activity Cadence & Probable Timezone Engine
# =============================================================================

@dataclass
class ActivityCadenceReport:
    """24-hour activity distribution and estimated timezone."""
    handle: str
    total_events: int = 0
    hourly_distribution: Dict[int, int] = field(default_factory=dict)
    peak_hours_utc: List[int] = field(default_factory=list)
    quiet_window_utc: str = ""
    estimated_active_window: str = ""
    probable_timezone_offset: str = ""
    probable_region: str = ""
    ascii_chart: str = ""
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handle": self.handle,
            "total_events": self.total_events,
            "hourly_distribution": self.hourly_distribution,
            "peak_hours_utc": self.peak_hours_utc,
            "quiet_window_utc": self.quiet_window_utc,
            "estimated_active_window": self.estimated_active_window,
            "probable_timezone_offset": self.probable_timezone_offset,
            "probable_region": self.probable_region,
            "ascii_chart": self.ascii_chart,
            "is_success": self.is_success,
        }


class ActivityCadenceEngine:
    """Analyzes timestamp telemetry across public developer/social activities to infer timezone."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    async def analyze(self, client: httpx.AsyncClient, handle: str) -> ActivityCadenceReport:
        clean_handle = handle.strip().lstrip("@")
        report = ActivityCadenceReport(handle=clean_handle)
        hourly_counts = {h: 0 for h in range(24)}
        utc_hours: List[int] = []

        # 1. GitHub public events timestamps
        try:
            gh_url = f"https://api.github.com/users/{clean_handle}/events/public"
            r = await client.get(gh_url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github.v3+json"}, timeout=self.timeout)
            if r.status_code == 200:
                events = r.json() or []
                if isinstance(events, list):
                    for ev in events:
                        if isinstance(ev, dict) and ev.get("created_at"):
                            try:
                                dt = datetime.datetime.fromisoformat(ev["created_at"].replace("Z", "+00:00"))
                                utc_hours.append(dt.hour)
                            except Exception:
                                pass
        except Exception:
            pass

        # 2. HackerNews public activity timestamps via Algolia
        try:
            hn_url = f"https://hn.algolia.com/api/v1/search?tags=author_{clean_handle}&hitsPerPage=30"
            r_hn = await client.get(hn_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_hn.status_code == 200:
                data = r_hn.json() or {}
                hits = data.get("hits") or []
                for h in hits:
                    created_i = h.get("created_at_i")
                    if created_i:
                        try:
                            dt = datetime.datetime.fromtimestamp(created_i, tz=datetime.timezone.utc)
                            utc_hours.append(dt.hour)
                        except Exception:
                            pass
        except Exception:
            pass

        # 3. Reddit public submissions
        try:
            reddit_url = f"https://www.reddit.com/user/{clean_handle}/submitted.json?limit=25"
            r_red = await client.get(reddit_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_red.status_code == 200:
                data = r_red.json() or {}
                children = (data.get("data") or {}).get("children") or []
                for child in children:
                    c_data = (child.get("data") or {})
                    created_utc = c_data.get("created_utc")
                    if created_utc:
                        try:
                            dt = datetime.datetime.fromtimestamp(created_utc, tz=datetime.timezone.utc)
                            utc_hours.append(dt.hour)
                        except Exception:
                            pass
        except Exception:
            pass

        report.total_events = len(utc_hours)
        if report.total_events < 2:
            report.is_success = False
            report.probable_timezone_offset = "Insufficient timestamp data"
            return report

        for hr in utc_hours:
            hourly_counts[hr] += 1
        report.hourly_distribution = hourly_counts

        # Find quiet window (minimum consecutive 7 hours)
        min_sum = 999999
        quiet_start = 0
        for i in range(24):
            window_sum = sum(hourly_counts[(i + j) % 24] for j in range(7))
            if window_sum < min_sum:
                min_sum = window_sum
                quiet_start = i

        quiet_end = (quiet_start + 7) % 24
        report.quiet_window_utc = f"{quiet_start:02d}:00 – {quiet_end:02d}:00 UTC"
        wake_start = quiet_end
        wake_end = quiet_start
        report.estimated_active_window = f"{wake_start:02d}:00 – {wake_end:02d}:00 UTC"

        # If sleep is typically 00:00–07:00 local time,
        # quiet_start UTC corresponds to local 00:00.
        # offset = local_time - utc_time = 0 - quiet_start = -quiet_start
        raw_offset = -quiet_start
        if raw_offset < -12:
            raw_offset += 24
        elif raw_offset > 14:
            raw_offset -= 24

        sign = "+" if raw_offset >= 0 else "-"
        report.probable_timezone_offset = f"UTC{sign}{abs(raw_offset)}"

        # Region approximation
        if raw_offset in (-8, -7):
            report.probable_region = "US Pacific / West Coast (UTC-8 / UTC-7)"
        elif raw_offset in (-6, -5):
            report.probable_region = "US Central / Eastern (UTC-6 / UTC-5)"
        elif raw_offset in (-4, -3):
            report.probable_region = "South America / Atlantic (UTC-4 / UTC-3)"
        elif raw_offset in (0, 1):
            report.probable_region = "Western Europe / UK / West Africa (UTC+0 / UTC+1)"
        elif raw_offset in (2, 3):
            report.probable_region = "Eastern Europe / Middle East / East Africa (UTC+2 / UTC+3)"
        elif raw_offset in (5, 6):
            report.probable_region = "South Asia / India (UTC+5 / UTC+6)"
        elif raw_offset in (7, 8):
            report.probable_region = "East / Southeast Asia (UTC+7 / UTC+8)"
        elif raw_offset in (9, 10):
            report.probable_region = "Japan / Australia East (UTC+9 / UTC+10)"
        else:
            report.probable_region = f"Global Belt {report.probable_timezone_offset}"

        # Generate clean ASCII chart
        max_val = max(hourly_counts.values()) or 1
        lines = []
        for h in range(0, 24, 2):
            cnt = hourly_counts[h] + hourly_counts[(h + 1) % 24]
            bars = int((cnt / (max_val * 2 or 1)) * 16)
            bar_str = "■" * bars
            lines.append(f"{h:02d}:00 [{bar_str:<16}] {cnt}")
        report.ascii_chart = "\n".join(lines)
        report.is_success = True
        return report


# =============================================================================
# 4. Public Corporate & Historical Records Engine
# =============================================================================

@dataclass
class PublicRecordItem:
    """Public corporate or nonprofit entity match."""
    source: str  # Wikidata, ProPublica, Wayback
    title: str
    description: str = ""
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PublicRecordsReport:
    """Historical corporate, nonprofit, and biographical records."""
    query: str
    items: List[PublicRecordItem] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "items": [i.to_dict() for i in self.items],
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class PublicRecordsEngine:
    """Queries Wikidata and ProPublica Nonprofit Explorer for public leadership and roles."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    async def analyze(self, client: httpx.AsyncClient, name_or_query: str) -> PublicRecordsReport:
        clean_q = name_or_query.strip().lstrip("@")
        report = PublicRecordsReport(query=clean_q)
        if not clean_q:
            report.warnings.append("No entity query provided.")
            return report

        # 1. Wikidata entity search
        try:
            w_url = f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={urllib.parse.quote(clean_q)}&language=en&format=json&limit=4"
            r_wiki = await client.get(w_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_wiki.status_code == 200:
                w_data = r_wiki.json() or {}
                search_results = w_data.get("search") or []
                for s in search_results:
                    lbl = s.get("label") or ""
                    desc = s.get("description") or ""
                    w_id = s.get("id") or ""
                    if lbl and w_id:
                        report.items.append(
                            PublicRecordItem(
                                source="Wikidata",
                                title=f"{lbl} ({w_id})",
                                description=desc,
                                url=f"https://www.wikidata.org/wiki/{w_id}",
                            )
                        )
                        report.is_success = True
        except Exception as exc:
            logger.debug("Wikidata entity search error for %s: %s", clean_q, exc)

        # 2. ProPublica Nonprofit Explorer public API
        try:
            pp_url = f"https://projects.propublica.org/nonprofits/api/v2/search.json?q={urllib.parse.quote(clean_q)}"
            r_pp = await client.get(pp_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_pp.status_code == 200:
                pp_data = r_pp.json() or {}
                organizations = pp_data.get("organizations") or []
                for org in organizations[:4]:
                    org_name = org.get("name") or ""
                    city = org.get("city") or ""
                    state = org.get("state") or ""
                    ein = org.get("ein") or ""
                    if org_name:
                        loc = f"{city}, {state}".strip(", ")
                        report.items.append(
                            PublicRecordItem(
                                source="ProPublica Nonprofit",
                                title=f"{org_name} (EIN: {ein})",
                                description=f"Registered 501(c) Organization in {loc}",
                                url=f"https://projects.propublica.org/nonprofits/organizations/{ein}",
                            )
                        )
                        report.is_success = True
        except Exception as exc:
            logger.debug("ProPublica query error for %s: %s", clean_q, exc)

        return report


# =============================================================================
# 5. Web3 / ENS & Decentralized Identity Engine
# =============================================================================

@dataclass
class Web3IdentityReport:
    """Ethereum Name Service (ENS) and decentralized identity record."""
    ens_name: str
    address: str = ""
    avatar_url: str = ""
    email: str = ""
    url: str = ""
    twitter: str = ""
    github: str = ""
    description: str = ""
    content_hash: str = ""
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Web3IdentityEngine:
    """Queries public ENS resolvers for Web3 addresses and cross-linked social text records."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    async def analyze(self, client: httpx.AsyncClient, handle: str) -> Web3IdentityReport:
        raw_name = handle.strip().lstrip("@")
        clean_name = raw_name[:-4] if raw_name.lower().endswith(".eth") else raw_name
        ens_domain = f"{clean_name}.eth"
        report = Web3IdentityReport(ens_name=ens_domain)

        if not clean_name:
            report.warnings.append("No ENS handle provided.")
            return report

        try:
            # Query ensideas public HTTPS resolver
            resolver_url = f"https://api.ensideas.com/ens/resolve/{ens_domain}"
            r = await client.get(resolver_url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json() or {}
                addr = data.get("address") or ""
                if addr:
                    report.address = addr
                    report.avatar_url = data.get("avatar") or ""
                    report.email = data.get("email") or ""
                    report.url = data.get("url") or ""
                    report.twitter = data.get("twitter") or ""
                    report.github = data.get("github") or ""
                    report.description = data.get("description") or ""
                    report.content_hash = data.get("contentHash") or ""
                    report.is_success = True
                    return report
                else:
                    report.warnings.append(f"ENS domain '{ens_domain}' is not registered or has no forward address.")
            elif r.status_code == 404:
                report.warnings.append(f"ENS domain '{ens_domain}' not found.")
        except Exception as exc:
            logger.debug("ENS resolver query error for %s: %s", ens_domain, exc)

        # Fallback to web3.bio resolver
        try:
            bio_url = f"https://api.web3.bio/ns/ens/{ens_domain}"
            r_bio = await client.get(bio_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if r_bio.status_code == 200:
                data = r_bio.json() or {}
                if data.get("address"):
                    report.address = data.get("address") or ""
                    report.avatar_url = data.get("avatar") or ""
                    report.description = data.get("description") or ""
                    report.is_success = True
        except Exception:
            pass

        return report


# =============================================================================
# Consolidated Deep Personal OSINT Suite
# =============================================================================

@dataclass
class DeepPersonalReport:
    """Master report combining all 5 legal personal OSINT engines."""
    target: str
    dev_footprint: DevFootprintReport = field(default_factory=lambda: DevFootprintReport(handle=""))
    academic_identity: AcademicReport = field(default_factory=lambda: AcademicReport(query=""))
    activity_cadence: ActivityCadenceReport = field(default_factory=lambda: ActivityCadenceReport(handle=""))
    public_records: PublicRecordsReport = field(default_factory=lambda: PublicRecordsReport(query=""))
    web3_identity: Web3IdentityReport = field(default_factory=lambda: Web3IdentityReport(ens_name=""))
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "dev_footprint": self.dev_footprint.to_dict(),
            "academic_identity": self.academic_identity.to_dict(),
            "activity_cadence": self.activity_cadence.to_dict(),
            "public_records": self.public_records.to_dict(),
            "web3_identity": self.web3_identity.to_dict(),
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class PersonalDeepOSINTSuite:
    """Orchestrates all 5 expanded personal OSINT engines concurrently."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout
        self.dev_engine = DevFootprintEngine(timeout=timeout)
        self.academic_engine = AcademicIdentityEngine(timeout=timeout)
        self.cadence_engine = ActivityCadenceEngine(timeout=timeout)
        self.records_engine = PublicRecordsEngine(timeout=timeout)
        self.web3_engine = Web3IdentityEngine(timeout=timeout)

    async def analyze(self, target: str) -> DeepPersonalReport:
        clean_target = target.strip().lstrip("@")
        report = DeepPersonalReport(target=clean_target)
        if not clean_target:
            report.warnings.append("Empty target provided for deep personal OSINT.")
            return report

        async with httpx.AsyncClient(
            verify=certifi.where(),
            timeout=self.timeout,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=30, max_keepalive_connections=15),
        ) as client:
            dev_task = asyncio.create_task(self.dev_engine.analyze(client, clean_target))
            acad_task = asyncio.create_task(self.academic_engine.analyze(client, clean_target))
            cad_task = asyncio.create_task(self.cadence_engine.analyze(client, clean_target))
            rec_task = asyncio.create_task(self.records_engine.analyze(client, clean_target))
            web3_task = asyncio.create_task(self.web3_engine.analyze(client, clean_target))

            results = await asyncio.gather(
                dev_task, acad_task, cad_task, rec_task, web3_task, return_exceptions=True
            )

            report.dev_footprint = results[0] if isinstance(results[0], DevFootprintReport) else DevFootprintReport(handle=clean_target)
            report.academic_identity = results[1] if isinstance(results[1], AcademicReport) else AcademicReport(query=clean_target)
            report.activity_cadence = results[2] if isinstance(results[2], ActivityCadenceReport) else ActivityCadenceReport(handle=clean_target)
            report.public_records = results[3] if isinstance(results[3], PublicRecordsReport) else PublicRecordsReport(query=clean_target)
            report.web3_identity = results[4] if isinstance(results[4], Web3IdentityReport) else Web3IdentityReport(ens_name=clean_target)

            report.is_success = any([
                report.dev_footprint.is_success,
                report.academic_identity.is_success,
                report.activity_cadence.is_success,
                report.public_records.is_success,
                report.web3_identity.is_success,
            ])
            return report

    @classmethod
    def run_sync(cls, target: str, timeout: float = 6.0) -> DeepPersonalReport:
        """Synchronous wrapper for GUI workers and test harnesses."""
        suite = cls(timeout=timeout)
        try:
            return asyncio.run(suite.analyze(target))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(suite.analyze(target))
            finally:
                loop.close()
