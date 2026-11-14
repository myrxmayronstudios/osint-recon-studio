"""Passive Internet Archive (Wayback Machine) reconnaissance engine.

Queries public Wayback Machine Availability and CDX APIs to discover historical snapshots,
first/latest recorded captures, and archive footprint without crawling or downloading pages.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
WAYBACK_AVAILABILITY_API = "https://archive.org/wayback/available"
WAYBACK_CDX_API = "https://web.archive.org/cdx/search/cdx"


@dataclass
class ArchiveSnapshot:
    """Represents a historical snapshot captured by Internet Archive."""
    timestamp: str  # YYYYMMDDhhmmss
    formatted_date: str = ""
    original_url: str = ""
    archive_url: str = ""
    status_code: str = ""
    mime_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ArchiveReport:
    """Consolidated Internet Archive intelligence report."""
    domain: str
    is_archived: bool = False
    first_seen: str = ""
    latest_seen: str = ""
    total_samples: int = 0
    closest_snapshot_url: str = ""
    snapshots: List[ArchiveSnapshot] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "is_archived": self.is_archived,
            "first_seen": self.first_seen,
            "latest_seen": self.latest_seen,
            "total_samples": self.total_samples,
            "closest_snapshot_url": self.closest_snapshot_url,
            "snapshots": [s.to_dict() for s in self.snapshots],
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class ArchiveEngine:
    """Queries Internet Archive Wayback Machine public metadata."""

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

    def _format_timestamp(self, ts: str) -> str:
        """Converts YYYYMMDDHHMMSS to human-readable ISO string."""
        if len(ts) >= 8:
            year = ts[0:4]
            month = ts[4:6]
            day = ts[6:8]
            time_part = ""
            if len(ts) >= 14:
                hour = ts[8:10]
                minute = ts[10:12]
                second = ts[12:14]
                time_part = f" {hour}:{minute}:{second} UTC"
            return f"{year}-{month}-{day}{time_part}"
        return ts

    def query_availability(self, domain: str) -> Tuple[bool, str, str]:
        """Queries the Wayback Availability API."""
        clean_d = self.clean_domain(domain)
        headers = {"User-Agent": self.user_agent}
        params = {"url": clean_d}

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(WAYBACK_AVAILABILITY_API, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    snapshots = data.get("archived_snapshots", {})
                    closest = snapshots.get("closest", {})
                    available = closest.get("available", False)
                    url = closest.get("url", "")
                    ts = closest.get("timestamp", "")
                    return available, url, ts
        except Exception as e:
            logger.debug(f"Wayback Availability lookup error: {e}")

        return False, "", ""

    def query_cdx(self, domain: str, limit: int = 25) -> List[ArchiveSnapshot]:
        """Queries the public CDX API for historical snapshot records."""
        clean_d = self.clean_domain(domain)
        headers = {"User-Agent": self.user_agent}
        params = {
            "url": clean_d,
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode,digest",
            "collapse": "digest",
            "limit": str(limit),
        }

        snapshots: List[ArchiveSnapshot] = []

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(WAYBACK_CDX_API, params=params, headers=headers)
                if resp.status_code == 200:
                    rows = resp.json()
                    # First row is header: ["timestamp","original","mimetype","statuscode","digest"]
                    if len(rows) > 1:
                        for row in rows[1:]:
                            if len(row) >= 4:
                                ts = str(row[0])
                                orig = str(row[1])
                                mime = str(row[2])
                                status = str(row[3])
                                archive_url = f"https://web.archive.org/web/{ts}/{orig}"
                                snapshots.append(
                                    ArchiveSnapshot(
                                        timestamp=ts,
                                        formatted_date=self._format_timestamp(ts),
                                        original_url=orig,
                                        archive_url=archive_url,
                                        status_code=status,
                                        mime_type=mime,
                                    )
                                )
        except Exception as e:
            logger.debug(f"Wayback CDX lookup error: {e}")

        # Sort chronologically
        snapshots.sort(key=lambda s: s.timestamp)
        return snapshots

    def analyze(self, domain: str) -> ArchiveReport:
        """Performs non-intrusive historical reconnaissance using Internet Archive."""
        clean_d = self.clean_domain(domain)
        report = ArchiveReport(domain=clean_d)

        # 1. Availability check
        available, closest_url, closest_ts = self.query_availability(clean_d)
        report.is_archived = available
        report.closest_snapshot_url = closest_url

        # 2. CDX historical captures
        snapshots = self.query_cdx(clean_d, limit=30)
        report.snapshots = snapshots
        report.total_samples = len(snapshots)

        if snapshots:
            report.is_archived = True
            report.first_seen = snapshots[0].formatted_date
            report.latest_seen = snapshots[-1].formatted_date
        elif closest_ts:
            report.first_seen = self._format_timestamp(closest_ts)
            report.latest_seen = report.first_seen

        if not report.is_archived:
            report.warnings.append(f"No historical snapshots found in Internet Archive for '{clean_d}'.")

        report.is_success = True
        return report
