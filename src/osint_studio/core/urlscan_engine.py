"""URLScan.io and AlienVault OTX passive threat archive search engine.

Queries the public, zero-key URLScan.io search API and AlienVault OTX passive DNS
to uncover historical scans, observed IP address transitions, page titles, ASN shifts,
and screenshot references without initiating an active scan against the target.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import urllib.parse

import certifi
import httpx

from osint_studio.core.domain_utils import extract_root_domain, normalize_domain

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
ALIENVAULT_OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


@dataclass
class URLScanRecord:
    """Historical scan record from URLScan.io."""
    scan_id: str
    scan_date: str
    target_url: str
    domain: str
    ip: str = ""
    asn: str = ""
    asn_name: str = ""
    country: str = ""
    page_title: str = ""
    screenshot_url: str = ""
    result_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OTXRecord:
    """Historical passive DNS record from AlienVault OTX."""
    record_type: str
    address: str
    first_seen: str
    last_seen: str
    asn: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatArchiveReport:
    """Consolidated threat archive and historical scan intelligence report."""
    target_domain: str
    urlscan_records: List[URLScanRecord] = field(default_factory=list)
    otx_records: List[OTXRecord] = field(default_factory=list)
    historical_ips_observed: List[str] = field(default_factory=list)
    historical_asns_observed: List[str] = field(default_factory=list)
    total_scans_found: int = 0
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "urlscan_records": [r.to_dict() for r in self.urlscan_records],
            "otx_records": [r.to_dict() for r in self.otx_records],
            "historical_ips_observed": self.historical_ips_observed,
            "historical_asns_observed": self.historical_asns_observed,
            "total_scans_found": self.total_scans_found,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class URLScanEngine:
    """Passively queries URLScan.io and AlienVault OTX historical scan indexes."""

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = USER_AGENT,
        api_key: Optional[str] = None,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.api_key = api_key

    def search_urlscan(self, domain: str) -> List[URLScanRecord]:
        """Queries URLScan.io search API for historical public scan artifacts."""
        clean_d = normalize_domain(domain)
        params = {"q": f"domain:{clean_d}", "size": "50"}
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key

        records: List[URLScanRecord] = []
        try:
            with httpx.Client(timeout=self.timeout, verify=certifi.where(), follow_redirects=True) as client:
                resp = client.get(URLSCAN_SEARCH_URL, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    for item in results:
                        page = item.get("page", {})
                        task = item.get("task", {})
                        stats = item.get("stats", {})

                        scan_id = item.get("_id", "")
                        screenshot = item.get("screenshot", "")
                        result_url = item.get("result", f"https://urlscan.io/result/{scan_id}/")

                        records.append(
                            URLScanRecord(
                                scan_id=scan_id,
                                scan_date=task.get("time", ""),
                                target_url=page.get("url", task.get("url", "")),
                                domain=page.get("domain", clean_d),
                                ip=page.get("ip", ""),
                                asn=str(page.get("asn", "")),
                                asn_name=page.get("asnname", ""),
                                country=page.get("country", ""),
                                page_title=page.get("title", ""),
                                screenshot_url=screenshot,
                                result_url=result_url,
                            )
                        )
        except Exception as e:
            logger.debug(f"URLScan.io search failed for {clean_d}: {e}")

        # Sort chronologically reverse (newest first)
        records.sort(key=lambda r: r.scan_date, reverse=True)
        return records

    def search_alienvault_otx(self, domain: str) -> List[OTXRecord]:
        """Queries AlienVault OTX Passive DNS endpoint for historical IP resolution mappings."""
        clean_d = extract_root_domain(domain)
        url = ALIENVAULT_OTX_URL.format(domain=clean_d)
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        records: List[OTXRecord] = []

        try:
            with httpx.Client(timeout=self.timeout, verify=certifi.where(), follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    p_dns = data.get("passive_dns", [])
                    for entry in p_dns:
                        records.append(
                            OTXRecord(
                                record_type=entry.get("record_type", "A"),
                                address=entry.get("address", ""),
                                first_seen=entry.get("first", ""),
                                last_seen=entry.get("last", ""),
                                asn=str(entry.get("asn", "")),
                            )
                        )
        except Exception as e:
            logger.debug(f"AlienVault OTX passive DNS lookup failed for {clean_d}: {e}")

        records.sort(key=lambda r: r.last_seen, reverse=True)
        return records

    def analyze(self, domain: str) -> ThreatArchiveReport:
        """Executes combined URLScan.io and AlienVault OTX passive search."""
        clean_d = normalize_domain(domain)
        report = ThreatArchiveReport(target_domain=clean_d)

        urlscan_recs = self.search_urlscan(clean_d)
        otx_recs = self.search_alienvault_otx(clean_d)

        report.urlscan_records = urlscan_recs
        report.otx_records = otx_recs
        report.total_scans_found = len(urlscan_recs)

        ips: set[str] = set()
        asns: set[str] = set()

        for u in urlscan_recs:
            if u.ip:
                ips.add(u.ip)
            if u.asn:
                asns.add(f"{u.asn} ({u.asn_name})".strip())

        for o in otx_recs:
            if o.address:
                ips.add(o.address)
            if o.asn:
                asns.add(o.asn)

        report.historical_ips_observed = sorted(list(ips))
        report.historical_asns_observed = sorted(list(asns))
        report.is_success = True

        if not urlscan_recs and not otx_recs:
            report.warnings.append(f"No historical scans or passive DNS entries found for '{clean_d}'.")

        return report


def search_threat_archives(
    domain: str,
    timeout: float = 10.0,
    api_key: Optional[str] = None,
) -> ThreatArchiveReport:
    """Convenience wrapper executing URLScan.io and AlienVault OTX threat archive searches."""
    engine = URLScanEngine(timeout=timeout, api_key=api_key)
    return engine.analyze(domain)

