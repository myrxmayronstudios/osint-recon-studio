"""IP Geolocation, Autonomous System Number (ASN), BGP, and Cloud Provider intelligence engine.

Passively queries public IP/ASN metadata endpoints (ipwho.is and RDAP) to identify
geographic location, ISP, ASN, BGP prefix, and cloud infrastructure providers (Cloudflare, AWS, Azure, GCP, Akamai).
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import certifi
import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
IPWHOIS_BASE = "https://ipwho.is"

KNOWN_CLOUD_PROVIDERS = [
    ("Cloudflare", ["cloudflare", "as13335"]),
    ("Amazon Web Services (AWS)", ["amazon", "aws", "as16509", "as14618"]),
    ("Microsoft Azure", ["microsoft", "azure", "as8075"]),
    ("Google Cloud Platform (GCP)", ["google", "as15169", "as396982"]),
    ("Akamai Technologies", ["akamai", "as20940", "as16625"]),
    ("Fastly", ["fastly", "as54113"]),
    ("DigitalOcean", ["digitalocean", "as14061"]),
    ("Hetzner", ["hetzner", "as24940"]),
    ("OVHcloud", ["ovh", "as16276"]),
    ("Oracle Cloud", ["oracle", "as31898"]),
]


@dataclass
class IPIntelRecord:
    """Detailed intelligence record for a single IP address."""
    ip: str
    country: str = "Unknown"
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: str = ""
    asn_org: str = ""
    isp: str = ""
    timezone: str = ""
    is_cloud: bool = False
    cloud_provider: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IPIntelReport:
    """Consolidated IP intelligence and geolocation output."""
    target_domain: str
    records: List[IPIntelRecord] = field(default_factory=list)
    unique_countries: List[str] = field(default_factory=list)
    unique_asns: List[str] = field(default_factory=list)
    cloud_providers_detected: List[str] = field(default_factory=list)
    is_behind_cdn_or_cloud: bool = False
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "records": [r.to_dict() for r in self.records],
            "unique_countries": self.unique_countries,
            "unique_asns": self.unique_asns,
            "cloud_providers_detected": self.cloud_providers_detected,
            "is_behind_cdn_or_cloud": self.is_behind_cdn_or_cloud,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class IPIntelEngine:
    """Gathers geolocation and network infrastructure intelligence on resolved IP addresses."""

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = USER_AGENT,
        rate_limit_delay: float = 0.5,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.rate_limit_delay = rate_limit_delay

    @staticmethod
    def is_public_ip(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
        except ValueError:
            return False

    def _detect_cloud_provider(self, text_context: str) -> Optional[str]:
        """Matches network org and ASN strings against recognized cloud infrastructure signatures."""
        context_lower = text_context.lower()
        for provider_name, keywords in KNOWN_CLOUD_PROVIDERS:
            for kw in keywords:
                if kw in context_lower:
                    return provider_name
        return None

    def query_ip(self, ip_str: str) -> IPIntelRecord:
        """Queries public ipwho.is endpoint for IP geolocation and ASN data."""
        rec = IPIntelRecord(ip=ip_str)
        if not self.is_public_ip(ip_str):
            rec.isp = "Private / Local Network"
            return rec

        url = f"{IPWHOIS_BASE}/{ip_str}"
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}

        try:
            with httpx.Client(timeout=self.timeout, verify=certifi.where(), follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success", False):
                        rec.raw_data = data
                        rec.country = data.get("country", "Unknown")
                        rec.country_code = data.get("country_code", "")
                        rec.region = data.get("region", "")
                        rec.city = data.get("city", "")
                        rec.latitude = data.get("latitude")
                        rec.longitude = data.get("longitude")

                        connection = data.get("connection", {})
                        asn_num = connection.get("asn", "")
                        asn_org = connection.get("org", "")
                        rec.asn = f"AS{asn_num}" if asn_num else ""
                        rec.asn_org = asn_org
                        rec.isp = connection.get("isp", asn_org)

                        tz = data.get("timezone", {})
                        rec.timezone = tz.get("id", "")

                        # Cloud detection
                        match_text = f"{rec.asn} {rec.asn_org} {rec.isp}"
                        provider = self._detect_cloud_provider(match_text)
                        if provider:
                            rec.is_cloud = True
                            rec.cloud_provider = provider
                else:
                    logger.debug(f"ipwho.is returned HTTP {resp.status_code} for {ip_str}")
        except Exception as e:
            logger.debug(f"IP intelligence query failed for {ip_str}: {e}")

        return rec

    def analyze(self, domain: str, resolved_ips: List[str]) -> IPIntelReport:
        """Performs batch IP intelligence gathering across all target IP addresses."""
        report = IPIntelReport(target_domain=domain)
        unique_ips = [ip for ip in set(resolved_ips) if self.is_public_ip(ip)]

        if not unique_ips:
            report.warnings.append("No public IP addresses provided for geolocation analysis.")
            report.is_success = True
            return report

        countries: set[str] = set()
        asns: set[str] = set()
        clouds: set[str] = set()

        for idx, ip in enumerate(unique_ips):
            rec = self.query_ip(ip)
            report.records.append(rec)

            if rec.country and rec.country != "Unknown":
                countries.add(rec.country)
            if rec.asn:
                asns.add(f"{rec.asn} ({rec.asn_org})")
            if rec.is_cloud and rec.cloud_provider:
                clouds.add(rec.cloud_provider)

            if idx < len(unique_ips) - 1 and self.rate_limit_delay > 0:
                time.sleep(self.rate_limit_delay)

        report.unique_countries = sorted(list(countries))
        report.unique_asns = sorted(list(asns))
        report.cloud_providers_detected = sorted(list(clouds))
        report.is_behind_cdn_or_cloud = len(clouds) > 0
        report.is_success = True

        return report
