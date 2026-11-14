"""Passive Shodan InternetDB & open service intelligence engine.

Queries Shodan's free, zero-key, strictly passive InternetDB API (https://internetdb.shodan.io/{ip})
to retrieve historical open ports, CPE software identifiers, hostnames, tags, and known CVE references
associated with discovered target IP addresses without transmitting a single port-scan packet.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
SHODAN_INTERNETDB_BASE = "https://internetdb.shodan.io"


@dataclass
class InternetDBHost:
    """Historical exposure record for a single IP address."""
    ip: str
    ports: List[int] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)  # CVE list
    found_in_shodan: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InternetDBReport:
    """Consolidated InternetDB passive exposure report."""
    target_domain: str
    queried_ips: List[str] = field(default_factory=list)
    hosts: List[InternetDBHost] = field(default_factory=list)
    all_open_ports: List[int] = field(default_factory=list)
    all_cves: List[str] = field(default_factory=list)
    all_cpes: List[str] = field(default_factory=list)
    all_tags: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "queried_ips": self.queried_ips,
            "hosts": [h.to_dict() for h in self.hosts],
            "all_open_ports": self.all_open_ports,
            "all_cves": self.all_cves,
            "all_cpes": self.all_cpes,
            "all_tags": self.all_tags,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class InternetDBEngine:
    """Passively queries Shodan InternetDB for historical port and vulnerability exposure."""

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
        """Verifies if an IP is a valid public IPv4/IPv6 address."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
        except ValueError:
            return False

    def query_ip(self, ip_str: str) -> InternetDBHost:
        """Queries Shodan InternetDB for a single public IP."""
        host = InternetDBHost(ip=ip_str)
        if not self.is_public_ip(ip_str):
            return host

        url = f"{SHODAN_INTERNETDB_BASE}/{ip_str}"
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    host.found_in_shodan = True
                    host.ports = sorted(data.get("ports", []))
                    host.cpes = sorted(data.get("cpes", []))
                    host.hostnames = sorted(data.get("hostnames", []))
                    host.tags = sorted(data.get("tags", []))
                    host.vulns = sorted(data.get("vulns", []))
                elif resp.status_code == 404:
                    # 404 simply means no open services or vulnerabilities indexed by Shodan
                    host.found_in_shodan = False
                else:
                    logger.debug(f"InternetDB returned HTTP {resp.status_code} for IP {ip_str}")
        except Exception as e:
            logger.debug(f"InternetDB lookup failed for IP {ip_str}: {e}")

        return host

    def analyze(self, domain: str, resolved_ips: List[str]) -> InternetDBReport:
        """Analyzes all resolved IPs for a domain using passive InternetDB lookups."""
        report = InternetDBReport(target_domain=domain, queried_ips=resolved_ips)

        unique_public_ips = [ip for ip in set(resolved_ips) if self.is_public_ip(ip)]

        if not unique_public_ips:
            report.warnings.append("No public IP addresses resolved to query InternetDB.")
            report.is_success = True
            return report

        all_ports: set[int] = set()
        all_cves: set[str] = set()
        all_cpes: set[str] = set()
        all_tags: set[str] = set()

        for idx, ip in enumerate(unique_public_ips):
            host = self.query_ip(ip)
            report.hosts.append(host)
            all_ports.update(host.ports)
            all_cves.update(host.vulns)
            all_cpes.update(host.cpes)
            all_tags.update(host.tags)

            if idx < len(unique_public_ips) - 1 and self.rate_limit_delay > 0:
                time.sleep(self.rate_limit_delay)

        report.all_open_ports = sorted(list(all_ports))
        report.all_cves = sorted(list(all_cves))
        report.all_cpes = sorted(list(all_cpes))
        report.all_tags = sorted(list(all_tags))
        report.is_success = True

        if report.all_cves:
            report.warnings.append(
                f"Historical CVEs detected on IP assets in Shodan database: {len(report.all_cves)} CVEs referenced."
            )

        return report
