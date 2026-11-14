"""Subdomain Takeover and Dangling CNAME Audit Engine.

Passively resolves CNAME records for discovered subdomains using public resolvers
(1.1.1.1, 8.8.8.8, 9.9.9.9), fingerprints cloud providers (GitHub Pages, AWS S3,
Azure, Heroku, Shopify, etc.), and detects dangling DNS pointers that resolve to NXDOMAIN.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
import logging
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver

from osint_studio.core.domain_utils import normalize_domain

logger = logging.getLogger(__name__)

PUBLIC_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Database of known vulnerable third-party services and fingerprint patterns
PROVIDER_PATTERNS = [
    ("GitHub Pages", [".github.io"]),
    ("Heroku", [".herokuapp.com", ".herokussl.com", ".herokudns.com"]),
    ("Amazon AWS S3", [".s3.amazonaws.com", ".s3-website", ".s3-website-", ".s3.dualstack."]),
    ("Amazon Elastic Beanstalk", [".elasticbeanstalk.com"]),
    ("Microsoft Azure", [".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net", ".blob.core.windows.net", ".azureedge.net", ".azurefd.net"]),
    ("Shopify", [".myshopify.com"]),
    ("Ghost", [".ghost.io"]),
    ("Pantheon", [".pantheonsite.io"]),
    ("Netlify", [".netlify.app", ".netlify.com"]),
    ("Vercel", [".vercel.app", "cname.vercel-dns.com"]),
    ("Fastly", [".fastly.net"]),
    ("ReadMe.io", [".readme.io"]),
    ("WordPress.com", [".wordpress.com"]),
    ("Surge.sh", [".surge.sh"]),
    ("Bitbucket", [".bitbucket.io"]),
    ("Zendesk", [".zendesk.com"]),
    ("Helpjuice", [".helpjuice.com"]),
    ("Help Scout", [".helpscoutdocs.com"]),
    ("Cargo Collective", [".cargocollective.com"]),
    ("Tumblr", ["domains.tumblr.com"]),
    ("Fly.io", [".fly.dev"]),
]


@dataclass
class TakeoverRecord:
    """Findings for a single subdomain CNAME inspection."""
    subdomain: str
    cname_target: str
    provider: str = "Unknown"
    status: str = "ACTIVE_CNAME"  # "VULNERABLE (NXDOMAIN)", "DANGLING (NXDOMAIN)", "ACTIVE_PROVIDER_CNAME", "NO_ANSWER", "TIMEOUT"
    risk_level: str = "INFO"      # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    target_resolves: bool = True
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TakeoverAuditReport:
    """Consolidated subdomain takeover risk assessment report."""
    target_domain: str
    total_checked: int = 0
    cname_count: int = 0
    vulnerable_count: int = 0
    dangling_count: int = 0
    records: List[TakeoverRecord] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _identify_provider(cname_target: str) -> str:
    """Identifies third-party service provider from CNAME hostname."""
    target_lower = cname_target.lower()
    for provider_name, patterns in PROVIDER_PATTERNS:
        for pat in patterns:
            if pat in target_lower:
                return provider_name
    return "Generic / Self-Hosted"


def _create_resolver(timeout: float = 4.0) -> dns.resolver.Resolver:
    """Creates a configured DNS stub resolver using public nameservers."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(PUBLIC_NAMESERVERS)
    resolver.lifetime = timeout
    resolver.timeout = timeout
    return resolver


def check_subdomain_takeover(
    subdomain: str,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 4.0,
) -> Optional[TakeoverRecord]:
    """Inspects a single subdomain for CNAME pointers and dangling DNS status."""
    clean_sub = normalize_domain(subdomain)
    if not clean_sub:
        return None

    res = resolver or _create_resolver(timeout=timeout)

    try:
        answers = res.resolve(clean_sub, "CNAME")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None  # No CNAME record on this host
    except Exception as exc:
        logger.debug("CNAME query for %s failed: %s", clean_sub, exc)
        return None

    cname_target = ""
    for rdata in answers:
        cname_target = str(rdata.target).rstrip(".")
        break

    if not cname_target:
        return None

    provider = _identify_provider(cname_target)
    is_known_provider = provider != "Generic / Self-Hosted"

    # Now verify if the CNAME target host actually resolves
    try:
        target_answers = res.resolve(cname_target, "A")
        # Target resolves to an IP address
        if is_known_provider:
            return TakeoverRecord(
                subdomain=clean_sub,
                cname_target=cname_target,
                provider=provider,
                status="ACTIVE_PROVIDER_CNAME",
                risk_level="INFO",
                target_resolves=True,
                description=f"Active CNAME alias pointing to hosted {provider} infrastructure.",
            )
        else:
            return TakeoverRecord(
                subdomain=clean_sub,
                cname_target=cname_target,
                provider=provider,
                status="ACTIVE_CNAME",
                risk_level="INFO",
                target_resolves=True,
                description="Standard CNAME alias resolving to active host.",
            )

    except dns.resolver.NXDOMAIN:
        # High-risk dangling pointer!
        if is_known_provider:
            return TakeoverRecord(
                subdomain=clean_sub,
                cname_target=cname_target,
                provider=provider,
                status="VULNERABLE (NXDOMAIN)",
                risk_level="CRITICAL",
                target_resolves=False,
                description=f"Dangling CNAME points to non-existent {provider} service. Unclaimed asset vulnerable to takeover!",
            )
        else:
            return TakeoverRecord(
                subdomain=clean_sub,
                cname_target=cname_target,
                provider=provider,
                status="DANGLING (NXDOMAIN)",
                risk_level="HIGH",
                target_resolves=False,
                description=f"CNAME points to non-existent hostname ({cname_target}). Dangling DNS entry.",
            )

    except dns.resolver.NoAnswer:
        return TakeoverRecord(
            subdomain=clean_sub,
            cname_target=cname_target,
            provider=provider,
            status="NO_ANSWER",
            risk_level="MEDIUM" if is_known_provider else "LOW",
            target_resolves=False,
            description="CNAME target exists in DNS but returns no A/AAAA records.",
        )

    except dns.resolver.LifetimeTimeout:
        return TakeoverRecord(
            subdomain=clean_sub,
            cname_target=cname_target,
            provider=provider,
            status="TIMEOUT",
            risk_level="LOW",
            target_resolves=False,
            description="Target host resolution timed out during inspection.",
        )

    except Exception as exc:
        return TakeoverRecord(
            subdomain=clean_sub,
            cname_target=cname_target,
            provider=provider,
            status="QUERY_ERROR",
            risk_level="LOW",
            target_resolves=False,
            description=f"Resolution error on CNAME target: {exc}",
        )


def audit_subdomain_takeover(
    domain: str,
    subdomains: Optional[List[str]] = None,
    timeout: float = 4.0,
    max_workers: int = 8,
) -> TakeoverAuditReport:
    """Audits a collection of subdomains for dangling CNAME pointers and takeover vulnerability."""
    clean_domain = normalize_domain(domain)
    report = TakeoverAuditReport(target_domain=clean_domain)

    if not clean_domain:
        report.warnings.append("No valid domain supplied for takeover audit.")
        return report

    targets_to_check = set()
    if subdomains:
        for s in subdomains:
            norm = normalize_domain(s)
            if norm:
                targets_to_check.add(norm)

    # Always ensure root and common service prefixes are checked
    common_prefixes = ["www", "mail", "blog", "app", "dev", "api", "shop", "status", "docs", "help", "support", "cdn", "stage", "test"]
    for p in common_prefixes:
        targets_to_check.add(f"{p}.{clean_domain}")
    targets_to_check.add(clean_domain)

    target_list = sorted(list(targets_to_check))
    report.total_checked = len(target_list)

    resolver = _create_resolver(timeout=timeout)

    records: List[TakeoverRecord] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(check_subdomain_takeover, sub, resolver, timeout)
            for sub in target_list
        ]
        for f in futures:
            try:
                rec = f.result()
                if rec is not None:
                    records.append(rec)
            except Exception as exc:
                logger.debug("Subdomain check worker error: %s", exc)

    # Sort so CRITICAL / HIGH are at the top
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    records.sort(key=lambda r: (risk_order.get(r.risk_level, 99), r.subdomain))

    report.records = records
    report.cname_count = len(records)
    report.vulnerable_count = sum(1 for r in records if r.risk_level == "CRITICAL")
    report.dangling_count = sum(1 for r in records if r.risk_level in ("CRITICAL", "HIGH"))
    report.is_success = True

    return report


async def audit_subdomain_takeover_async(
    domain: str,
    subdomains: Optional[List[str]] = None,
    timeout: float = 4.0,
    max_workers: int = 8,
) -> TakeoverAuditReport:
    """Asynchronous wrapper running the threaded DNS audit in an executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        audit_subdomain_takeover,
        domain,
        subdomains,
        timeout,
        max_workers,
    )
