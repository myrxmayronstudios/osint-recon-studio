"""Passive DNS reconnaissance and email security posture auditing engine.

Queries public DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA),
evaluates SPF, DMARC, DNSSEC, CAA compliance, performs reverse DNS (PTR),
and queries Certificate Transparency (CT) logs via crt.sh with exponential backoff
and HackerTarget fallback for resilient passive subdomain discovery.
Configured with hardened public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) and certifi CA bundles.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import urllib.parse

import certifi
import dns.dnssec
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename
import httpx

from osint_studio.core.domain_utils import normalize_domain

logger = logging.getLogger(__name__)

DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
PUBLIC_RESOLVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]


@dataclass
class DNSRecord:
    """Represents a single parsed DNS record."""
    record_type: str
    name: str
    value: str
    ttl: int
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SPFAuditResult:
    """SPF configuration analysis."""
    found: bool = False
    record: str = ""
    multiple_records: bool = False
    all_mechanism: Optional[str] = None
    status: str = "Missing"
    details: List[str] = field(default_factory=list)
    mechanisms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DMARCAuditResult:
    """DMARC configuration analysis."""
    found: bool = False
    record: str = ""
    policy: str = "none"
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    rua: Optional[str] = None
    ruf: Optional[str] = None
    status: str = "Missing"
    details: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSSECAuditResult:
    """DNSSEC deployment status."""
    enabled: bool = False
    status: str = "Disabled"
    has_ds: bool = False
    has_dnskey: bool = False
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CAAAuditResult:
    """CAA policy status."""
    configured: bool = False
    issuers: List[str] = field(default_factory=list)
    wildcard_issuers: List[str] = field(default_factory=list)
    iodef: Optional[str] = None
    status: str = "Not Configured"
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CTSubdomain:
    """Subdomain discovered via Certificate Transparency or passive endpoints."""
    subdomain: str
    logged_date: str = ""
    issuer: str = ""
    source: str = "crt.sh"
    not_before: str = ""
    not_after: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSEngineReport:
    """Consolidated DNS reconnaissance output."""
    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    record_counts: Dict[str, int] = field(default_factory=dict)
    resolved_ips: List[str] = field(default_factory=list)
    reverse_dns: Dict[str, str] = field(default_factory=dict)
    mail_servers: List[Dict[str, Any]] = field(default_factory=list)
    name_servers: List[str] = field(default_factory=list)
    spf: SPFAuditResult = field(default_factory=SPFAuditResult)
    dmarc: DMARCAuditResult = field(default_factory=DMARCAuditResult)
    dnssec: DNSSECAuditResult = field(default_factory=DNSSECAuditResult)
    caa: CAAAuditResult = field(default_factory=CAAAuditResult)
    ct_subdomains: List[CTSubdomain] = field(default_factory=list)
    subdomain_count: int = 0
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "records": [r.to_dict() for r in self.records],
            "record_counts": self.record_counts,
            "resolved_ips": self.resolved_ips,
            "reverse_dns": self.reverse_dns,
            "mail_servers": self.mail_servers,
            "name_servers": self.name_servers,
            "spf": self.spf.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "dnssec": self.dnssec.to_dict(),
            "caa": self.caa.to_dict(),
            "ct_subdomains": [s.to_dict() for s in self.ct_subdomains],
            "subdomain_count": self.subdomain_count,
            "warnings": self.warnings,
        }


class DNSEngine:
    """Performs non-intrusive DNS reconnaissance and Certificate Transparency lookups."""

    def __init__(
        self,
        timeout: float = 5.0,
        nameservers: Optional[List[str]] = None,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        # Hardened resolver with configure=False to avoid Windows stub hang
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = nameservers or list(PUBLIC_RESOLVERS)
        self.resolver.lifetime = timeout
        self.resolver.timeout = min(3.0, timeout)

    def clean_domain(self, domain: str) -> str:
        """Sanitizes user input to extract clean FQDN with Punycode IDN support."""
        return normalize_domain(domain)

    def query_records(
        self,
        domain: str,
        record_types: Optional[List[str]] = None,
    ) -> List[DNSRecord]:
        """Queries standard DNS record types for the domain."""
        target_domain = self.clean_domain(domain)
        types_to_query = record_types or DEFAULT_RECORD_TYPES
        results: List[DNSRecord] = []

        for rtype in types_to_query:
            try:
                answers = self.resolver.resolve(target_domain, rtype)
                for rdata in answers:
                    val = rdata.to_text().strip('"')
                    if rtype in ("CNAME", "NS") and val.endswith("."):
                        val = val[:-1]
                    results.append(
                        DNSRecord(
                            record_type=rtype,
                            name=target_domain,
                            value=val,
                            ttl=answers.ttl,
                            raw=rdata.to_text(),
                        )
                    )
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
            ):
                continue
            except dns.exception.Timeout:
                logger.warning(f"Timeout querying DNS {rtype} for {target_domain}")
            except Exception as e:
                logger.debug(f"Error querying {rtype} for {target_domain}: {e}")

        return results

    def audit_spf(self, domain: str, records: List[DNSRecord]) -> SPFAuditResult:
        spf_strings = [
            r.value for r in records if r.record_type == "TXT" and r.value.startswith("v=spf1")
        ]

        if not spf_strings:
            return SPFAuditResult(
                found=False,
                status="Missing",
                details=["No SPF record found. Email from this domain is susceptible to spoofing."],
            )

        if len(spf_strings) > 1:
            return SPFAuditResult(
                found=True,
                record=" | ".join(spf_strings),
                multiple_records=True,
                status="Invalid",
                details=[
                    "CRITICAL: Multiple SPF records found (RFC 7208 forbids more than one). "
                    "Mail receivers may treat this as SPF PermError and reject legitimate mail."
                ],
            )

        spf_record = spf_strings[0]
        mechanisms = spf_record.split()
        all_mech: Optional[str] = None
        details: List[str] = []

        for mech in mechanisms:
            if mech.endswith("all"):
                all_mech = mech
                break

        if all_mech == "-all":
            status = "Strong"
            details.append("HardFail (-all) enforced. Excellent protection against unauthorized senders.")
        elif all_mech == "~all":
            status = "Moderate"
            details.append("SoftFail (~all) configured. Unauthorized mail is flagged but typically not outright rejected.")
        elif all_mech == "?all":
            status = "Risky"
            details.append("Neutral (?all) mechanism used. SPF validation is effectively disabled/ineffective.")
        elif all_mech == "+all":
            status = "Critical Risk"
            details.append("Pass (+all) mechanism detected! Any IP address on the Internet is authorized to send email as this domain.")
        else:
            status = "Incomplete"
            details.append("SPF record lacks an explicit 'all' termination mechanism.")

        return SPFAuditResult(
            found=True,
            record=spf_record,
            multiple_records=False,
            all_mechanism=all_mech,
            status=status,
            details=details,
            mechanisms=mechanisms,
        )

    def audit_dmarc(self, domain: str) -> DMARCAuditResult:
        target_domain = self.clean_domain(domain)
        dmarc_name = f"_dmarc.{target_domain}"

        try:
            answers = self.resolver.resolve(dmarc_name, "TXT")
            records = [rdata.to_text().strip('"') for rdata in answers]
        except Exception:
            return DMARCAuditResult(
                found=False,
                status="Missing",
                details=["No DMARC record found at _dmarc." + target_domain + ". Domain lacks email policy enforcement."],
            )

        dmarc_rec = next((r for r in records if r.startswith("v=DMARC1")), None)
        if not dmarc_rec:
            return DMARCAuditResult(
                found=False,
                status="Missing",
                details=["TXT record found at _dmarc but missing 'v=DMARC1' tag."],
            )

        tags: Dict[str, str] = {}
        for part in dmarc_rec.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        policy = tags.get("p", "none").lower()
        sub_policy = tags.get("sp")
        rua = tags.get("rua")
        ruf = tags.get("ruf")
        pct = int(tags.get("pct", 100)) if tags.get("pct", "100").isdigit() else 100

        details: List[str] = []
        if policy == "reject":
            status = "Strong"
            details.append("DMARC 'reject' policy active. Fraudulent and unauthenticated emails are rejected by receiving MTAs.")
        elif policy == "quarantine":
            status = "Moderate"
            details.append("DMARC 'quarantine' policy active. Unauthenticated emails are sent to spam/quarantine folders.")
        elif policy == "none":
            status = "Weak"
            details.append("DMARC 'none' policy active (monitoring mode only). Mail is monitored without enforcement.")
        else:
            status = "Unknown"
            details.append(f"Unrecognized DMARC policy: {policy}")

        if pct < 100:
            details.append(f"Policy enforcement is restricted to only {pct}% of messages.")

        if not rua:
            details.append("Warning: No aggregate reporting address (rua) configured. Sender cannot monitor authentication failures.")

        return DMARCAuditResult(
            found=True,
            record=dmarc_rec,
            policy=policy,
            subdomain_policy=sub_policy,
            percentage=pct,
            rua=rua,
            ruf=ruf,
            status=status,
            details=details,
            tags=tags,
        )

    def audit_dnssec(self, domain: str) -> DNSSECAuditResult:
        target_domain = self.clean_domain(domain)
        has_dnskey = False
        has_ds = False
        details: List[str] = []

        try:
            self.resolver.resolve(target_domain, "DNSKEY")
            has_dnskey = True
        except Exception:
            pass

        try:
            self.resolver.resolve(target_domain, "DS")
            has_ds = True
        except Exception:
            pass

        if has_dnskey and has_ds:
            status = "Active & Signed"
            details.append("DNSSEC is fully deployed with validated DS and DNSKEY records.")
        elif has_dnskey and not has_ds:
            status = "Partial (No DS at Registrar)"
            details.append("DNSKEY exists on zone, but no parent DS record discovered.")
        else:
            status = "Disabled"
            details.append("DNSSEC is not enabled for this domain (zone is vulnerable to DNS cache poisoning/spoofing).")

        return DNSSECAuditResult(
            enabled=(has_dnskey and has_ds),
            status=status,
            has_ds=has_ds,
            has_dnskey=has_dnskey,
            details=details,
        )

    def audit_caa(self, records: List[DNSRecord]) -> CAAAuditResult:
        caa_records = [r for r in records if r.record_type == "CAA"]
        if not caa_records:
            return CAAAuditResult(
                configured=False,
                status="Not Configured",
                details=["No CAA records found. Any public Certificate Authority may issue certificates for this domain."],
            )

        issuers: List[str] = []
        wildcards: List[str] = []
        iodef: Optional[str] = None
        details: List[str] = []

        for r in caa_records:
            val = r.value.strip()
            parts = val.split(maxsplit=2)
            if len(parts) >= 3:
                tag = parts[1].lower()
                param = parts[2].strip('"\'')
                if tag == "issue":
                    issuers.append(param)
                elif tag == "issuewild":
                    wildcards.append(param)
                elif tag == "iodef":
                    iodef = param

        details.append(f"Authorized CAs: {', '.join(issuers) if issuers else 'None'}")
        if wildcards:
            details.append(f"Wildcard CAs: {', '.join(wildcards)}")
        if iodef:
            details.append(f"Policy violation reporting contact: {iodef}")

        return CAAAuditResult(
            configured=True,
            issuers=issuers,
            wildcard_issuers=wildcards,
            iodef=iodef,
            status="Configured",
            details=details,
        )

    def resolve_reverse_dns(self, ips: List[str]) -> Dict[str, str]:
        ptr_map: Dict[str, str] = {}
        for ip in ips:
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(rev_name, "PTR")
                ptrs = [str(rdata).rstrip(".") for rdata in answers]
                ptr_map[ip] = ptrs[0] if ptrs else "No PTR"
            except Exception:
                ptr_map[ip] = "No PTR Record"
        return ptr_map

    def _query_crtsh(self, target_domain: str) -> Dict[str, CTSubdomain]:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(target_domain)}&output=json"
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        discovered: Dict[str, CTSubdomain] = {}

        max_retries = 3
        backoff_delays = [1.0, 2.0, 3.5]

        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=self.timeout, verify=certifi.where(), follow_redirects=True) as client:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "").lower()
                        if "json" in content_type or resp.text.strip().startswith("["):
                            data = resp.json()
                            if isinstance(data, list):
                                for entry in data:
                                    raw_names = entry.get("name_value", "")
                                    issuer = entry.get("issuer_name", "")
                                    entry_ts = entry.get("entry_timestamp", "")
                                    not_before = entry.get("not_before", "")
                                    not_after = entry.get("not_after", "")

                                    for name in raw_names.split("\n"):
                                        name = name.strip().lower()
                                        if name.startswith("*."):
                                            name = name[2:]
                                        if name.endswith(target_domain) and name not in discovered:
                                            discovered[name] = CTSubdomain(
                                                subdomain=name,
                                                logged_date=entry_ts,
                                                issuer=issuer.split(",")[0] if issuer else "Unknown CA",
                                                source="crt.sh",
                                                not_before=not_before,
                                                not_after=not_after,
                                            )
                                return discovered
            except Exception as e:
                logger.debug(f"crt.sh attempt {attempt + 1} failed: {e}")

            if attempt < max_retries - 1:
                time.sleep(backoff_delays[attempt])

        return discovered

    def _query_hackertarget_fallback(self, target_domain: str) -> Dict[str, CTSubdomain]:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(target_domain)}"
        headers = {"User-Agent": self.user_agent}
        discovered: Dict[str, CTSubdomain] = {}

        try:
            with httpx.Client(timeout=self.timeout, verify=certifi.where(), follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    lines = resp.text.strip().splitlines()
                    for line in lines:
                        if "," in line:
                            sub, ip = line.split(",", 1)
                            sub = sub.strip().lower()
                            if sub.endswith(target_domain) and sub not in discovered:
                                discovered[sub] = CTSubdomain(
                                    subdomain=sub,
                                    logged_date="Passive DNS",
                                    issuer="HackerTarget Passive",
                                    source="HackerTarget",
                                )
        except Exception as e:
            logger.debug(f"HackerTarget fallback failed: {e}")

        return discovered

    def query_certificate_transparency(self, domain: str) -> List[CTSubdomain]:
        target_domain = self.clean_domain(domain)
        discovered = self._query_crtsh(target_domain)

        if not discovered:
            logger.info(f"crt.sh returned no subdomains for {target_domain}; querying HackerTarget fallback...")
            discovered = self._query_hackertarget_fallback(target_domain)

        return sorted(discovered.values(), key=lambda s: s.subdomain)

    def analyze(
        self,
        domain: str,
        include_ct: bool = True,
    ) -> DNSEngineReport:
        clean_d = self.clean_domain(domain)
        records = self.query_records(clean_d)

        counts: Dict[str, int] = {}
        for r in records:
            counts[r.record_type] = counts.get(r.record_type, 0) + 1

        ips = [r.value for r in records if r.record_type in ("A", "AAAA")]
        unique_ips = sorted(list(set(ips)))
        rev_dns = self.resolve_reverse_dns(unique_ips)

        ns_records = sorted(list(set(r.value for r in records if r.record_type == "NS")))
        mx_records: List[Dict[str, Any]] = []
        for r in records:
            if r.record_type == "MX":
                parts = r.value.split(maxsplit=1)
                priority = int(parts[0]) if len(parts) > 1 and parts[0].isdigit() else 0
                host = parts[1] if len(parts) > 1 else parts[0]
                mx_records.append({"host": host, "priority": priority})
        mx_records.sort(key=lambda x: x["priority"])

        spf_audit = self.audit_spf(clean_d, records)
        dmarc_audit = self.audit_dmarc(clean_d)
        dnssec_audit = self.audit_dnssec(clean_d)
        caa_audit = self.audit_caa(records)

        ct_subs: List[CTSubdomain] = []
        if include_ct:
            ct_subs = self.query_certificate_transparency(clean_d)

        warnings: List[str] = []
        if not records:
            warnings.append(f"No DNS records returned for '{clean_d}'. Domain may be unregistered or nameservers down.")
        if spf_audit.status in ("Missing", "Risky", "Critical Risk", "Invalid"):
            warnings.append(f"SPF Security Warning: {spf_audit.status}")
        if dmarc_audit.status in ("Missing", "Weak"):
            warnings.append(f"DMARC Security Warning: {dmarc_audit.status}")
        if not dnssec_audit.enabled:
            warnings.append("DNSSEC is disabled on this zone.")

        return DNSEngineReport(
            domain=clean_d,
            records=records,
            record_counts=counts,
            resolved_ips=unique_ips,
            reverse_dns=rev_dns,
            mail_servers=mx_records,
            name_servers=ns_records,
            spf=spf_audit,
            dmarc=dmarc_audit,
            dnssec=dnssec_audit,
            caa=caa_audit,
            ct_subdomains=ct_subs,
            subdomain_count=len(ct_subs),
            warnings=warnings,
        )
