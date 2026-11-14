"""Email security posture and spoofing resistance auditing engine.

Passively audits domain email defense standards:
- SPF (Sender Policy Framework, RFC 7208)
- DMARC (Domain-based Message Authentication, Reporting, and Conformance, RFC 7489)
- DKIM common selector lookups (DomainKeys Identified Mail, RFC 6376)
- BIMI (Brand Indicators for Message Identification)
- MTA-STS (Mail Transfer Agent Strict Transport Security, RFC 8461) & TLS-RPT (RFC 8460)
Computes a unified Email Spoofing Resistance Grade (A through F) with defensive remediation.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import urllib.parse

import dns.resolver

logger = logging.getLogger(__name__)

COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "s1",
    "s2",
    "mandrill",
    "postmark",
    "cm",
    "sendgrid",
]


@dataclass
class DKIMSelectorResult:
    """Status for an individual probed DKIM selector."""
    selector: str
    record_name: str
    found: bool = False
    record_text: str = ""
    key_type: str = "rsa"
    public_key_present: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BIMIResult:
    """BIMI DNS record evaluation."""
    found: bool = False
    record: str = ""
    logo_url: str = ""
    vmc_url: str = ""
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MTASTSResult:
    """MTA-STS & TLS-RPT policy evaluation."""
    mta_sts_found: bool = False
    mta_sts_record: str = ""
    tls_rpt_found: bool = False
    tls_rpt_record: str = ""
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EmailSecurityReport:
    """Consolidated email security and anti-spoofing posture report."""
    domain: str
    spf_found: bool = False
    spf_record: str = ""
    spf_mechanism: str = ""  # -all, ~all, ?all, +all
    spf_status: str = "Missing"  # Strong, Moderate, Risky, Critical, Missing, Invalid
    spf_includes: List[str] = field(default_factory=list)
    spf_lookup_count: int = 0

    dmarc_found: bool = False
    dmarc_record: str = ""
    dmarc_policy: str = "none"  # reject, quarantine, none
    dmarc_subdomain_policy: Optional[str] = None
    dmarc_pct: int = 100
    dmarc_rua: str = ""
    dmarc_status: str = "Missing"

    dkim_selectors_checked: List[DKIMSelectorResult] = field(default_factory=list)
    dkim_active_count: int = 0

    bimi: BIMIResult = field(default_factory=BIMIResult)
    mta_sts: MTASTSResult = field(default_factory=MTASTSResult)

    spoofing_grade: str = "F"  # A+, A, B, C, D, F
    spoofing_score: int = 0     # 0 to 100
    risk_summary: str = ""
    defensive_recommendations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "spf_found": self.spf_found,
            "spf_record": self.spf_record,
            "spf_mechanism": self.spf_mechanism,
            "spf_status": self.spf_status,
            "spf_includes": self.spf_includes,
            "spf_lookup_count": self.spf_lookup_count,
            "dmarc_found": self.dmarc_found,
            "dmarc_record": self.dmarc_record,
            "dmarc_policy": self.dmarc_policy,
            "dmarc_subdomain_policy": self.dmarc_subdomain_policy,
            "dmarc_pct": self.dmarc_pct,
            "dmarc_rua": self.dmarc_rua,
            "dmarc_status": self.dmarc_status,
            "dkim_selectors_checked": [s.to_dict() for s in self.dkim_selectors_checked],
            "dkim_active_count": self.dkim_active_count,
            "bimi": self.bimi.to_dict(),
            "mta_sts": self.mta_sts.to_dict(),
            "spoofing_grade": self.spoofing_grade,
            "spoofing_score": self.spoofing_score,
            "risk_summary": self.risk_summary,
            "defensive_recommendations": self.defensive_recommendations,
            "warnings": self.warnings,
        }


class EmailSecurityEngine:
    """Performs deep, passive DNS audits of email authentication and spoofing resistance."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def clean_domain(self, domain: str) -> str:
        d = domain.strip().lower()
        if "://" in d:
            parsed = urllib.parse.urlparse(d)
            d = parsed.netloc or parsed.path
        return d.split("/")[0].split(":")[0].strip(".")

    def audit_spf(self, domain: str) -> tuple[bool, str, str, str, List[str], int, List[str]]:
        """Parses SPF records and evaluates mechanism strength and include count."""
        try:
            answers = self.resolver.resolve(domain, "TXT")
            records = [rdata.to_text().strip('"') for rdata in answers]
        except Exception:
            records = []

        spf_records = [r for r in records if r.startswith("v=spf1")]
        if not spf_records:
            return False, "", "", "Missing", [], 0, ["No SPF record published. Direct email spoofing is possible."]

        if len(spf_records) > 1:
            return (
                True,
                " | ".join(spf_records),
                "",
                "Invalid",
                [],
                0,
                ["Multiple SPF records found (RFC 7208 PermError). Receiving MTAs may reject legitimate emails."],
            )

        spf = spf_records[0]
        tokens = spf.split()
        all_mech = ""
        includes: List[str] = []

        for token in tokens:
            if token.endswith("all"):
                all_mech = token
            elif token.startswith("include:"):
                includes.append(token.split("include:")[1])

        lookup_count = len(includes)  # Approximation of DNS lookup burden

        if all_mech == "-all":
            status = "Strong"
        elif all_mech == "~all":
            status = "Moderate"
        elif all_mech == "?all":
            status = "Risky"
        elif all_mech == "+all":
            status = "Critical"
        else:
            status = "Missing Mechanism"

        recs = []
        if status in ("Risky", "Critical"):
            recs.append("Replace neutral (?all) or allow (+all) mechanism with strict HardFail (-all).")
        elif status == "Moderate":
            recs.append("Consider migrating SoftFail (~all) to HardFail (-all) for strict delivery rejection.")

        return True, spf, all_mech, status, includes, lookup_count, recs

    def audit_dmarc(self, domain: str) -> tuple[bool, str, str, Optional[str], int, str, str, List[str]]:
        """Parses DMARC TXT record at _dmarc.<domain>."""
        dmarc_host = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_host, "TXT")
            records = [rdata.to_text().strip('"') for rdata in answers]
        except Exception:
            records = []

        dmarc_rec = next((r for r in records if r.startswith("v=DMARC1")), None)
        if not dmarc_rec:
            return (
                False,
                "",
                "none",
                None,
                100,
                "",
                "Missing",
                ["No DMARC record deployed. Domain lacks email anti-spoofing enforcement and visibility."],
            )

        tags: Dict[str, str] = {}
        for part in dmarc_rec.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        policy = tags.get("p", "none").lower()
        sub_policy = tags.get("sp")
        pct = int(tags.get("pct", 100)) if tags.get("pct", "100").isdigit() else 100
        rua = tags.get("rua", "")

        if policy == "reject":
            status = "Strong"
        elif policy == "quarantine":
            status = "Moderate"
        else:
            status = "Weak (Monitoring)"

        recs = []
        if policy == "none":
            recs.append("Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' to actively block phishing.")
        if not rua:
            recs.append("Add aggregate reporting address: rua=mailto:dmarc-reports@" + domain)

        return True, dmarc_rec, policy, sub_policy, pct, rua, status, recs

    def probe_dkim_selectors(self, domain: str) -> List[DKIMSelectorResult]:
        """Passively checks common public DKIM selectors via DNS."""
        results: List[DKIMSelectorResult] = []

        for selector in COMMON_DKIM_SELECTORS:
            host = f"{selector}._domainkey.{domain}"
            sel_res = DKIMSelectorResult(selector=selector, record_name=host)
            try:
                answers = self.resolver.resolve(host, "TXT")
                txts = [rdata.to_text().strip('"') for rdata in answers]
                dkim_txt = next((t for t in txts if "v=DKIM1" in t or "p=" in t), None)
                if dkim_txt:
                    sel_res.found = True
                    sel_res.record_text = dkim_txt
                    sel_res.public_key_present = "p=" in dkim_txt
                    if "k=ed25519" in dkim_txt.lower():
                        sel_res.key_type = "ed25519"
                    else:
                        sel_res.key_type = "rsa"
            except Exception:
                pass
            results.append(sel_res)

        return results

    def audit_bimi(self, domain: str) -> BIMIResult:
        """Checks for BIMI (Brand Indicators for Message Identification) record."""
        bimi_host = f"default._bimi.{domain}"
        res = BIMIResult()
        try:
            answers = self.resolver.resolve(bimi_host, "TXT")
            txts = [rdata.to_text().strip('"') for rdata in answers]
            bimi_txt = next((t for t in txts if t.startswith("v=BIMI1")), None)
            if bimi_txt:
                res.found = True
                res.record = bimi_txt
                for part in bimi_txt.split(";"):
                    part = part.strip()
                    if part.startswith("l="):
                        res.logo_url = part[2:]
                    elif part.startswith("a="):
                        res.vmc_url = part[2:]
                res.details.append("BIMI record configured with branded SVG logo.")
        except Exception:
            res.details.append("No BIMI record found at default._bimi." + domain)
        return res

    def audit_mta_sts(self, domain: str) -> MTASTSResult:
        """Audits MTA Strict Transport Security and TLS Reporting records."""
        res = MTASTSResult()
        # MTA-STS
        mta_host = f"_mta-sts.{domain}"
        try:
            answers = self.resolver.resolve(mta_host, "TXT")
            txts = [rdata.to_text().strip('"') for rdata in answers]
            sts_txt = next((t for t in txts if t.startswith("v=STSv1")), None)
            if sts_txt:
                res.mta_sts_found = True
                res.mta_sts_record = sts_txt
                res.details.append("MTA-STS enabled: enforces TLS in transit for inbound email.")
        except Exception:
            res.details.append("MTA-STS is not configured.")

        # TLS-RPT
        rpt_host = f"_smtp._tls.{domain}"
        try:
            answers = self.resolver.resolve(rpt_host, "TXT")
            txts = [rdata.to_text().strip('"') for rdata in answers]
            rpt_txt = next((t for t in txts if t.startswith("v=TLSRPTv1")), None)
            if rpt_txt:
                res.tls_rpt_found = True
                res.tls_rpt_record = rpt_txt
                res.details.append("TLS-RPT configured: automated reporting of TLS negotiation failures.")
        except Exception:
            res.details.append("TLS-RPT reporting is not configured.")

        return res

    def analyze(self, domain: str) -> EmailSecurityReport:
        """Executes full passive email spoofing resistance audit."""
        clean_d = self.clean_domain(domain)
        report = EmailSecurityReport(domain=clean_d)

        # 1. SPF
        spf_found, spf_rec, spf_mech, spf_stat, includes, lookup_cnt, spf_recs = self.audit_spf(clean_d)
        report.spf_found = spf_found
        report.spf_record = spf_rec
        report.spf_mechanism = spf_mech
        report.spf_status = spf_stat
        report.spf_includes = includes
        report.spf_lookup_count = lookup_cnt

        # 2. DMARC
        dmarc_found, dmarc_rec, dmarc_pol, dmarc_sp, dmarc_pct, dmarc_rua, dmarc_stat, dmarc_recs = self.audit_dmarc(clean_d)
        report.dmarc_found = dmarc_found
        report.dmarc_record = dmarc_rec
        report.dmarc_policy = dmarc_pol
        report.dmarc_subdomain_policy = dmarc_sp
        report.dmarc_pct = dmarc_pct
        report.dmarc_rua = dmarc_rua
        report.dmarc_status = dmarc_stat

        # 3. DKIM Common Selectors
        dkim_results = self.probe_dkim_selectors(clean_d)
        report.dkim_selectors_checked = dkim_results
        report.dkim_active_count = sum(1 for s in dkim_results if s.found)

        # 4. BIMI
        report.bimi = self.audit_bimi(clean_d)

        # 5. MTA-STS
        report.mta_sts = self.audit_mta_sts(clean_d)

        # Score & Grade Calculation
        score = 0
        recs: List[str] = []

        # SPF scoring (max 30)
        if spf_stat == "Strong":
            score += 30
        elif spf_stat == "Moderate":
            score += 20
        elif spf_stat == "Risky":
            score += 5
        elif spf_stat == "Invalid":
            score += 0
        else:
            score += 0

        # DMARC scoring (max 45)
        if dmarc_stat == "Strong":
            score += 45
        elif dmarc_stat == "Moderate":
            score += 35
        elif dmarc_stat == "Weak (Monitoring)":
            score += 15
        else:
            score += 0

        # DKIM discovered (max 15)
        if report.dkim_active_count > 0:
            score += 15

        # MTA-STS (max 10)
        if report.mta_sts.mta_sts_found:
            score += 10

        recs.extend(spf_recs)
        recs.extend(dmarc_recs)
        if report.dkim_active_count == 0:
            recs.append("Ensure DKIM signing is active across outbound mail gateways.")
        if not report.mta_sts.mta_sts_found:
            recs.append("Deploy MTA-STS (_mta-sts." + clean_d + ") to enforce encrypted mail transport.")

        report.defensive_recommendations = recs
        report.spoofing_score = score

        if score >= 90:
            report.spoofing_grade = "A+" if score >= 95 else "A"
            report.risk_summary = "Excellent anti-spoofing defenses. Enforces strict SPF, DMARC rejection, and DKIM."
        elif score >= 75:
            report.spoofing_grade = "B"
            report.risk_summary = "Good defenses in place, but DMARC or SPF policy allows potential bypass under specific conditions."
        elif score >= 55:
            report.spoofing_grade = "C"
            report.risk_summary = "Moderate risk: Monitoring-only DMARC or weak SPF allows attackers to spoof domain emails."
        elif score >= 30:
            report.spoofing_grade = "D"
            report.risk_summary = "High risk: Incomplete email authentication. SPF or DMARC is missing."
        else:
            report.spoofing_grade = "F"
            report.risk_summary = "Critical vulnerability: No functional SPF or DMARC enforcement. Anyone on the Internet can spoof this domain."

        return report
