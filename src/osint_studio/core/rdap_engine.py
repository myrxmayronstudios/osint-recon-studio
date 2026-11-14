"""Passive Registration Data Access Protocol (RDAP) reconnaissance engine.

Queries modern, standardized public RDAP endpoints (RFC 7480 - 7484, RFC 9082 - 9083)
to extract domain lifecycle dates, registrar information, abuse contacts, EPP status flags,
nameservers, and privacy proxy status without active probing.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import urllib.parse

import certifi
import httpx

from osint_studio.core.domain_utils import normalize_domain

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
PRIMARY_RDAP_BASE = "https://rdap.org/domain"
FALLBACK_RDAP_BASES = [
    "https://rdap.iana.org/domain",
    "https://rdap.verisign.com/com/v1/domain",
    "https://rdap.verisign.com/net/v1/domain",
    "https://rdap.nic.org/rdap/domain",
]

PRIVACY_PROXY_KEYWORDS = [
    "privacy",
    "proxy",
    "whoisguard",
    "domains by proxy",
    "withheld for privacy",
    "contact privacy",
    "redacted",
    "gdpr masked",
    "data protected",
    "private registration",
    "identity protect",
]


@dataclass
class RDAPEntity:
    """Represents an RDAP entity (registrar, registrant, contact)."""
    roles: List[str] = field(default_factory=list)
    handle: str = ""
    name: str = ""
    organization: str = ""
    email: str = ""
    phone: str = ""
    address: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RDAPReport:
    """Consolidated RDAP intelligence report."""
    domain: str
    handle: str = ""
    status_codes: List[str] = field(default_factory=list)
    created_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    domain_age_days: Optional[int] = None
    days_until_expiration: Optional[int] = None
    registrar_name: str = ""
    registrar_iana_id: str = ""
    abuse_email: str = ""
    abuse_phone: str = ""
    nameservers: List[str] = field(default_factory=list)
    entities: List[RDAPEntity] = field(default_factory=list)
    is_privacy_protected: bool = False
    privacy_provider: str = ""
    raw_rdap: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "handle": self.handle,
            "status_codes": self.status_codes,
            "created_date": self.created_date,
            "expiration_date": self.expiration_date,
            "updated_date": self.updated_date,
            "domain_age_days": self.domain_age_days,
            "days_until_expiration": self.days_until_expiration,
            "registrar_name": self.registrar_name,
            "registrar_iana_id": self.registrar_iana_id,
            "abuse_email": self.abuse_email,
            "abuse_phone": self.abuse_phone,
            "nameservers": self.nameservers,
            "entities": [e.to_dict() for e in self.entities],
            "is_privacy_protected": self.is_privacy_protected,
            "privacy_provider": self.privacy_provider,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


class RDAPEngine:
    """Queries and normalizes domain registration records via RDAP."""

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def clean_domain(self, domain: str) -> str:
        return normalize_domain(domain)

    def _parse_vcard(self, vcard_array: List[Any]) -> Dict[str, str]:
        """Extracts fields from standard RDAP vcardArray (RFC 7095)."""
        result = {"name": "", "org": "", "email": "", "phone": "", "address": ""}
        if not vcard_array or len(vcard_array) < 2:
            return result

        items = vcard_array[1]
        for item in items:
            if not isinstance(item, list) or len(item) < 4:
                continue
            prop = str(item[0]).lower()
            val = item[3]
            if prop == "fn" and isinstance(val, str):
                result["name"] = val
            elif prop == "org" and isinstance(val, (str, list)):
                result["org"] = val if isinstance(val, str) else " / ".join(str(x) for x in val)
            elif prop == "email" and isinstance(val, str):
                result["email"] = val
            elif prop == "tel" and isinstance(val, str):
                result["phone"] = val
            elif prop == "adr" and isinstance(val, list):
                # Standard ADR format: [pobox, ext, street, locality, region, code, country]
                addr_parts = [str(x) for x in val if x and str(x).strip()]
                result["address"] = ", ".join(addr_parts)

        return result

    def _calculate_date_diff(self, date_str: str) -> Optional[int]:
        """Calculates days from now to date_str."""
        if not date_str:
            return None
        # Normalize ISO timestamps like 2024-05-10T12:00:00Z
        clean_str = date_str.replace("Z", "+00:00")
        try:
            target_dt = datetime.datetime.fromisoformat(clean_str)
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            return (target_dt - now_dt).days
        except Exception:
            return None

    def query(self, domain: str) -> RDAPReport:
        """Queries RDAP endpoints passively and normalizes domain registration data."""
        clean_d = self.clean_domain(domain)
        report = RDAPReport(domain=clean_d)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/rdap+json, application/json",
        }

        urls_to_try = [f"{PRIMARY_RDAP_BASE}/{clean_d}"]

        raw_data: Optional[Dict[str, Any]] = None
        last_error = ""

        with httpx.Client(timeout=self.timeout, verify=certifi.where(), follow_redirects=True) as client:
            for url in urls_to_try:
                try:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        raw_data = resp.json()
                        break
                    elif resp.status_code == 404:
                        report.warnings.append(f"Domain '{clean_d}' not found in RDAP registry (may be unregistered or unsupported TLD).")
                        return report
                    else:
                        last_error = f"RDAP endpoint returned HTTP status {resp.status_code}"
                except httpx.TimeoutException:
                    last_error = "RDAP request timed out after 10s."
                except Exception as e:
                    last_error = f"RDAP query failed: {str(e)}"

        if not raw_data:
            report.warnings.append(last_error or "Unable to retrieve RDAP data from public registry.")
            return report

        report.is_success = True
        report.raw_rdap = raw_data
        report.handle = raw_data.get("handle", "")
        report.status_codes = raw_data.get("status", [])

        # Lifecycle events
        events = raw_data.get("events", [])
        for ev in events:
            action = ev.get("eventAction", "").lower()
            date_val = ev.get("eventDate", "")
            if "registration" in action or action == "created":
                report.created_date = date_val
                age_days = self._calculate_date_diff(date_val)
                if age_days is not None:
                    report.domain_age_days = abs(age_days)
            elif "expiration" in action or action == "renew":
                report.expiration_date = date_val
                rem_days = self._calculate_date_diff(date_val)
                report.days_until_expiration = rem_days
            elif "last changed" in action or action == "last update":
                report.updated_date = date_val

        # Nameservers
        ns_objs = raw_data.get("nameservers", [])
        for ns in ns_objs:
            name = ns.get("ldhName", "")
            if name:
                report.nameservers.append(name.lower().rstrip("."))

        # Entities
        entities_raw = raw_data.get("entities", [])
        for ent in entities_raw:
            roles = ent.get("roles", [])
            handle = ent.get("handle", "")
            vcard = ent.get("vcardArray", [])
            vcard_parsed = self._parse_vcard(vcard)

            entity_obj = RDAPEntity(
                roles=roles,
                handle=handle,
                name=vcard_parsed["name"],
                organization=vcard_parsed["org"],
                email=vcard_parsed["email"],
                phone=vcard_parsed["phone"],
                address=vcard_parsed["address"],
            )

            # Check sub-entities if present
            sub_entities = ent.get("entities", [])
            for sub in sub_entities:
                sub_roles = sub.get("roles", [])
                sub_vcard = self._parse_vcard(sub.get("vcardArray", []))
                if "abuse" in sub_roles:
                    if sub_vcard["email"] and not report.abuse_email:
                        report.abuse_email = sub_vcard["email"]
                    if sub_vcard["phone"] and not report.abuse_phone:
                        report.abuse_phone = sub_vcard["phone"]

            # Check for registrar entity
            if "registrar" in roles:
                report.registrar_name = entity_obj.organization or entity_obj.name or handle
                report.registrar_iana_id = handle
                # Public IANA registrar ID is often in publicIds
                public_ids = ent.get("publicIds", [])
                for pid in public_ids:
                    if pid.get("type", "").lower() == "iana":
                        report.registrar_iana_id = str(pid.get("identifier", report.registrar_iana_id))

            # Check for abuse contact
            if "abuse" in roles:
                if entity_obj.email and not report.abuse_email:
                    report.abuse_email = entity_obj.email
                if entity_obj.phone and not report.abuse_phone:
                    report.abuse_phone = entity_obj.phone

            # Privacy proxy detection
            all_text = f"{entity_obj.name} {entity_obj.organization} {entity_obj.email}".lower()
            for kw in PRIVACY_PROXY_KEYWORDS:
                if kw in all_text:
                    report.is_privacy_protected = True
                    report.privacy_provider = entity_obj.organization or entity_obj.name
                    break

            report.entities.append(entity_obj)

        # Flag expiring domains
        if report.days_until_expiration is not None:
            if report.days_until_expiration < 0:
                report.warnings.append("CRITICAL: Domain registration has expired!")
            elif report.days_until_expiration < 30:
                report.warnings.append(
                    f"WARNING: Domain registration expires in {report.days_until_expiration} days."
                )

        return report
