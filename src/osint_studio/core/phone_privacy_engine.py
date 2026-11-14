"""Personal Phone Number Intelligence and Privacy Exposure Auditor.

Uses Google's authoritative `phonenumbers` library to validate numbering-plan
authenticity, parse multi-format representations (E.164, RFC3966, International),
fingerprint telecom carrier and line type (Mobile vs VoIP vs Landline),
calculate privacy exposure scores, and provide defensive self-audit search dorks.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import logging
from typing import Any, Dict, List, Optional
import urllib.parse

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import PhoneNumberType

logger = logging.getLogger(__name__)

LINE_TYPE_MAP = {
    PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
    PhoneNumberType.MOBILE: "Mobile / Cellular",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
    PhoneNumberType.TOLL_FREE: "Toll-Free",
    PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    PhoneNumberType.SHARED_COST: "Shared Cost",
    PhoneNumberType.VOIP: "VoIP (Virtual / Disposable)",
    PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "Universal Access Number (UAN)",
    PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "Unknown Line Type",
}


@dataclass
class PhonePrivacyReport:
    """Findings for personal phone number privacy audit."""
    raw_input: str
    is_valid: bool = False
    is_possible: bool = False
    e164: str = ""
    international: str = ""
    national: str = ""
    rfc3966: str = ""
    country_code: int = 0
    region_code: str = ""
    location_name: str = ""
    carrier_name: str = ""
    line_type: str = "Unknown"
    timezones: List[str] = field(default_factory=list)
    privacy_risk_level: str = "MEDIUM"  # "HIGH", "MEDIUM", "LOW"
    privacy_score: int = 50             # 0-100 (100 = most private / least linkable)
    privacy_recommendations: List[str] = field(default_factory=list)
    dork_links: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PhonePrivacyEngine:
    """Analyzes phone numbers for personal exposure, SIM linking, and VoIP privacy."""

    @classmethod
    def audit_phone(cls, phone_input: str, default_region: Optional[str] = None) -> PhonePrivacyReport:
        clean_input = phone_input.strip()
        report = PhonePrivacyReport(raw_input=clean_input)

        if not clean_input:
            report.warnings.append("No phone number supplied for analysis.")
            return report

        try:
            # Parse number with fallback default region
            num_obj = phonenumbers.parse(clean_input, default_region or "US")
        except phonenumbers.NumberParseException as e:
            # If parsing failed and doesn't start with +, retry assuming default region
            report.warnings.append(f"Phone number parsing error: {e}")
            return report

        is_valid = phonenumbers.is_valid_number(num_obj)
        is_possible = phonenumbers.is_possible_number(num_obj)

        report.is_valid = is_valid
        report.is_possible = is_possible
        report.country_code = num_obj.country_code
        report.region_code = phonenumbers.region_code_for_number(num_obj) or ""

        # Formats
        e164 = phonenumbers.format_number(num_obj, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(num_obj, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat = phonenumbers.format_number(num_obj, phonenumbers.PhoneNumberFormat.NATIONAL)
        rfc = phonenumbers.format_number(num_obj, phonenumbers.PhoneNumberFormat.RFC3966)

        report.e164 = e164
        report.international = intl
        report.national = nat
        report.rfc3966 = rfc

        # Geolocation & Carrier metadata
        loc = geocoder.description_for_number(num_obj, "en")
        car = carrier.name_for_number(num_obj, "en")
        tzs = list(timezone.time_zones_for_number(num_obj))

        report.location_name = loc or "Unknown Region"
        report.carrier_name = car or "Unknown / Unassigned Carrier"
        report.timezones = tzs

        # Line type
        ntype = phonenumbers.number_type(num_obj)
        line_type_str = LINE_TYPE_MAP.get(ntype, "Unknown")
        report.line_type = line_type_str

        # Calculate Privacy Exposure Risk
        # Mobile carriers tie numbers directly to real-name KYC SIM registrations in most jurisdictions.
        # VoIP numbers provide significantly higher anonymity and burner privacy.
        if ntype == PhoneNumberType.VOIP:
            report.privacy_score = 90
            report.privacy_risk_level = "LOW"
            report.privacy_recommendations.append(
                "VoIP number detected: Provides strong privacy separation from personal identity, credit bureaus, and cellular SIM registries."
            )
        elif ntype == PhoneNumberType.MOBILE:
            report.privacy_score = 45
            report.privacy_risk_level = "HIGH"
            report.privacy_recommendations.extend([
                "Cellular Mobile SIM detected: Highly sensitive identifier. Direct link to SIM card identity and SMS 2FA vulnerability.",
                "Avoid sharing your primary cellular mobile number on public profiles, domain registrations, or retail forms.",
                "Migrate SMS two-factor authentication (2FA) accounts to hardware security keys (FIDO2) or authenticator apps (TOTP) to mitigate SIM swapping risks.",
            ])
        elif ntype in (PhoneNumberType.FIXED_LINE, PhoneNumberType.FIXED_LINE_OR_MOBILE):
            report.privacy_score = 55
            report.privacy_risk_level = "MEDIUM"
            report.privacy_recommendations.append(
                "Landline/Fixed line detected: Geographic location is publicly correlated to physical city/exchange."
            )
        else:
            report.privacy_score = 65
            report.privacy_risk_level = "MEDIUM"

        # Generate safe self-audit verification search links
        encoded_e164 = urllib.parse.quote(f'"{e164}"')
        encoded_intl = urllib.parse.quote(f'"{intl}"')

        report.dork_links = [
            {
                "title": "Google Public Web Index Check",
                "query": f'"{intl}"',
                "url": f"https://www.google.com/search?q={encoded_intl}",
                "description": "Check if this phone number is indexed on public blogs, forums, or resume documents.",
            },
            {
                "title": "Public Paste Sites Search",
                "query": f'site:pastebin.com "{e164}"',
                "url": f"https://www.google.com/search?q=site%3Apastebin.com+{encoded_e164}",
                "description": "Check if this number appears in public pastes, developer logs, or breach dumps.",
            },
            {
                "title": "Document & PDF Exposure Check",
                "query": f'filetype:pdf "{intl}"',
                "url": f"https://www.google.com/search?q=filetype%3Apdf+{encoded_intl}",
                "description": "Audit public PDF invoices, rosters, or corporate directory sheets.",
            },
        ]

        return report
