"""Public PGP Keyserver & Corporate Contact OSINT Engine.

Queries public OpenPGP keyservers (keyserver.ubuntu.com, pgp.mit.edu) using the standard
machine-readable (HKP MR) protocol to passively discover corporate contact names,
cryptographic key IDs, algorithms, creation timestamps, and email identities under a domain.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import email.utils
import logging
import re
from typing import Any, Dict, List, Optional
import urllib.parse

import certifi
import httpx

from osint_studio.core.domain_utils import extract_root_domain, normalize_domain

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"
PRIMARY_KEYSERVER = "https://keyserver.ubuntu.com/pks/lookup"
FALLBACK_KEYSERVER = "https://pgp.mit.edu/pks/lookup"

# OpenPGP Algorithm Map (RFC 4880 / RFC 9580)
ALGORITHM_MAP = {
    "1": "RSA (Encrypt or Sign)",
    "2": "RSA Encrypt-Only",
    "3": "RSA Sign-Only",
    "16": "Elgamal",
    "17": "DSA",
    "18": "ECDH",
    "19": "ECDSA",
    "22": "EdDSA",
}


@dataclass
class PGPKeyIdentity:
    """A user ID (UID) associated with a PGP public key."""
    name: str
    email: str
    raw_uid: str
    is_domain_match: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PGPKeyRecord:
    """Public PGP key metadata."""
    key_id: str
    algorithm: str = "Unknown"
    key_length: int = 0
    created_at: str = ""
    expires_at: str = "Never"
    flags: str = ""
    is_revoked: bool = False
    identities: List[PGPKeyIdentity] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PGPReport:
    """Consolidated PGP keyserver intelligence report."""
    target_domain: str
    keys: List[PGPKeyRecord] = field(default_factory=list)
    discovered_emails: List[str] = field(default_factory=list)
    domain_specific_emails: List[str] = field(default_factory=list)
    total_keys: int = 0
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _format_epoch(epoch_str: str) -> str:
    """Converts a UNIX epoch timestamp string to ISO date format."""
    if not epoch_str or epoch_str == "0":
        return ""
    try:
        ts = int(epoch_str)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return epoch_str


def parse_hkp_mr_index(raw_text: str, target_domain: str) -> List[PGPKeyRecord]:
    """Parses HKP Machine-Readable (MR) index format into structured PGPKeyRecord objects."""
    records: List[PGPKeyRecord] = []
    current_key: Optional[PGPKeyRecord] = None
    target_domain_lower = target_domain.lower()

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split(":")
        tag = parts[0]

        if tag == "pub":
            # pub:<keyid>:<algo>:<keylen>:<creationdate>:<expirationdate>:<flags>
            if current_key:
                records.append(current_key)

            key_id = parts[1] if len(parts) > 1 else "Unknown"
            algo_code = parts[2] if len(parts) > 2 else ""
            algo_name = ALGORITHM_MAP.get(algo_code, f"Algorithm {algo_code}" if algo_code else "Unknown")
            key_len = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
            created = _format_epoch(parts[4]) if len(parts) > 4 else ""
            expires = _format_epoch(parts[5]) if len(parts) > 5 and parts[5] else "Never"
            flags = parts[6] if len(parts) > 6 else ""
            is_rev = "r" in flags.lower()

            current_key = PGPKeyRecord(
                key_id=key_id,
                algorithm=algo_name,
                key_length=key_len,
                created_at=created,
                expires_at=expires,
                flags=flags,
                is_revoked=is_rev,
                identities=[],
            )

        elif tag == "uid" and current_key is not None:
            # uid:<escaped uid string>:<creationdate>:<expirationdate>:<flags>
            raw_uid_escaped = parts[1] if len(parts) > 1 else ""
            raw_uid = urllib.parse.unquote(raw_uid_escaped).strip()

            name, parsed_email = email.utils.parseaddr(raw_uid)
            if not parsed_email and "@" in raw_uid:
                # Regex fallback for email extraction
                match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_uid)
                if match:
                    parsed_email = match.group(0)

            is_domain = parsed_email.lower().endswith(f"@{target_domain_lower}") or target_domain_lower in parsed_email.lower()

            identity = PGPKeyIdentity(
                name=name or (raw_uid if not parsed_email else ""),
                email=parsed_email,
                raw_uid=raw_uid,
                is_domain_match=is_domain,
            )
            current_key.identities.append(identity)

    if current_key:
        records.append(current_key)

    return records


async def search_pgp_keys_async(domain: str, timeout: float = 10.0) -> PGPReport:
    """Queries public PGP keyservers for keys matching the target domain."""
    clean_domain = normalize_domain(domain)
    root_domain = extract_root_domain(clean_domain) or clean_domain

    report = PGPReport(target_domain=clean_domain)
    if not clean_domain:
        report.warnings.append("No valid domain provided for PGP keyserver lookup.")
        return report

    params = {
        "search": clean_domain,
        "op": "index",
        "options": "mr",
    }

    async with httpx.AsyncClient(
        verify=certifi.where(),
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        # Try primary keyserver (Ubuntu)
        raw_body = ""
        try:
            resp = await client.get(PRIMARY_KEYSERVER, params=params)
            if resp.status_code == 200:
                raw_body = resp.text
            elif resp.status_code == 404 or "No keys found" in resp.text:
                report.is_success = True
                return report
            else:
                logger.warning("Primary keyserver returned status %d", resp.status_code)
        except Exception as exc:
            logger.warning("Primary keyserver connection failed: %s; trying fallback", exc)

        # Fallback to MIT keyserver if primary failed
        if not raw_body:
            try:
                resp = await client.get(FALLBACK_KEYSERVER, params=params)
                if resp.status_code == 200:
                    raw_body = resp.text
                elif resp.status_code == 404:
                    report.is_success = True
                    return report
            except Exception as exc:
                logger.warning("Fallback keyserver connection failed: %s", exc)
                report.warnings.append(f"PGP keyserver lookup timed out or was unreachable: {exc}")
                return report

        if not raw_body:
            report.is_success = True
            return report

        # Parse machine-readable records
        keys = parse_hkp_mr_index(raw_body, root_domain)
        report.keys = keys
        report.total_keys = len(keys)

        emails_seen = set()
        domain_emails = set()

        for k in keys:
            for ident in k.identities:
                em = ident.email.lower()
                if em and "@" in em:
                    emails_seen.add(em)
                    if ident.is_domain_match:
                        domain_emails.add(em)

        report.discovered_emails = sorted(list(emails_seen))
        report.domain_specific_emails = sorted(list(domain_emails))
        report.is_success = True

    return report


def search_pgp_keys(domain: str, timeout: float = 10.0) -> PGPReport:
    """Synchronous convenience wrapper for search_pgp_keys_async."""
    try:
        return asyncio.run(search_pgp_keys_async(domain, timeout=timeout))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(search_pgp_keys_async(domain, timeout=timeout))
        finally:
            loop.close()
