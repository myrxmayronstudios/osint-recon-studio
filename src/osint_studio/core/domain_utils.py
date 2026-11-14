"""Domain sanitization, Punycode/IDN normalization, and name parsing utilities.

Properly normalizes Internationalized Domain Names (IDNs), strips URLs, protocols,
paths, and ports, and safely extracts root domains and organization name handles.
"""

from __future__ import annotations

import re
import urllib.parse
import idna


TWO_LEVEL_TLDS = {
    "co.uk", "ac.uk", "gov.uk", "org.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.za", "org.za", "net.za", "gov.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "org.mx", "edu.mx", "gob.mx",
    "com.sg", "edu.sg", "gov.sg",
    "co.in", "net.in", "org.in", "gen.in",
}


def normalize_domain(domain_input: str) -> str:
    """Sanitizes user input, strips protocols/paths/ports, and applies IDN/Punycode encoding.

    Examples:
        'https://münchen.de/path' -> 'xn--mnchen-3ya.de'
        '  BLOG.Example.COM:8080/  ' -> 'blog.example.com'
    """
    if not domain_input:
        return ""

    d = domain_input.strip()
    if "://" in d:
        parsed = urllib.parse.urlparse(d)
        d = parsed.netloc or parsed.path

    # Strip paths, parameters, ports, and trailing periods
    d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip(". \t\r\n")

    if not d:
        return ""

    # Convert Internationalized Domain Names (IDN) via Punycode
    try:
        d = idna.encode(d.lower()).decode("ascii")
    except Exception:
        d = d.lower()

    return d


def extract_root_domain(domain: str) -> str:
    """Extracts the registered root domain from a subdomain or FQDN.

    Examples:
        'blog.sub.example.com' -> 'example.com'
        'app.corp.co.uk' -> 'corp.co.uk'
        'localhost' -> 'localhost'
    """
    clean_d = normalize_domain(domain)
    parts = clean_d.split(".")
    if len(parts) <= 2:
        return clean_d

    # Check for known 2-level TLDs
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in TWO_LEVEL_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"

    return f"{parts[-2]}.{parts[-1]}"


def extract_brand_handle(domain: str) -> str:
    """Derives a candidate brand or organization handle slug from a domain name.

    Examples:
        'github.com' -> 'github'
        'google.co.uk' -> 'google'
        'blog.microsoft.com' -> 'microsoft'
    """
    root = extract_root_domain(domain)
    return root.split(".")[0]


def sanitize_filename(filename: str, replacement: str = "_") -> str:
    """Sanitizes strings for safe cross-platform filesystem filenames.

    Prevents Windows OSError: [Errno 22] Invalid argument by replacing reserved characters.
    """
    # Windows reserved characters: < > : " / \ | ? *
    return re.sub(r'[<>:"/\\|?*\s]+', replacement, filename).strip("._")
