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

    Robustly handles full URLs, basic authentication credentials, port numbers,
    query parameters, email addresses, and internationalized domain names (IDNs).

    Examples:
        'https://münchen.de/path?arg=1#frag' -> 'xn--mnchen-3ya.de'
        '  BLOG.Example.COM:8080/  ' -> 'blog.example.com'
        'https://user:pass@example.com:8443/api/v1' -> 'example.com'
        'contact@company.co.uk' -> 'company.co.uk'
    """
    if not domain_input:
        return ""

    d = domain_input.strip()

    # Prepend scheme if missing so urllib.parse correctly extracts hostnames from paths and ports
    test_url = d if "://" in d else f"https://{d}"

    try:
        parsed = urllib.parse.urlparse(test_url)
        host = parsed.hostname or parsed.netloc or d
    except Exception:
        host = d

    # Strip residual paths, queries, fragments, ports, and whitespace
    host = host.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip(". \t\r\n")

    # If an email address was passed, extract domain part
    if "@" in host:
        host = host.split("@")[-1]

    if not host:
        return ""

    # Convert Internationalized Domain Names (IDN) via Punycode
    try:
        host = idna.encode(host.lower()).decode("ascii")
    except Exception:
        host = host.lower()

    return host


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
