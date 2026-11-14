"""Unit and integration test suite for OSINT Recon Studio passive engines and exporter.

Uses mock network and DNS responses to enable 100% offline, deterministic verification
covering all core engines: DNS, RDAP, Web, Wayback, InternetDB, IP Intel,
Email Security, Tech Stack, Document Metadata, Exporter, Settings, Domain Utils,
URLScan/OTX Threat Archives, GitHub OSINT, PGP Keyserver, Brand Checker, and Subdomain Takeovers.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest
from PIL import Image
from pypdf import PdfWriter

from osint_studio.core.phone_privacy_engine import PhonePrivacyEngine, PhonePrivacyReport
from osint_studio.core.email_privacy_engine import EmailPrivacyEngine, EmailPrivacyReport
from osint_studio.core.social_privacy_engine import (
    SocialPrivacyEngine,
    SocialPrivacyReport,
    _extract_og_tag,
)
from osint_studio.core.archive_engine import ArchiveEngine
from osint_studio.core.dns_engine import (
    CAAAuditResult,
    DMARCAuditResult,
    DNSEngine,
    DNSRecord,
    SPFAuditResult,
)
from osint_studio.core.domain_utils import (
    extract_brand_handle,
    extract_root_domain,
    normalize_domain,
    sanitize_filename,
)
from osint_studio.core.email_security_engine import EmailSecurityEngine
from osint_studio.core.exporter import ReconExporter
from osint_studio.core.github_osint_engine import (
    GitHubOrgReport,
    GitHubRepo,
    audit_github_footprint,
)
from osint_studio.core.internetdb_engine import InternetDBEngine
from osint_studio.core.ip_intel_engine import IPIntelEngine
from osint_studio.core.metadata_engine import MetadataEngine
from osint_studio.core.pgp_osint_engine import (
    PGPReport,
    parse_hkp_mr_index,
    search_pgp_keys,
)
from osint_studio.core.rdap_engine import RDAPEngine
from osint_studio.core.takeover_audit_engine import (
    TakeoverAuditReport,
    audit_subdomain_takeover,
    check_subdomain_takeover,
)
from osint_studio.core.tech_stack_engine import TechStackEngine
from osint_studio.core.urlscan_engine import (
    ThreatArchiveReport,
    search_threat_archives,
)
from osint_studio.core.username_engine import (
    UsernameReport,
    check_brand_handles,
    clean_brand_handle,
)
from osint_studio.core.web_engine import WebEngine
from osint_studio.ui.settings_dialog import DEFAULT_CONFIG, load_config, save_config
from osint_studio.ui.styles import (
    CATPPUCCIN_MOCHA_QSS,
    MONOCHROME_QSS,
    get_theme_stylesheet,
)
from osint_studio.ui.workers import ReconWorker


class TestDomainUtils:
    """Tests for IDN/Punycode normalization and domain parsing utilities."""

    def test_normalize_domain(self):
        assert normalize_domain("https://example.com/path?arg=1") == "example.com"
        assert normalize_domain("  BLOG.EXAMPLE.COM:8080/  ") == "blog.example.com"
        assert normalize_domain("http://münchen.de/") == "xn--mnchen-3ya.de"

    def test_extract_root_domain(self):
        assert extract_root_domain("sub.example.com") == "example.com"
        assert extract_root_domain("api.internal.corp.co.uk") == "corp.co.uk"
        assert extract_root_domain("example.com") == "example.com"

    def test_extract_brand_handle(self):
        assert extract_brand_handle("github.com") == "github"
        assert extract_brand_handle("blog.cloudflare.co.uk") == "cloudflare"

    def test_clean_brand_handle(self):
        assert clean_brand_handle("user@example.com") == "user"
        assert clean_brand_handle("https://github.com/torvalds") == "torvalds"
        assert clean_brand_handle("  @mybrand  ") == "mybrand"
        assert clean_brand_handle("google.com") == "google"
        assert clean_brand_handle("") == ""

    def test_sanitize_filename(self):
        assert sanitize_filename("example.com:80/test") == "example.com_80_test"
        assert sanitize_filename("foo*bar?baz<qux>") == "foo_bar_baz_qux"


class TestDNSEngine:
    """Tests for passive DNS and email authentication audits."""

    def test_clean_domain(self):
        engine = DNSEngine()
        assert engine.clean_domain("https://example.com/test") == "example.com"
        assert engine.clean_domain("http://sub.domain.org:8080/") == "sub.domain.org"
        assert engine.clean_domain("  TARGET.COM.  ") == "target.com"

    def test_spf_hardfail(self):
        engine = DNSEngine()
        records = [
            DNSRecord("TXT", "example.com", "v=spf1 include:_spf.example.com -all", 300)
        ]
        result = engine.audit_spf("example.com", records)
        assert result.found is True
        assert result.status == "Strong"
        assert result.all_mechanism == "-all"
        assert result.multiple_records is False

    def test_spf_softfail(self):
        engine = DNSEngine()
        records = [
            DNSRecord("TXT", "example.com", "v=spf1 include:_spf.google.com ~all", 300)
        ]
        result = engine.audit_spf("example.com", records)
        assert result.found is True
        assert result.status == "Moderate"
        assert result.all_mechanism == "~all"

    def test_spf_risky_pass_all(self):
        engine = DNSEngine()
        records = [
            DNSRecord("TXT", "example.com", "v=spf1 +all", 300)
        ]
        result = engine.audit_spf("example.com", records)
        assert result.status == "Critical Risk"

    def test_caa_audit(self):
        engine = DNSEngine()
        records = [
            DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 300),
            DNSRecord("CAA", "example.com", '0 issuewild "digicert.com"', 300),
            DNSRecord("CAA", "example.com", '0 iodef "mailto:security@example.com"', 300),
        ]
        result = engine.audit_caa(records)
        assert result.configured is True
        assert "letsencrypt.org" in result.issuers
        assert "digicert.com" in result.wildcard_issuers

    @patch("httpx.Client.get")
    def test_crtsh_fallback_to_hackertarget(self, mock_get):
        resp_crt = MagicMock()
        resp_crt.status_code = 503

        resp_ht = MagicMock()
        resp_ht.status_code = 200
        resp_ht.text = "api.example.com,1.2.3.4\nmail.example.com,1.2.3.5"

        mock_get.side_effect = [resp_crt, resp_crt, resp_crt, resp_ht]

        engine = DNSEngine()
        subs = engine.query_certificate_transparency("example.com")
        assert len(subs) >= 2
        names = [s.subdomain for s in subs]
        assert "api.example.com" in names
        assert "mail.example.com" in names


class TestEmailSecurityEngine:
    """Tests for SPF, DMARC, DKIM, and MTA-STS analysis."""

    @patch("dns.resolver.Resolver.resolve")
    def test_dmarc_parsing(self, mock_resolve):
        engine = EmailSecurityEngine()
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = '"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com; aspf=s"'
        mock_resolve.return_value = [mock_rdata]

        found, rec, pol, sp, pct, rua, stat, recs = engine.audit_dmarc("example.com")
        assert found is True
        assert pol == "reject"
        assert pct == 100
        assert "dmarc@example.com" in rua

    @patch.object(EmailSecurityEngine, "audit_dmarc")
    @patch.object(EmailSecurityEngine, "audit_spf")
    @patch.object(EmailSecurityEngine, "probe_dkim_selectors")
    def test_scoring_matrix(self, mock_dkim, mock_spf, mock_dmarc):
        engine = EmailSecurityEngine()
        mock_spf.return_value = (True, "v=spf1 -all", "-all", "Strong", [], 1, ["v=spf1 -all"])
        mock_dmarc.return_value = (True, "v=DMARC1; p=reject", "reject", "reject", 100, "dmarc@example.com", "Strong", ["v=DMARC1"])
        mock_dkim.return_value = [MagicMock(found=True)]

        report = engine.analyze("example.com")
        assert report.spoofing_score >= 80
        assert report.spoofing_grade in ("A", "A+")


class TestTakeoverAuditEngine:
    """Tests for CNAME analysis and subdomain takeover risk assessment."""

    def test_check_subdomain_takeover_vulnerable(self):
        mock_resolver = MagicMock()

        # Subdomain resolves to CNAME github.io
        cname_rdata = MagicMock()
        cname_rdata.target = "myorg.github.io."
        mock_resolver.resolve.side_effect = [
            [cname_rdata],                        # 1st query: CNAME
            dns.resolver.NXDOMAIN(),              # 2nd query: Target host returns NXDOMAIN
        ]

        rec = check_subdomain_takeover("sub.example.com", resolver=mock_resolver)
        assert rec is not None
        assert rec.subdomain == "sub.example.com"
        assert rec.cname_target == "myorg.github.io"
        assert rec.provider == "GitHub Pages"
        assert rec.status == "VULNERABLE (NXDOMAIN)"
        assert rec.risk_level == "CRITICAL"
        assert rec.target_resolves is False

    def test_check_subdomain_takeover_active(self):
        mock_resolver = MagicMock()

        cname_rdata = MagicMock()
        cname_rdata.target = "active-app.herokuapp.com."

        a_rdata = MagicMock()
        mock_resolver.resolve.side_effect = [
            [cname_rdata],                        # 1st query: CNAME
            [a_rdata],                            # 2nd query: Target host resolves to A record
        ]

        rec = check_subdomain_takeover("app.example.com", resolver=mock_resolver)
        assert rec is not None
        assert rec.cname_target == "active-app.herokuapp.com"
        assert rec.provider == "Heroku"
        assert rec.status == "ACTIVE_PROVIDER_CNAME"
        assert rec.risk_level == "INFO"
        assert rec.target_resolves is True


class TestURLScanEngine:
    """Tests for URLScan.io and AlienVault OTX threat archive querying."""

    @patch("httpx.Client.get")
    def test_search_threat_archives(self, mock_get):
        urlscan_resp = MagicMock()
        urlscan_resp.status_code = 200
        urlscan_resp.json.return_value = {
            "total": 1,
            "results": [
                {
                    "_id": "scan123",
                    "task": {
                        "time": "2026-01-15T12:00:00Z",
                        "url": "https://example.com/",
                        "domain": "example.com",
                        "reportURL": "https://urlscan.io/result/scan123/",
                        "screenshotURL": "https://urlscan.io/screenshots/scan123.png",
                    },
                    "page": {
                        "ip": "93.184.216.34",
                        "asn": "AS15133",
                        "asnname": "EDGECAST",
                        "country": "US",
                        "title": "Example Domain",
                    },
                }
            ],
        }

        otx_resp = MagicMock()
        otx_resp.status_code = 200
        otx_resp.json.return_value = {
            "passive_dns": [
                {
                    "record_type": "A",
                    "address": "93.184.216.34",
                    "first": "2024-01-01",
                    "last": "2026-01-01",
                    "asn": "AS15133",
                }
            ]
        }

        mock_get.side_effect = [urlscan_resp, otx_resp]

        report = search_threat_archives("example.com")
        assert report.is_success is True
        assert report.total_scans_found == 1
        assert len(report.urlscan_records) == 1
        assert report.urlscan_records[0].ip == "93.184.216.34"
        assert len(report.otx_records) == 1


class TestGitHubOSINT:
    """Tests for GitHub REST API org footprint and SECURITY.md discovery."""

    @patch("httpx.AsyncClient.get")
    @patch("httpx.AsyncClient.head")
    def test_audit_github_footprint(self, mock_head, mock_get):
        # Org endpoint
        org_resp = MagicMock()
        org_resp.status_code = 200
        org_resp.headers = {"x-ratelimit-remaining": "59"}
        org_resp.json.return_value = {
            "name": "Example Corp",
            "description": "An open platform",
            "blog": "https://example.com",
            "public_repos": 10,
            "followers": 150,
            "created_at": "2015-01-01T00:00:00Z",
            "html_url": "https://github.com/example",
        }

        # Repos endpoint
        repos_resp = MagicMock()
        repos_resp.status_code = 200
        repos_resp.json.return_value = [
            {
                "name": "core-engine",
                "full_name": "example/core-engine",
                "html_url": "https://github.com/example/core-engine",
                "description": "Core OSINT Engine",
                "language": "Python",
                "stargazers_count": 42,
                "forks_count": 8,
                "open_issues_count": 2,
                "updated_at": "2026-11-14T00:00:00Z",
                "fork": False,
                "archived": False,
                "topics": ["osint", "recon"],
            }
        ]

        # Community profile
        comm_resp = MagicMock()
        comm_resp.status_code = 200
        comm_resp.json.return_value = {
            "files": {
                "security_policy": {
                    "url": "https://github.com/example/.github/blob/main/SECURITY.md",
                    "html_url": "https://github.com/example/.github/blob/main/SECURITY.md",
                }
            }
        }

        mock_get.side_effect = [org_resp, repos_resp, comm_resp]

        report = audit_github_footprint("example.com")
        assert report.is_success is True
        assert report.entity_type == "Organization"
        assert report.name == "Example Corp"
        assert len(report.repos) == 1
        assert report.repos[0].name == "core-engine"
        assert report.has_security_policy is True
        assert report.total_stars == 42


class TestPGPOSINT:
    """Tests for HKP machine-readable PGP keyserver parsing and queries."""

    def test_parse_hkp_mr_index(self):
        sample_mr = (
            "info:1:2\n"
            "pub:1234567890ABCDEF:1:4096:1546300800::\n"
            "uid:Linus%20Torvalds%20%3Ctorvalds%40kernel.org%3E:1546300800::\n"
            "pub:FEDCBA0987654321:19:256:1609459200::\n"
            "uid:Greg%20Kroah-Hartman%20%3Cgregkh%40linuxfoundation.org%3E:1609459200::\n"
        )

        keys = parse_hkp_mr_index(sample_mr, "kernel.org")
        assert len(keys) == 2
        assert keys[0].key_id == "1234567890ABCDEF"
        assert keys[0].key_length == 4096
        assert len(keys[0].identities) == 1
        assert keys[0].identities[0].name == "Linus Torvalds"
        assert keys[0].identities[0].email == "torvalds@kernel.org"
        assert keys[0].identities[0].is_domain_match is True
        assert keys[1].identities[0].is_domain_match is False


class TestUsernameEngine:
    """Tests for Sherlock-style 20-platform brand and username checker."""

    @patch("httpx.AsyncClient.get")
    def test_check_brand_handles(self, mock_get):
        resp_claimed = MagicMock()
        resp_claimed.status_code = 200
        resp_claimed.text = "profile page"
        resp_claimed.json.return_value = {"id": "octocat"}

        mock_get.return_value = resp_claimed

        report = check_brand_handles("octocat")
        assert report.is_success is True
        assert report.total_checked == 20
        assert report.claimed_count > 0


class TestInternetDBEngine:
    """Tests for Shodan InternetDB zero-key queries."""

    @patch("httpx.Client.get")
    def test_query_ip(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "ip": "1.1.1.1",
            "ports": [53, 80, 443],
            "cpes": ["cpe:/a:cloudflare:dns"],
            "hostnames": ["one.one.one.one"],
            "tags": ["dns", "cloudflare"],
            "vulns": ["CVE-2021-9999"],
        }
        mock_get.return_value = resp

        engine = InternetDBEngine()
        res = engine.query_ip("1.1.1.1")
        assert res.ip == "1.1.1.1"
        assert 53 in res.ports
        assert "CVE-2021-9999" in res.vulns


class TestIPIntelEngine:
    """Tests for ASN, ISP, and Cloud Provider detection."""

    @patch("httpx.Client.get")
    def test_query_ipwhois(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "ip": "104.16.132.229",
            "country": "United States",
            "city": "San Francisco",
            "isp": "Cloudflare, Inc.",
            "org": "Cloudflare, Inc.",
            "connection": {"asn": 13335, "org": "CLOUDFLARENET"},
        }
        mock_get.return_value = resp

        engine = IPIntelEngine()
        info = engine.query_ip("104.16.132.229")
        assert info.country == "United States"
        assert info.cloud_provider == "Cloudflare"
        assert "13335" in str(info.asn)


class TestMetadataEngine:
    """Tests for PDF and image metadata extraction."""

    def test_extract_pdf_metadata(self, tmp_path: Path):
        pdf_path = tmp_path / "test_doc.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.add_metadata({
            "/Author": "Security Researcher",
            "/Creator": "OSINT Studio Test Suite",
            "/Producer": "PyPDF Testing",
        })
        with open(pdf_path, "wb") as f:
            writer.write(f)

        engine = MetadataEngine()
        report = engine.inspect_file(str(pdf_path))
        assert report.file_type == "PDF"
        assert report.author == "Security Researcher"
        assert report.creator_tool == "OSINT Studio Test Suite"

    def test_extract_image_metadata(self, tmp_path: Path):
        img_path = tmp_path / "test_img.jpg"
        img = Image.new("RGB", (50, 50), color="blue")
        img.save(img_path, format="JPEG")

        engine = MetadataEngine()
        report = engine.inspect_file(str(img_path))
        assert report.file_type == "IMAGE"
        assert report.file_size_bytes > 0


class TestRDAPEngine:
    """Tests for RDAP parsing and normalization."""

    def test_vcard_extraction(self):
        engine = RDAPEngine()
        sample_vcard = [
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Security Department"],
                ["org", {}, "text", "Example Global Corp"],
                ["email", {}, "text", "abuse@example.com"],
                ["tel", {}, "text", "+1.555019999"],
            ],
        ]
        parsed = engine._parse_vcard(sample_vcard)
        assert parsed["name"] == "Security Department"
        assert parsed["email"] == "abuse@example.com"


class TestWebEngine:
    """Tests for HTTP security headers and posture evaluation."""

    def test_audit_security_headers_perfect_grade(self):
        engine = WebEngine()
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        }
        items, score, grade = engine.audit_security_headers(headers)
        assert score >= 90
        assert grade in ("A", "A+")


class TestArchiveEngine:
    """Tests for Wayback Machine metadata extraction."""

    def test_format_timestamp(self):
        engine = ArchiveEngine()
        ts = "20220514123045"
        formatted = engine._format_timestamp(ts)
        assert formatted == "2022-05-14 12:30:45 UTC"


class TestExporter:
    """Tests for JSON, Markdown, and HTML report generation."""

    @pytest.fixture
    def sample_data(self):
        return {
            "domain": "example.com",
            "timestamp": "2026-11-14T00:00:00Z",
            "scorecard": {"score": 92, "grade": "A", "findings": []},
            "dns": {"records": [], "ct_subdomains": [], "subdomain_count": 0},
            "takeover": {"vulnerable_count": 0, "dangling_count": 0, "cname_count": 0, "records": []},
            "rdap": {"registrar_name": "Example LLC"},
            "web": {"security_grade": "A", "security_score": 90, "security_headers": []},
            "archive": {"is_archived": True, "total_samples": 5},
            "internetdb": {"all_open_ports": [80, 443], "all_cves": [], "hosts": []},
            "ip_intel": {"unique_countries": ["US"], "cloud_providers_detected": ["Cloudflare"]},
            "urlscan": {"total_scans_found": 1, "urlscan_records": []},
            "email_sec": {"spoofing_grade": "A", "spoofing_score": 90, "spf_status": "Strong"},
            "tech_stack": {"technologies": [{"name": "React", "category": "Framework", "evidence": "HTML"}]},
            "github": {"handle": "example", "entity_type": "Organization", "public_repos_count": 5},
            "pgp": {"total_keys": 1, "keys": []},
            "username": {"claimed_count": 3, "results": []},
        }

    def test_export_json_and_markdown_and_html(self, tmp_path: Path, sample_data):
        j_out = tmp_path / "rep.json"
        m_out = tmp_path / "rep.md"
        h_out = tmp_path / "rep.html"

        ReconExporter.export_json(sample_data, str(j_out))
        ReconExporter.export_markdown(sample_data, str(m_out))
        ReconExporter.export_html(sample_data, str(h_out))

        assert j_out.exists()
        assert m_out.exists()
        assert h_out.exists()
        assert "Passive OSINT & Attack Surface Audit" in m_out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in h_out.read_text(encoding="utf-8")


class TestPhonePrivacyEngine:
    """Tests for personal phone number intelligence and exposure auditor."""

    def test_valid_phone_parsing(self):
        # Googleplex Mountain View CA standard number
        report = PhonePrivacyEngine.audit_phone("+16502530000")
        assert report.is_valid is True
        assert report.is_possible is True
        assert report.country_code == 1
        assert report.region_code == "US"
        assert report.e164 == "+16502530000"
        assert "+1 650-253-0000" in report.international or "+1 650 253 0000" in report.international
        assert "Mountain View" in report.location_name
        assert len(report.dork_links) >= 3
        assert report.privacy_score > 0

    def test_invalid_and_empty_phone(self):
        empty_rep = PhonePrivacyEngine.audit_phone("")
        assert empty_rep.is_valid is False
        assert len(empty_rep.warnings) > 0

        invalid_rep = PhonePrivacyEngine.audit_phone("not-a-number")
        assert invalid_rep.is_valid is False
        assert len(invalid_rep.warnings) > 0

    def test_toll_free_line_type(self):
        report = PhonePrivacyEngine.audit_phone("+18005550199")
        assert report.is_possible is True
        assert "Toll-Free" in report.line_type or "Toll" in report.line_type


class TestEmailPrivacyEngine:
    """Tests for personal email exposure, breach audit, and avatar leaks."""

    def test_email_format_and_hashing(self):
        report = EmailPrivacyEngine.audit_email("John.Doe@example.com")
        assert report.is_valid_format is True
        assert report.domain == "example.com"
        assert report.md5_hash == "8eb1b522f60d11fa897de1dc6351b7e8"
        assert len(report.sha256_hash) == 64

    def test_disposable_domain_detection(self):
        report = EmailPrivacyEngine.audit_email("anonymous_user@mailinator.com")
        assert report.is_disposable is True
        assert any("Disposable" in r for r in report.recommendations)

    @patch("httpx.AsyncClient.get")
    def test_gravatar_and_breach_parsing(self, mock_get):
        async def mock_fetch(url, *args, **kwargs):
            url_str = str(url)
            resp = MagicMock()
            if "gravatar.com" in url_str:
                resp.status_code = 200
                resp.json.return_value = {
                    "entry": [
                        {
                            "displayName": "Alex Dev",
                            "profileUrl": "https://gravatar.com/alexdev",
                            "accounts": [{"shortname": "github", "url": "https://github.com/alexdev"}],
                        }
                    ]
                }
            elif "xposedornot.com" in url_str:
                resp.status_code = 200
                resp.json.return_value = {
                    "breaches": [["Adobe", "LinkedIn"]],
                }
            else:
                resp.status_code = 404
            return resp

        mock_get.side_effect = mock_fetch

        report = EmailPrivacyEngine.audit_email("alex@example.com")
        assert report.is_valid_format is True
        assert report.gravatar_found is True
        assert report.gravatar_display_name == "Alex Dev"
        assert report.breaches_count == 2
        assert any(b.breach_name == "Adobe" for b in report.breaches)
        assert report.privacy_score < 100


class TestSocialPrivacyEngine:
    """Tests for social media OpenGraph extraction and linkability scoring."""

    def test_extract_og_tag(self):
        html = """
        <html>
            <head>
                <meta property="og:title" content="Jane Doe | Profile" />
                <meta property="og:description" content="Senior Software Engineer & OSINT Researcher" />
                <meta content="https://example.com/avatar.jpg" property="og:image" />
            </head>
        </html>
        """
        assert _extract_og_tag(html, "title") == "Jane Doe | Profile"
        assert _extract_og_tag(html, "description") == "Senior Software Engineer & OSINT Researcher"
        assert _extract_og_tag(html, "image") == "https://example.com/avatar.jpg"
        assert _extract_og_tag(html, "nonexistent") == ""

    @patch("httpx.AsyncClient.get")
    def test_audit_social_handle_linkability(self, mock_get):
        async def mock_social_get(url, *args, **kwargs):
            url_str = str(url)
            resp = MagicMock()
            if "github.com" in url_str:
                resp.status_code = 200
                resp.text = '<html><meta property="og:title" content="DevJane - GitHub" /></html>'
            elif "reddit.com" in url_str:
                resp.status_code = 200
                resp.text = '<html><meta property="og:title" content="Overview for DevJane" /></html>'
            elif "instagram.com" in url_str:
                resp.status_code = 200
                resp.text = '<html><meta property="og:title" content="Login • Instagram" /></html>'
            else:
                resp.status_code = 404
                resp.text = "Not found"
            return resp

        mock_get.side_effect = mock_social_get

        report = SocialPrivacyEngine.audit_social_handle("DevJane")
        assert report.handle == "DevJane"
        assert report.total_platforms_checked == 8
        assert report.public_profiles_found >= 2
        assert report.linkability_score > 0
        assert len(report.hardening_tips) > 0


class TestThemeStyles:
    """Tests for GUI visual styling and theme switching."""

    def test_theme_stylesheet_resolution(self):
        mocha_qss = get_theme_stylesheet("mocha")
        assert "CATPPUCCIN" in mocha_qss or "#1e1e2e" in mocha_qss

        mono_qss = get_theme_stylesheet("monochrome")
        assert "Monochrome" in mono_qss or "#0b0b0b" in mono_qss

        mono_fallback = get_theme_stylesheet("bw")
        assert mono_fallback == mono_qss

        default_fallback = get_theme_stylesheet("unknown_theme")
        assert default_fallback == mocha_qss


