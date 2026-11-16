"""Unit tests for LegalScraperEngine, LightweightHTMLHarvester, and Compliance Gatekeeper."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from osint_studio.core.legal_scraper_engine import (
    ComplianceReport,
    FeedItem,
    HeuristicPublicStructurer,
    LegalScraperEngine,
    LightweightHTMLHarvester,
    RobotsComplianceGatekeeper,
    ScrapedMeta,
    StructuredPublicIntelligence,
)


class TestLegalScraperEngine:
    """Test suite for Phase 7 AI-Assisted Legal Public Data Scraping Engine."""

    def test_lightweight_html_harvester(self):
        html = (
            "<!DOCTYPE html>"
            "<html><head>"
            "<title>Acme Corporation - Cloud Security</title>"
            '<meta name="description" content="Enterprise defense systems.">'
            '<meta property="og:title" content="Acme Cloud">'
            '<meta property="og:site_name" content="Acme Defense">'
            '<meta name="author" content="Jane Doe">'
            '<meta name="generator" content="WordPress 6.4">'
            '<link rel="canonical" href="https://acme.org/">'
            '<link rel="alternate" type="application/rss+xml" href="/feed.xml">'
            '<script type="application/ld+json">'
            '{"@context": "https://schema.org", "@type": "Organization", "name": "Acme Defense LLC"}'
            "</script>"
            "</head><body>"
            "<nav><a href='/'>Home</a></nav>"
            "<p>Acme Corporation provides automated defensive OSINT reconnaissance.</p>"
            "<p>Contact security@acme.org or visit https://github.com/acme-org for details.</p>"
            "<footer>Copyright © 2026 Acme Corp. All rights reserved.</footer>"
            "</body></html>"
        )

        harvester = LightweightHTMLHarvester()
        harvester.feed(html)

        assert harvester.meta.title == "Acme Corporation - Cloud Security"
        assert harvester.meta.description == "Enterprise defense systems."
        assert harvester.meta.author == "Jane Doe"
        assert harvester.meta.site_name == "Acme Defense"
        assert harvester.meta.canonical_url == "https://acme.org/"
        assert "/feed.xml" in harvester.feed_urls
        assert len(harvester.meta.json_ld_entities) == 1
        assert harvester.meta.json_ld_entities[0].get("name") == "Acme Defense LLC"

        body = harvester.get_clean_body_text()
        assert "Home" not in body  # <nav> should be stripped
        assert "Acme Corporation provides automated defensive OSINT" in body

    def test_heuristic_public_structurer(self):
        meta = ScrapedMeta(
            title="SecCorp Global",
            description="Leading cybersecurity monitoring.",
            site_name="SecCorp",
            author="John Smith",
            generator="WordPress",
            json_ld_entities=[{"@type": "Corporation", "name": "SecCorp Inc."}],
        )
        body = (
            "We build secure cloud telemetry. Contact us at info@seccorp.com or support@seccorp.com. "
            "Follow our repositories at https://github.com/seccorp and https://twitter.com/seccorp_official. "
            "Copyright © 2026 SecCorp International."
        )
        feeds = [
            FeedItem(title="Q4 Security Threat Report", published="2026-11-10", summary="Analysis of recent cloud CVEs.")
        ]

        intel = HeuristicPublicStructurer.extract_structured_intel("seccorp.com", meta, body, feeds)

        assert "info@seccorp.com" in intel.contact_endpoints
        assert "support@seccorp.com" in intel.contact_endpoints
        assert "https://github.com/seccorp" in intel.organization_links
        assert "WordPress CMS" in intel.tech_identifiers
        assert any("SecCorp" in e for e in intel.entities)
        assert len(intel.public_statements) >= 1
        assert "SecCorp Global" in intel.clean_summary

    def test_robots_compliance_gatekeeper(self):
        import asyncio
        mock_robots_txt = (
            "User-agent: *\n"
            "Crawl-delay: 2\n"
            "Disallow: /admin/\n"
            "Disallow: /private/\n"
            "Sitemap: https://target.com/sitemap.xml\n"
        )
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = mock_robots_txt
        mock_client.get.return_value = mock_resp

        report, parser = asyncio.run(
            RobotsComplianceGatekeeper.evaluate_compliance(mock_client, "target.com")
        )
        assert report.robots_txt_found is True
        assert report.crawl_delay == 2.0
        assert "/admin/" in report.disallowed_paths
        assert "https://target.com/sitemap.xml" in report.sitemaps
        assert report.is_scraping_allowed is True

    def test_legal_scraper_engine_sync(self):
        engine = LegalScraperEngine()
        with patch.object(engine, "analyze_async", new_callable=AsyncMock) as mock_async:
            from osint_studio.core.legal_scraper_engine import LegalScraperReport
            mock_async.return_value = LegalScraperReport(domain="test.com", is_success=True)
            res = engine.analyze("test.com")
            assert res.domain == "test.com"
            assert res.is_success is True
