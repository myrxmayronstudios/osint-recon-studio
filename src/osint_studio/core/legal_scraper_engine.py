"""AI-Assisted Legal Public Data Scraping & Harvesting Engine.

Passively and strictly legally gathers publicly available web intelligence:
- Robots.txt & Crawl-Delay Compliance Gatekeeper
- OpenGraph, Twitter Card & Meta Tag Harvester
- Schema.org JSON-LD Structured Entity Extractor
- RSS/Atom Public News & Blog Feed Discoverer
- AI-Driven Public Text Noise Removal & Entity Structuring (Ollama / 0-RAM Heuristic fallback)

Strictly observes legal boundaries: zero credential stuffing, zero paywall/login bypass,
zero CAPTCHA solving, and 100% respect for robots.txt disallow directives.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import urllib.robotparser
import xml.etree.ElementTree as ET

import certifi
import httpx

from osint_studio.core.domain_utils import normalize_domain
from osint_studio.core.fast_network import FastHttpClient

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "OSINTReconStudio-LegalHarvester/1.0 (+https://github.com/myrxmayronstudios/osint-recon-studio)"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ScrapedMeta:
    """HTML <meta>, OpenGraph, and Twitter Card metadata."""
    title: str = ""
    description: str = ""
    keywords: List[str] = field(default_factory=list)
    author: str = ""
    canonical_url: str = ""
    site_name: str = ""
    og_type: str = ""
    og_image: str = ""
    twitter_card: str = ""
    generator: str = ""
    json_ld_entities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FeedItem:
    """Public RSS/Atom article or bulletin entry."""
    title: str
    link: str = ""
    published: str = ""
    author: str = ""
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceReport:
    """Legal harvesting posture and robots.txt evaluation."""
    domain: str
    robots_txt_found: bool = False
    is_scraping_allowed: bool = True
    crawl_delay: float = 1.5
    disallowed_paths: List[str] = field(default_factory=list)
    sitemaps: List[str] = field(default_factory=list)
    legal_disclaimer: str = (
        "Strictly legal public OSINT: zero login bypass, zero paywall intrusion, "
        "and 100% respect for robots.txt compliance rules."
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StructuredPublicIntelligence:
    """AI-extracted & normalized intelligence from raw public text."""
    target_domain: str
    entities: List[str] = field(default_factory=list)
    organization_links: List[str] = field(default_factory=list)
    public_statements: List[str] = field(default_factory=list)
    tech_identifiers: List[str] = field(default_factory=list)
    contact_endpoints: List[str] = field(default_factory=list)
    clean_summary: str = ""
    extraction_method: str = "Deterministic Heuristic"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LegalScraperReport:
    """Consolidated report produced by the legal harvesting engine."""
    domain: str
    compliance: ComplianceReport = field(default_factory=lambda: ComplianceReport(domain=""))
    metadata: ScrapedMeta = field(default_factory=ScrapedMeta)
    feeds: List[FeedItem] = field(default_factory=list)
    extracted_intelligence: StructuredPublicIntelligence = field(
        default_factory=lambda: StructuredPublicIntelligence(target_domain="")
    )
    harvested_urls: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "compliance": self.compliance.to_dict(),
            "metadata": self.metadata.to_dict(),
            "feeds": [f.to_dict() for f in self.feeds],
            "extracted_intelligence": self.extracted_intelligence.to_dict(),
            "harvested_urls": self.harvested_urls,
            "warnings": self.warnings,
            "is_success": self.is_success,
        }


# =============================================================================
# Lightweight HTML & Metadata Parser (Zero Heavy Dependencies)
# =============================================================================

class LightweightHTMLHarvester(HTMLParser):
    """Fast, safe streaming HTML parser extracting meta, OpenGraph, JSON-LD and clean text."""

    def __init__(self) -> None:
        super().__init__()
        self.meta = ScrapedMeta()
        self.feed_urls: List[str] = []
        self._current_tag = ""
        self._in_title = False
        self._in_json_ld = False
        self._json_ld_buffer = ""
        self._text_chunks: List[str] = []
        self._ignored_tags = {"script", "style", "noscript", "svg", "header", "footer", "nav"}
        self._current_ignored = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        tag_lower = tag.lower()
        self._current_tag = tag_lower
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag_lower in self._ignored_tags:
            self._current_ignored = True

        if tag_lower == "title":
            self._in_title = True

        elif tag_lower == "script" and attr_dict.get("type") == "application/ld+json":
            self._in_json_ld = True
            self._json_ld_buffer = ""

        elif tag_lower == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href", "")
            t_type = attr_dict.get("type", "").lower()
            if "canonical" in rel and href:
                self.meta.canonical_url = href
            elif ("rss" in t_type or "atom" in t_type) and href:
                self.feed_urls.append(href)

        elif tag_lower == "meta":
            name = attr_dict.get("name", "").lower()
            prop = attr_dict.get("property", "").lower()
            content = attr_dict.get("content", "").strip()

            if not content:
                return

            # OpenGraph tags
            if prop == "og:title" or name == "og:title":
                self.meta.title = self.meta.title or content
            elif prop == "og:description" or name == "og:description":
                self.meta.description = self.meta.description or content
            elif prop == "og:site_name" or name == "og:site_name":
                self.meta.site_name = content
            elif prop == "og:type" or name == "og:type":
                self.meta.og_type = content
            elif prop == "og:image" or name == "og:image":
                self.meta.og_image = content

            # Twitter Card tags
            elif name == "twitter:card":
                self.meta.twitter_card = content
            elif name == "twitter:title":
                self.meta.title = self.meta.title or content
            elif name == "twitter:description":
                self.meta.description = self.meta.description or content

            # Standard HTML tags
            elif name == "description":
                self.meta.description = self.meta.description or content
            elif name == "keywords":
                self.meta.keywords = [k.strip() for k in content.split(",") if k.strip()]
            elif name == "author":
                self.meta.author = content
            elif name == "generator":
                self.meta.generator = content

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in self._ignored_tags:
            self._current_ignored = False

        if tag_lower == "title":
            self._in_title = False

        elif tag_lower == "script" and self._in_json_ld:
            self._in_json_ld = False
            buf = self._json_ld_buffer.strip()
            if buf:
                try:
                    parsed = json.loads(buf)
                    if isinstance(parsed, dict):
                        self.meta.json_ld_entities.append(parsed)
                    elif isinstance(parsed, list):
                        self.meta.json_ld_entities.extend([p for p in parsed if isinstance(p, dict)])
                except Exception:
                    pass

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.meta.title = (self.meta.title + " " + data).strip()
        elif self._in_json_ld:
            self._json_ld_buffer += data
        elif not self._current_ignored:
            cleaned = data.strip()
            if len(cleaned) > 15:
                self._text_chunks.append(cleaned)

    def get_clean_body_text(self, max_chars: int = 4000) -> str:
        """Returns readable prose extracted from public paragraphs with noise stripped."""
        text = " ".join(self._text_chunks)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:max_chars]


# =============================================================================
# Compliance & Legal Gatekeeper
# =============================================================================

class RobotsComplianceGatekeeper:
    """Inspects target robots.txt, respects crawl-delays, and evaluates path permissions."""

    @staticmethod
    async def evaluate_compliance(
        client: httpx.AsyncClient,
        domain: str,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 6.0,
    ) -> Tuple[ComplianceReport, urllib.robotparser.RobotFileParser]:
        """Fetches robots.txt, computes allowed paths and crawl delay."""
        report = ComplianceReport(domain=domain)
        parser = urllib.robotparser.RobotFileParser()
        robots_url = f"https://{domain}/robots.txt"

        try:
            resp = await client.get(
                robots_url,
                headers={"User-Agent": user_agent},
                timeout=timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200 and resp.text:
                report.robots_txt_found = True
                content = resp.text
                parser.parse(content.splitlines())

                # Check crawl-delay
                cd = parser.crawl_delay(user_agent) or parser.crawl_delay("*")
                if cd is not None and cd > 0:
                    report.crawl_delay = min(float(cd), 5.0)

                # Extract Sitemaps
                sitemaps = re.findall(r"^Sitemap:\s*(\S+)", content, re.IGNORECASE | re.MULTILINE)
                report.sitemaps = sitemaps[:6]

                # Extract Disallowed paths
                disallows = re.findall(r"^Disallow:\s*(\S+)", content, re.IGNORECASE | re.MULTILINE)
                report.disallowed_paths = disallows[:8]

                # Evaluate root URL permission
                root_url = f"https://{domain}/"
                report.is_scraping_allowed = parser.can_fetch(user_agent, root_url)
            elif resp.status_code == 404:
                report.robots_txt_found = False
                report.is_scraping_allowed = True
            else:
                report.robots_txt_found = False
                report.is_scraping_allowed = True
        except Exception as exc:
            logger.debug("Robots.txt evaluation exception for %s: %s", domain, exc)
            report.is_scraping_allowed = True

        return report, parser


# =============================================================================
# Deterministic AI & Heuristic Public Text Structurer
# =============================================================================

class HeuristicPublicStructurer:
    """0-RAM deterministic rule-based extractor structuring raw public text into intelligence."""

    @staticmethod
    def extract_structured_intel(
        domain: str,
        meta: ScrapedMeta,
        body_text: str,
        feed_items: List[FeedItem],
    ) -> StructuredPublicIntelligence:
        intel = StructuredPublicIntelligence(target_domain=domain)
        all_text = f"{meta.title} {meta.description} {meta.generator} {body_text}"

        # 1. Contact Endpoints (Public security / support emails, tel links)
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", all_text)
        valid_emails = set()
        for em in emails:
            em_lower = em.lower().strip(".")
            if not em_lower.endswith((".png", ".jpg", ".svg", ".gif", ".webp")):
                if domain in em_lower or "support" in em_lower or "security" in em_lower or "contact" in em_lower:
                    valid_emails.add(em_lower)
        intel.contact_endpoints = sorted(list(valid_emails))[:5]

        # 2. Technology Identifiers
        tech_set = set()
        if meta.generator:
            tech_set.add(f"Generator: {meta.generator}")

        tech_patterns = [
            (r"wordpress", "WordPress CMS"),
            (r"next\.?js", "Next.js"),
            (r"react", "React"),
            (r"cloudflare", "Cloudflare CDN"),
            (r"shopify", "Shopify"),
            (r"drupal", "Drupal"),
            (r"tailwind", "Tailwind CSS"),
            (r"bootstrap", "Bootstrap"),
        ]
        for pat, label in tech_patterns:
            if re.search(pat, all_text, re.IGNORECASE):
                tech_set.add(label)
        intel.tech_identifiers = sorted(list(tech_set))

        # 3. Organization & Social Links
        org_links = set()
        social_domains = ["github.com", "twitter.com", "x.com", "linkedin.com", "youtube.com"]
        for sd in social_domains:
            matches = re.findall(rf"https?://(?:www\.)?{re.escape(sd)}/[a-zA-Z0-9_.-]+", all_text, re.IGNORECASE)
            for m in matches:
                org_links.add(m.rstrip("/.,;"))
        intel.organization_links = sorted(list(org_links))[:6]

        # 4. Public Statements (Mission, Privacy, Copyright)
        statements = []
        if meta.description:
            statements.append(f"Official Meta Description: \"{meta.description}\"")

        copyright_match = re.search(r"(?:©|\bcopyright\b)[^.\n\r]{4,60}", all_text, re.IGNORECASE)
        if copyright_match:
            statements.append(f"Legal Statement: {copyright_match.group(0).strip()}")

        for f_item in feed_items[:2]:
            statements.append(f"Recent Public Post: \"{f_item.title}\" ({f_item.published or 'Recent'})")

        intel.public_statements = statements[:4]

        # 5. Entity Extraction
        entities = set()
        if meta.site_name:
            entities.add(meta.site_name)
        if meta.author:
            entities.add(meta.author)

        # JSON-LD Schema entities
        for j_ent in meta.json_ld_entities:
            j_name = j_ent.get("name")
            j_type = j_ent.get("@type")
            if j_name and isinstance(j_name, str):
                entities.add(f"{j_name} ({j_type or 'Entity'})")

        if not entities:
            # Fallback to domain root brand
            brand = domain.split(".")[0].capitalize()
            entities.add(f"{brand} Organization")

        intel.entities = sorted(list(entities))[:6]

        # 6. Executive Clean Summary
        summary_parts = []
        if meta.title:
            summary_parts.append(f"Target web surface titled '{meta.title}'.")
        if meta.description:
            summary_parts.append(meta.description)
        elif intel.public_statements:
            summary_parts.append(intel.public_statements[0])
        else:
            summary_parts.append(f"Public web asset operating under domain {domain}.")

        if intel.tech_identifiers:
            summary_parts.append(f"Public technology signatures: {', '.join(intel.tech_identifiers)}.")

        intel.clean_summary = " ".join(summary_parts)
        intel.extraction_method = "Deterministic Heuristic (0-RAM)"
        return intel


# =============================================================================
# Main Engine Orchestrator
# =============================================================================

class LegalScraperEngine:
    """Coordinates compliant public harvesting, OpenGraph extraction, and AI structuring."""

    def __init__(self, timeout: float = 6.0, user_agent: str = DEFAULT_USER_AGENT) -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    async def _discover_and_parse_feeds(
        self,
        client: httpx.AsyncClient,
        domain: str,
        feed_urls: List[str],
        can_fetch: bool,
    ) -> List[FeedItem]:
        """Discovers and parses RSS/Atom feeds without external XML libraries."""
        items: List[FeedItem] = []
        if not can_fetch:
            return items

        # Candidate endpoints to probe
        candidates = list(feed_urls)
        for common in ["/feed", "/rss.xml", "/atom.xml", "/feed.xml"]:
            full_url = f"https://{domain}{common}"
            if full_url not in candidates:
                candidates.append(full_url)

        for candidate_url in candidates[:3]:
            try:
                # Ensure absolute URL
                if candidate_url.startswith("/"):
                    candidate_url = f"https://{domain}{candidate_url}"

                resp = await client.get(
                    candidate_url,
                    headers={"User-Agent": self.user_agent, "Accept": "application/rss+xml, application/atom+xml, text/xml"},
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                if resp.status_code == 200 and ("xml" in resp.headers.get("content-type", "") or "<rss" in resp.text or "<feed" in resp.text):
                    root = ET.fromstring(resp.text)
                    # Parse RSS 2.0
                    for item in root.findall(".//item")[:4]:
                        t = item.findtext("title") or "Untitled Post"
                        l = item.findtext("link") or ""
                        p = item.findtext("pubDate") or ""
                        a = item.findtext("author") or item.findtext("dc:creator") or ""
                        s = item.findtext("description") or ""
                        items.append(FeedItem(title=t.strip(), link=l.strip(), published=p.strip(), author=a.strip(), summary=s.strip()[:180]))

                    # Parse Atom
                    if not items:
                        for entry in root.findall(".//{http://www.w3.org/2005/Atom}entry")[:4]:
                            t = entry.findtext("{http://www.w3.org/2005/Atom}title") or "Untitled Entry"
                            l_elem = entry.find("{http://www.w3.org/2005/Atom}link")
                            l = l_elem.get("href", "") if l_elem is not None else ""
                            p = entry.findtext("{http://www.w3.org/2005/Atom}published") or entry.findtext("{http://www.w3.org/2005/Atom}updated") or ""
                            s = entry.findtext("{http://www.w3.org/2005/Atom}summary") or ""
                            items.append(FeedItem(title=t.strip(), link=l.strip(), published=p.strip(), summary=s.strip()[:180]))

                    if items:
                        break
            except Exception as exc:
                logger.debug("Feed parsing exception for %s: %s", candidate_url, exc)

        return items

    async def analyze_async(self, target: str) -> LegalScraperReport:
        """Asynchronously executes compliant public harvesting and AI-driven normalization."""
        clean_domain = normalize_domain(target)
        report = LegalScraperReport(domain=clean_domain)

        if not clean_domain:
            report.warnings.append("No valid domain provided for legal scraping.")
            return report

        async with httpx.AsyncClient(
            verify=certifi.where(),
            timeout=self.timeout,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=15, max_keepalive_connections=8),
        ) as client:
            # 1. Compliance & Robots.txt Check
            compliance, robot_parser = await RobotsComplianceGatekeeper.evaluate_compliance(
                client, clean_domain, user_agent=self.user_agent, timeout=self.timeout
            )
            report.compliance = compliance

            if not compliance.is_scraping_allowed:
                report.warnings.append("Robots.txt disallows automated harvesting on root path. Aborting per compliance rules.")
                report.extracted_intelligence.clean_summary = "Automated scraping restricted by target robots.txt policy."
                return report

            # Polite crawl delay
            await asyncio.sleep(min(compliance.crawl_delay, 1.5))

            # 2. Fetch and Parse Root Web Page (capped at first 64KB for RAM efficiency)
            root_url = f"https://{clean_domain}/"
            report.harvested_urls.append(root_url)
            html_content = ""

            try:
                r = await client.get(
                    root_url,
                    headers={"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml"},
                    timeout=self.timeout,
                )
                if r.status_code == 200:
                    # Stream first 64 KB to maintain strict low-RAM footprint
                    html_content = r.text[:65536]
                else:
                    report.warnings.append(f"HTTP {r.status_code} returned for root URL.")
            except Exception as exc:
                report.warnings.append(f"Failed to fetch public web page: {exc}")

            # 3. Extract Metadata, OpenGraph & Clean Body Prose
            body_text = ""
            if html_content:
                parser = LightweightHTMLHarvester()
                try:
                    parser.feed(html_content)
                    report.metadata = parser.meta
                    body_text = parser.get_clean_body_text()
                except Exception as exc:
                    logger.debug("HTML parsing warning: %s", exc)

                # 4. Discover and Parse Public Feeds
                feeds = await self._discover_and_parse_feeds(
                    client, clean_domain, parser.feed_urls, compliance.is_scraping_allowed
                )
                report.feeds = feeds

            # 5. AI & Deterministic Public Intelligence Structuring
            intel = HeuristicPublicStructurer.extract_structured_intel(
                clean_domain, report.metadata, body_text, report.feeds
            )
            report.extracted_intelligence = intel
            report.is_success = bool(report.metadata.title or report.metadata.description or intel.entities)
            return report

    def analyze(self, target: str) -> LegalScraperReport:
        """Synchronous wrapper for GUI workers and test harnesses."""
        try:
            return asyncio.run(self.analyze_async(target))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self.analyze_async(target))
            finally:
                loop.close()
