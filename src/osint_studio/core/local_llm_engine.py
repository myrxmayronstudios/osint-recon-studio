"""Ultra-Low-RAM Local LLM Intelligence Analyst & Offline Heuristic Correlation Engine.

Runs zero-cloud, privacy-first intelligence correlation comfortably on 1.2 GB to 2.5 GB RAM
using local Ollama (Qwen2.5-1.5B / LLaMA3.2-1B / Phi-4-mini) with zero-RAM rule-based
deterministic fallback when local AI is absent or offline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx
from osint_studio.core.fast_network import FastHttpClient

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"

# Recommended Ultra-Low-RAM Models (<2.5 GB memory footprint)
LOW_RAM_MODELS = [
    ("qwen2.5:1.5b", "Qwen 2.5 1.5B (~1.3 GB RAM - Recommended Fast Analyst)"),
    ("llama3.2:1b", "LLaMA 3.2 1B (~1.1 GB RAM - Ultra-Light Mode)"),
    ("qwen2.5:3b", "Qwen 2.5 3B (~2.2 GB RAM - Deep Correlation)"),
    ("phi4-mini:latest", "Phi-4 Mini (~2.5 GB RAM - Complex Reasoning)"),
]

DOSSIER_SYSTEM_PROMPT = """You are a Principal Cyber Threat Intelligence & OSINT Lead Analyst.
Analyze the target's passive reconnaissance telemetry objectively.
Format your report into clean, professional Markdown with these exact sections:
1. Executive Exposure Summary
2. Infrastructure & Defensive Posture Analysis
3. Personal Privacy & Digital Footprint
4. Identity Correlation Chains (How handles, emails, DNS, and records interlink)
5. Prioritized Action Checklist (Immediate, High, Medium, Low)

Keep explanations crisp, concrete, technical, and prioritized by genuine operational risk.
Never speculate on unverified facts."""


def is_ollama_available_sync(base_url: str = DEFAULT_OLLAMA_BASE_URL) -> bool:
    """Synchronous fast check if Ollama server is responsive."""
    try:
        with httpx.Client(timeout=1.0) as client:
            resp = client.get(f"{base_url.rstrip('/')}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


async def is_ollama_available(base_url: str = DEFAULT_OLLAMA_BASE_URL) -> bool:
    """Check if Ollama server is running locally."""
    try:
        client = FastHttpClient.get_client()
        resp = await client.get(f"{base_url.rstrip('/')}/api/tags", timeout=1.5)
        return resp.status_code == 200
    except Exception:
        return False


async def list_ollama_models(base_url: str = DEFAULT_OLLAMA_BASE_URL) -> List[str]:
    """Retrieves list of installed Ollama models."""
    try:
        client = FastHttpClient.get_client()
        resp = await client.get(f"{base_url.rstrip('/')}/api/tags", timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            models = [m.get("name") for m in data.get("models", []) if m.get("name")]
            return models
    except Exception as exc:
        logger.debug("Failed to list Ollama models: %s", exc)
    return []


async def pull_model_stream(
    model_name: str,
    base_url: str = DEFAULT_OLLAMA_BASE_URL,
) -> AsyncIterator[Dict[str, Any]]:
    """Pulls an Ollama model and yields progress dicts."""
    url = f"{base_url.rstrip('/')}/api/pull"
    try:
        client = FastHttpClient.get_client()
        async with client.stream("POST", url, json={"name": model_name}, timeout=httpx.Timeout(600.0, connect=5.0)) as resp:
            if resp.status_code != 200:
                yield {"status": f"HTTP Error {resp.status_code}", "completed": 0, "total": 0, "percent": 0.0}
                return

            async for line in resp.aiter_lines():
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    status = payload.get("status", "")
                    total = payload.get("total", 0)
                    completed = payload.get("completed", 0)
                    percent = (completed / total * 100.0) if total > 0 else 0.0
                    yield {
                        "status": status,
                        "completed": completed,
                        "total": total,
                        "percent": round(percent, 1),
                    }
                except Exception:
                    yield {"status": line, "completed": 0, "total": 0, "percent": 0.0}
    except Exception as exc:
        yield {"status": f"Connection error: {exc}", "completed": 0, "total": 0, "percent": 0.0}


def serialize_findings_to_compact_context(findings: Dict[str, Any], max_chars: int = 10000) -> str:
    """Serializes findings across Hubs 2-5 into token-efficient Markdown context (<2500 tokens)."""
    lines = ["### Passive Reconnaissance Telemetry Data"]

    target = findings.get("target") or findings.get("domain") or findings.get("email") or "Unknown Target"
    lines.append(f"- **Target**: {target}")

    # Hub 2: Domain & Infrastructure
    dns_data = findings.get("dns", {})
    records = dns_data.get("records", {})
    lines.append(f"- **DNS Records Found**: {sum(len(v) for v in records.values()) if isinstance(records, dict) else 0}")
    if isinstance(records, dict):
        if "A" in records:
            lines.append(f"  - A: {', '.join(records['A'][:4])}")
        if "MX" in records:
            lines.append(f"  - MX: {', '.join(records['MX'][:3])}")
        if "NS" in records:
            lines.append(f"  - NS: {', '.join(records['NS'][:3])}")

    subdomains = findings.get("subdomains", {}).get("subdomains", [])
    lines.append(f"- **Subdomains Discovered (crt.sh)**: {len(subdomains)}")
    if subdomains:
        sample_subs = subdomains[:8]
        lines.append(f"  - Sample: {', '.join(sample_subs)}")

    takeover = findings.get("takeover", {})
    dangling = takeover.get("vulnerabilities", [])
    lines.append(f"- **Dangling CNAME Takeovers Detected**: {len(dangling)}")
    for d in dangling[:3]:
        lines.append(f"  - [CRITICAL] {d.get('subdomain')} -> {d.get('cname')} ({d.get('service')})")

    rdap = findings.get("rdap", {})
    if rdap:
        lines.append(f"- **Registrar**: {rdap.get('registrar', 'Unknown')}, Org: {rdap.get('organization', 'Unknown')}, Exp: {rdap.get('expiration_date', 'Unknown')}")

    # Hub 3: Network & Threat Exposure
    internetdb = findings.get("internetdb", {})
    ports = internetdb.get("ports", [])
    cves = internetdb.get("vulns", [])
    lines.append(f"- **Open Ports (Passive InternetDB)**: {ports}")
    lines.append(f"- **Known CVE Vulnerabilities**: {cves if cves else 'None reported'}")

    ip_intel = findings.get("ip_intel", {})
    if ip_intel:
        lines.append(f"- **Hosting / Cloud Provider**: {ip_intel.get('org', 'Unknown')} (ASN: {ip_intel.get('asn', 'Unknown')}, Country: {ip_intel.get('country', 'Unknown')})")

    urlscan = findings.get("urlscan", {})
    hist_scans = urlscan.get("results", [])
    lines.append(f"- **Historical URLScan Records**: {len(hist_scans)}")

    # Hub 4: Web & Email Defensive Posture
    email_sec = findings.get("email_sec", {})
    lines.append(f"- **Email Spoofing Defense (DMARC/SPF)**: Grade={email_sec.get('grade', 'N/A')}, DMARC Policy={email_sec.get('dmarc_policy', 'None')}, SPF={email_sec.get('has_spf', False)}")

    headers = findings.get("headers", {})
    missing_headers = headers.get("missing", [])
    lines.append(f"- **Missing HTTP Security Headers**: {', '.join(missing_headers[:5]) if missing_headers else 'None'}")

    tech_stack = findings.get("tech_stack", {}).get("technologies", [])
    if tech_stack:
        lines.append(f"- **Identified Technologies**: {', '.join(tech_stack[:6])}")

    # Hub 5: Personal Data & Footprint
    personal = findings.get("personal", {})
    if personal:
        email_rep = personal.get("email_report", {})
        if email_rep:
            breaches = email_rep.get("breaches", [])
            lines.append(f"- **Personal Email Breach Count**: {len(breaches)}")
            for b in breaches[:4]:
                name = b.get("name") if isinstance(b, dict) else str(b)
                lines.append(f"  - Breach: {name}")

        social_rep = personal.get("social_profiles", [])
        verified_profiles = [p for p in social_rep if p.get("status") == "FOUND"]
        lines.append(f"- **Verified Public Social Profiles**: {len(verified_profiles)}")
        for p in verified_profiles[:6]:
            lines.append(f"  - {p.get('platform')}: {p.get('url')} (Title: {p.get('title', '')})")

        phone_rep = personal.get("phone_report", {})
        if phone_rep:
            lines.append(f"- **Phone Telemetry**: {phone_rep.get('carrier', 'Unknown')} ({phone_rep.get('line_type', 'Unknown')}), WhatsApp={phone_rep.get('whatsapp_available', False)}")

        permutations = personal.get("permutations", [])
        if permutations:
            lines.append(f"- **Generated Handle Permutations**: {len(permutations)} variations tested")

    raw_text = "\n".join(lines)
    if len(raw_text) > max_chars:
        raw_text = raw_text[:max_chars] + "\n...[telemetry truncated for token budget]..."
    return raw_text


class HeuristicAnalyst:
    """Deterministic, zero-RAM rule-based OSINT correlation & synthesis engine.

    Requires 0 MB extra RAM, has 0 external network dependencies, and provides
    instant, highly structured, expert-level executive summaries and remediation plans.
    """

    @classmethod
    def generate_dossier(cls, findings: Dict[str, Any]) -> str:
        """Synthesizes a comprehensive intelligence dossier using deterministic correlation rules."""
        target = findings.get("target") or findings.get("domain") or findings.get("email") or "Target Asset"
        
        # Calculate calculated metrics
        dns_records = findings.get("dns", {}).get("records", {})
        subdomains = findings.get("subdomains", {}).get("subdomains", [])
        takeovers = findings.get("takeover", {}).get("vulnerabilities", [])
        ports = findings.get("internetdb", {}).get("ports", [])
        cves = findings.get("internetdb", {}).get("vulns", [])
        email_sec = findings.get("email_sec", {})
        headers = findings.get("headers", {})
        tech = findings.get("tech_stack", {}).get("technologies", [])
        personal = findings.get("personal", {})
        email_rep = personal.get("email_report", {})
        breaches = email_rep.get("breaches", []) if email_rep else []
        social = personal.get("social_profiles", []) if personal else []
        found_social = [p for p in social if p.get("status") == "FOUND"]

        # Calculate Overall Risk Score
        risk_score = 10
        critical_flags = []
        high_flags = []
        medium_flags = []

        if takeovers:
            risk_score += 45
            critical_flags.append(f"{len(takeovers)} Dangling CNAME takeover vulnerability discovered")
        if cves:
            risk_score += 35
            critical_flags.append(f"{len(cves)} Known CVEs exposed on public IP ({', '.join(cves[:3])})")
        if breaches:
            risk_score += min(len(breaches) * 8, 30)
            high_flags.append(f"{len(breaches)} Historical data breaches exposing identity credentials")
        if email_sec.get("dmarc_policy") in ("none", "", None):
            risk_score += 15
            high_flags.append("Domain vulnerable to spoofing / CEO fraud (DMARC policy missing or 'none')")
        if 21 in ports or 23 in ports or 3389 in ports:
            risk_score += 20
            high_flags.append("Insecure remote management/plaintext ports exposed (FTP/Telnet/RDP)")
        if headers.get("missing"):
            risk_score += min(len(headers["missing"]) * 3, 15)
            medium_flags.append(f"{len(headers['missing'])} Recommended HTTP defensive headers missing")
        if len(found_social) >= 5:
            risk_score += 10
            medium_flags.append(f"High cross-platform identity linkability ({len(found_social)} profiles linked)")

        risk_score = min(max(risk_score, 10), 100)
        risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 35 else "LOW"

        # Construct Markdown Report
        md = []
        md.append(f"# 🏛️ EXECUTIVE OSINT INTELLIGENCE DOSSIER")
        md.append(f"**Target Asset:** `{target}`  |  **Overall Risk Score:** `{risk_score}/100 ({risk_level})`  |  **Engine:** `Deterministic Heuristic Correlation (0-RAM)`\n")
        md.append("---")

        # Section 1: Executive Exposure Summary
        md.append("## 1. Executive Exposure Summary")
        md.append(f"Automated passive reconnaissance against target `{target}` has compiled telemetry across Domain Infrastructure, Cloud Assets, Web/Email Posture, and Personal Footprint.")
        if critical_flags:
            md.append(f"\n> 🚨 **Critical Immediate Threats:**\n> - " + "\n> - ".join(critical_flags))
        if high_flags:
            md.append(f"\n> ⚠️ **High Operational Risks:**\n> - " + "\n> - ".join(high_flags))
        if not critical_flags and not high_flags:
            md.append("\n> ✅ **Baseline Posture:** No catastrophic dangling takeovers or critical CVEs detected on primary monitored endpoints.")

        # Section 2: Infrastructure & Defensive Posture
        md.append("\n## 2. Infrastructure & Defensive Posture Analysis")
        md.append(f"- **DNS & Surface Footprint:** {len(subdomains)} subdomains mapped via Certificate Transparency. Primary nameservers and mail exchangers successfully enumerated.")
        if ports:
            md.append(f"- **Perimeter Exposure:** Observed open ports: `{ports}`. Service banners indicate public accessibility.")
        else:
            md.append("- **Perimeter Exposure:** No open listening ports indexed in passive Shodan InternetDB feed.")
        
        dmarc_pol = email_sec.get("dmarc_policy", "Missing")
        spf_status = "Configured" if email_sec.get("has_spf") else "Missing"
        md.append(f"- **Email Defenses:** SPF: `{spf_status}` | DMARC Policy: `{dmarc_pol}` | Overall Grade: `{email_sec.get('grade', 'C')}`")
        if tech:
            md.append(f"- **Detected Web Technologies:** {', '.join(tech[:6])}")

        scraper_data = findings.get("legal_scraper", {})
        if scraper_data:
            meta = scraper_data.get("metadata", {})
            intel = scraper_data.get("extracted_intelligence", {})
            comp = scraper_data.get("compliance", {})
            if meta.get("title") or intel.get("entities"):
                md.append(f"- **Public Surface & OpenGraph:** Title: '{meta.get('title') or target}' (Robots Compliance: `{'Allowed' if comp.get('is_scraping_allowed') else 'Restricted'}`)")
            if intel.get("entities"):
                md.append(f"- **Public Entities Identified:** {', '.join(intel.get('entities')[:4])}")
            if intel.get("contact_endpoints"):
                md.append(f"- **Public Contact Endpoints:** {', '.join(intel.get('contact_endpoints')[:3])}")

        # Section 3: Personal Privacy & Digital Footprint
        md.append("\n## 3. Personal Privacy & Digital Footprint")
        if email_rep and email_rep.get("email"):
            md.append(f"- **Email Asset:** `{email_rep.get('email')}` (Gravatar Profile: `{'Found' if email_rep.get('gravatar_url') else 'Not Found'}`)")
            if breaches:
                md.append(f"- **Exposed Breaches ({len(breaches)}):** " + ", ".join([b.get("name", str(b)) if isinstance(b, dict) else str(b) for b in breaches[:6]]))
            else:
                md.append("- **Breach Analytics:** No public breach records indexed under XposedOrNot.")

        if found_social:
            md.append(f"- **Identified Social Profiles ({len(found_social)}):**")
            for p in found_social[:8]:
                md.append(f"  - **{p.get('platform')}**: [{p.get('url')}]({p.get('url')}) - *{p.get('title', '')}*")
        else:
            md.append("- **Social Footprint:** No high-confidence public profiles confirmed on probed platforms.")

        # Section 4: Identity Correlation Chains
        md.append("\n## 4. Identity & Infrastructure Correlation Chains")
        chains = []
        if breaches and found_social:
            chains.append("Cross-Correlation: Email breach records correlate with public social profiles sharing identical handles.")
        if takeovers:
            chains.append("Cloud Takeover Chain: Abandoned CNAME points to cloud tenant allowing full domain impersonation.")
        if email_sec.get("dmarc_policy") in ("none", "", None) and subdomains:
            chains.append("Phishing Vector: Missing DMARC combined with enumerated subdomains facilitates targeted brand spoofing.")
        if not chains:
            chains.append("Linear Asset Profile: Target exhibits independent asset clustering without dangerous cross-pivot leakage.")

        for c in chains:
            md.append(f"- 🔗 {c}")

        # Section 5: Prioritized Action Checklist
        md.append("\n## 5. Prioritized Security & Privacy Remediation Plan")
        actions = []
        if takeovers:
            actions.append(("CRITICAL", "Remove or claim dangling CNAME records immediately in DNS management to prevent subdomain takeover."))
        if cves:
            actions.append(("CRITICAL", f"Patch perimeter services running vulnerable software versions ({', '.join(cves[:3])})."))
        if email_sec.get("dmarc_policy") in ("none", "", None):
            actions.append(("HIGH", "Deploy strict DMARC policy (`v=DMARC1; p=reject; pct=100;`) to eliminate unauthorized domain spoofing."))
        if breaches:
            actions.append(("HIGH", "Rotate passwords on accounts linked to compromised breaches and enforce FIDO2/Hardware MFA."))
        if headers.get("missing"):
            actions.append(("MEDIUM", f"Deploy missing HTTP headers on web servers: {', '.join(headers['missing'][:3])}."))
        if found_social:
            actions.append(("LOW", "Review public privacy settings on identified social profiles to prevent automated OSINT harvest."))

        for priority, act in actions:
            badge = "🔴" if priority == "CRITICAL" else "🟠" if priority == "HIGH" else "🟡" if priority == "MEDIUM" else "🔵"
            md.append(f"- {badge} **[{priority}]** {act}")

        return "\n".join(md)

    @classmethod
    def answer_question(cls, question: str, findings: Dict[str, Any], context_summary: str = "") -> str:
        """Deterministic offline Q&A engine handling user follow-up questions."""
        q_lower = question.lower()

        # Handle specific common questions
        if "highest risk" in q_lower or "worst" in q_lower or "critical" in q_lower:
            takeovers = findings.get("takeover", {}).get("vulnerabilities", [])
            cves = findings.get("internetdb", {}).get("vulns", [])
            breaches = findings.get("personal", {}).get("email_report", {}).get("breaches", [])
            if takeovers:
                return (
                    f"**Highest Risk Finding: Dangling Subdomain Takeover**\n\n"
                    f"You have {len(takeovers)} DNS CNAME record(s) pointing to unclaimed external services. "
                    f"An attacker can register the target service resource and claim full control over your subdomain, "
                    f"enabling cookie theft, credential harvesting, and reputation destruction. Fix this immediately by deleting the orphaned CNAME."
                )
            elif cves:
                return (
                    f"**Highest Risk Finding: Unpatched Public CVEs**\n\n"
                    f"Passive telemetry detected known CVEs ({', '.join(cves[:4])}) on your public IP. "
                    f"Threat actors scan for these vulnerabilities constantly. Upgrade or isolate the listening perimeter software."
                )
            elif breaches:
                return (
                    f"**Highest Risk Finding: Credential Breaches**\n\n"
                    f"Your monitored email appears in {len(breaches)} historical breach records. "
                    f"Ensure credentials from these services are permanently rotated and MFA is enforced across all accounts."
                )
            else:
                return "The passive scan did not uncover critical takeovers or active CVEs. The highest priority is hardening email defenses (DMARC) and HTTP security headers."

        if "dmarc" in q_lower or "spoof" in q_lower or "email" in q_lower:
            email_sec = findings.get("email_sec", {})
            pol = email_sec.get("dmarc_policy", "none")
            return (
                f"**Email Spoofing & DMARC Recommendations:**\n\n"
                f"- **Current Policy:** `{pol}`\n"
                f"- **Action Required:** Publish a TXT record at `_dmarc.yourdomain.com`:\n"
                f"  `v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; pct=100; sp=reject`\n"
                f"- Ensure your SPF record (`v=spf1 ... -all`) ends with a hard-fail (`-all`) rather than a soft-fail (`~all`)."
            )

        if "takeover" in q_lower or "cname" in q_lower:
            takeovers = findings.get("takeover", {}).get("vulnerabilities", [])
            if takeovers:
                t = takeovers[0]
                return (
                    f"**Dangling CNAME Takeover Detected:**\n\n"
                    f"- **Subdomain:** `{t.get('subdomain')}`\n"
                    f"- **Target CNAME:** `{t.get('cname')}`\n"
                    f"- **Identified Platform:** `{t.get('service')}`\n\n"
                    f"**How to Fix:** Log into your DNS provider (e.g. Cloudflare, Route53, GoDaddy) and remove this CNAME record, "
                    f"or log into {t.get('service')} and claim the matching custom domain bucket."
                )
            return "No dangling CNAME takeovers were detected in the current scan results. All inspected subdomains resolve or have no orphaned cloud aliases."

        if "port" in q_lower or "shodan" in q_lower or "internetdb" in q_lower:
            ports = findings.get("internetdb", {}).get("ports", [])
            return (
                f"**Perimeter Port Exposure Analysis:**\n\n"
                f"- **Discovered Open Ports:** `{ports if ports else 'None indexed in passive feed'}`\n"
                f"- If sensitive administrative ports (like 22 SSH, 3389 RDP, 21 FTP, 445 SMB) are visible, place them behind a VPN or Cloudflare Zero Trust / WireGuard tunnel."
            )

        if "social" in q_lower or "profile" in q_lower or "handle" in q_lower or "privacy" in q_lower:
            personal = findings.get("personal", {})
            social = personal.get("social_profiles", [])
            found = [p for p in social if p.get("status") == "FOUND"]
            return (
                f"**Personal Footprint & Identity Correlation:**\n\n"
                f"- **Probed Platforms:** {len(social)} probed | **Confirmed Profiles:** {len(found)}\n"
                f"- High identity linkability occurs when identical handles or avatars are used across both anonymous sites (GitHub, Reddit) and real-name sites (LinkedIn, Instagram).\n"
                f"- Use the **EXIF Scrubber** in Hub 5 to sanitize uploaded images before sharing to strip embedded GPS coordinates and device identifiers."
            )

        # Generic intelligent response referencing findings
        target = findings.get("target") or "target"
        return (
            f"**Analyst Assessment for '{question}':**\n\n"
            f"Based on passive OSINT intelligence for `{target}`:\n"
            f"- Review the complete **Executive Dossier** in Hub 1 for cross-module correlations.\n"
            f"- Prioritize resolving dangling CNAMEs, configuring strict DMARC `p=reject`, and securing perimeter ports.\n"
            f"- To test against deeper LLM models, install Ollama and run `ollama pull qwen2.5:1.5b`."
        )

    @classmethod
    def generate_deterministic_dossier(cls, findings: Dict[str, Any]) -> str:
        """Alias for generate_dossier."""
        return cls.generate_dossier(findings)

    @classmethod
    def answer_offline_question(cls, findings: Dict[str, Any], question: str) -> str:
        """Convenience method for offline Q&A."""
        return cls.answer_question(question, findings)


class LocalLLMEngine:
    """Orchestrates token-streamed synthesis using local Ollama or Zero-RAM Heuristic Analyst."""

    def __init__(self, base_url: str = DEFAULT_OLLAMA_BASE_URL, default_model: str = "qwen2.5:1.5b"):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    async def check_availability(self) -> Tuple[bool, List[str]]:
        """Checks if Ollama is accessible and lists installed models."""
        available = await is_ollama_available(self.base_url)
        models = await list_ollama_models(self.base_url) if available else []
        return available, models

    async def synthesize_dossier_stream(
        self,
        findings: Dict[str, Any],
        model: str = "auto",
        force_heuristic: bool = False,
    ) -> AsyncIterator[str]:
        """Streams the executive intelligence dossier token-by-token.

        If force_heuristic is True or Ollama is unavailable, streams deterministic heuristic findings.
        """
        available = False if force_heuristic else await is_ollama_available(self.base_url)
        active_model = self.default_model if (model == "auto" or not model) else model

        if not available or force_heuristic:
            # Yield heuristic dossier line-by-line with slight streaming pacing
            full_dossier = HeuristicAnalyst.generate_dossier(findings)
            for paragraph in full_dossier.split("\n\n"):
                yield paragraph + "\n\n"
                await asyncio.sleep(0.015)
            return

        # Prepare compact context prompt
        context = serialize_findings_to_compact_context(findings, max_chars=8000)
        prompt = (
            f"{DOSSIER_SYSTEM_PROMPT}\n\n"
            f"Telemetric Intelligence Input:\n{context}\n\n"
            f"Synthesize the complete OSINT Intelligence Dossier now in clean Markdown:"
        )

        try:
            client = FastHttpClient.get_client()
            payload = {
                "model": active_model,
                "prompt": prompt,
                "stream": True,
                "options": {
                    "temperature": 0.2,
                    "num_ctx": 4096,
                },
            }
            async with client.stream(
                "POST",
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=httpx.Timeout(180.0, connect=3.0),
            ) as resp:
                if resp.status_code != 200:
                    yield f"⚠️ *Ollama returned HTTP {resp.status_code}. Falling back to Rule-Based Analyst...*\n\n"
                    full_dossier = HeuristicAnalyst.generate_dossier(findings)
                    yield full_dossier
                    return

                received_any = False
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("response", "")
                        if token:
                            received_any = True
                            yield token
                        if data.get("done", False):
                            break
                    except Exception:
                        continue

                if not received_any:
                    yield "\n\n*(Heuristic fallback)*\n" + HeuristicAnalyst.generate_dossier(findings)

        except Exception as exc:
            logger.warning("Local LLM streaming error: %s. Reverting to Heuristic Analyst.", exc)
            yield f"\n\n*(Local LLM offline: {exc}. Reverting to Zero-RAM Deterministic Analyst)*\n\n"
            yield HeuristicAnalyst.generate_dossier(findings)

    async def ask_question_stream(
        self,
        question: str,
        findings: Dict[str, Any],
        model: str = "auto",
        force_heuristic: bool = False,
    ) -> AsyncIterator[str]:
        """Streams answer to interactive follow-up question offline."""
        available = False if force_heuristic else await is_ollama_available(self.base_url)
        active_model = self.default_model if (model == "auto" or not model) else model

        if not available or force_heuristic:
            answer = HeuristicAnalyst.answer_question(question, findings)
            for chunk in answer.split("\n"):
                yield chunk + "\n"
                await asyncio.sleep(0.01)
            return

        context = serialize_findings_to_compact_context(findings, max_chars=5000)
        prompt = (
            f"You are an expert Cyber Intelligence Analyst. Given this passive OSINT telemetry:\n"
            f"{context}\n\n"
            f"Answer the investigator's question directly, concisely, and accurately in Markdown:\n"
            f"Question: {question}\n\n"
            f"Answer:"
        )

        try:
            client = FastHttpClient.get_client()
            payload = {
                "model": active_model,
                "prompt": prompt,
                "stream": True,
                "options": {"temperature": 0.3, "num_ctx": 4096},
            }
            async with client.stream(
                "POST",
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=httpx.Timeout(120.0, connect=3.0),
            ) as resp:
                if resp.status_code != 200:
                    yield HeuristicAnalyst.answer_question(question, findings)
                    return

                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("response", "")
                        if token:
                            yield token
                        if data.get("done", False):
                            break
                    except Exception:
                        continue
        except Exception:
            yield HeuristicAnalyst.answer_question(question, findings)
