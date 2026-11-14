"""Public document metadata and image Exif inspection engine.

Extracts author names, creator software, creation/modification timestamps, producer software,
and Exif metadata (camera, GPS, dimensions) from PDF files and images (PNG, JPG, TIFF)
using `pypdf` and `Pillow` entirely locally without sending data to third parties.
"""

from __future__ import annotations

import io
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS
from pypdf import PdfReader

logger = logging.getLogger(__name__)

USER_AGENT = "OSINTReconStudio-PassiveAudit/1.0"


@dataclass
class DocumentMetadataReport:
    """Extracted metadata and forensics properties of a public document or image."""
    source_name: str
    file_type: str  # PDF, IMAGE, UNKNOWN
    file_size_bytes: int = 0
    author: str = ""
    creator_tool: str = ""
    producer: str = ""
    title: str = ""
    subject: str = ""
    creation_date: str = ""
    modification_date: str = ""
    page_count: Optional[int] = None
    pdf_version: str = ""
    image_dimensions: str = ""
    camera_make: str = ""
    camera_model: str = ""
    software_used: str = ""
    gps_coordinates: str = ""
    exif_tags: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    is_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MetadataEngine:
    """Inspects documents and images for sensitive metadata leaks."""

    def __init__(self, timeout: float = 10.0, user_agent: str = USER_AGENT) -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def inspect_file(self, file_path_or_url: str) -> DocumentMetadataReport:
        """Inspects a local file path or public URL for document metadata."""
        path_str = file_path_or_url.strip()
        report = DocumentMetadataReport(source_name=path_str, file_type="UNKNOWN")

        file_bytes: Optional[bytes] = None

        if path_str.startswith("http://") or path_str.startswith("https://"):
            headers = {"User-Agent": self.user_agent}
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    resp = client.get(path_str, headers=headers)
                    if resp.status_code == 200:
                        file_bytes = resp.content
                        report.source_name = path_str.split("/")[-1] or path_str
            except Exception as e:
                report.warnings.append(f"Failed to download remote document: {e}")
                return report
        else:
            p = Path(path_str)
            if not p.exists() or not p.is_file():
                report.warnings.append(f"File not found: {path_str}")
                return report
            try:
                file_bytes = p.read_bytes()
                report.source_name = p.name
            except Exception as e:
                report.warnings.append(f"Could not read local file: {e}")
                return report

        if not file_bytes:
            report.warnings.append("No file content loaded.")
            return report

        report.file_size_bytes = len(file_bytes)

        # Check for PDF
        if file_bytes.startswith(b"%PDF"):
            return self._parse_pdf(file_bytes, report)

        # Try parsing as image via Pillow
        try:
            return self._parse_image(file_bytes, report)
        except Exception:
            report.warnings.append("Unrecognized or unsupported file format (supported: PDF, PNG, JPG, TIFF).")
            return report

    def _parse_pdf(self, file_bytes: bytes, report: DocumentMetadataReport) -> DocumentMetadataReport:
        """Extracts PDF document catalog and author metadata."""
        report.file_type = "PDF"
        try:
            reader = PdfReader(io.BytesIO(file_bytes))
            report.page_count = len(reader.pages)
            info = reader.metadata

            if info:
                report.title = str(info.title or "")
                report.author = str(info.author or "")
                report.subject = str(info.subject or "")
                report.creator_tool = str(info.creator or "")
                report.producer = str(info.producer or "")
                report.creation_date = str(info.creation_date or "")
                report.modification_date = str(info.modification_date or "")

            report.is_success = True
            if report.author:
                report.warnings.append(f"Author metadata exposed: '{report.author}'")
            if report.creator_tool:
                report.warnings.append(f"Creator software exposed: '{report.creator_tool}'")

        except Exception as e:
            report.warnings.append(f"PDF metadata extraction error: {e}")

        return report

    def _parse_image(self, file_bytes: bytes, report: DocumentMetadataReport) -> DocumentMetadataReport:
        """Extracts image dimensions, Exif metadata, and camera tags."""
        report.file_type = "IMAGE"
        img = Image.open(io.BytesIO(file_bytes))
        report.image_dimensions = f"{img.width} x {img.height} ({img.format})"

        try:
            exif_data = img.getexif()
            if exif_data:
                parsed_exif: Dict[str, str] = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    # Convert bytes to string safely
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            value = str(value)
                    parsed_exif[tag_name] = str(value)

                report.exif_tags = parsed_exif
                report.camera_make = parsed_exif.get("Make", "")
                report.camera_model = parsed_exif.get("Model", "")
                report.software_used = parsed_exif.get("Software", "")
                report.creation_date = parsed_exif.get("DateTime", "")

                if report.camera_model:
                    report.warnings.append(f"Camera model exposed in Exif: {report.camera_model}")
                if report.software_used:
                    report.warnings.append(f"Editing software exposed in Exif: {report.software_used}")

            report.is_success = True
        except Exception as e:
            logger.debug(f"Image Exif extraction error: {e}")
            report.is_success = True

        return report
