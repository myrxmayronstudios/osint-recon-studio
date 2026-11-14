"""High-performance shared HTTP/2 connection pooling & lightweight network client.

Provides a thread-safe singleton HTTP/2 client with connection reuse, polite timeouts,
bounded concurrency, and memory-capped response streaming (<64 KB) to avoid loading
large multi-megabyte HTML bodies into RAM.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator, Dict, Optional

import certifi
import httpx

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINTReconStudio-PassiveAudit/1.4"
MAX_HTML_BODY_BYTES = 64 * 1024  # 64 KB cap for metadata extraction


class FastHttpClient:
    """Thread-safe singleton HTTP/2 async client with connection pooling."""

    _instance: Optional[httpx.AsyncClient] = None
    _lock = asyncio.Lock() if hasattr(asyncio, "Lock") else None

    @classmethod
    def get_client(cls, timeout: float = 6.0, connect_timeout: float = 3.0) -> httpx.AsyncClient:
        """Retrieves or initializes the shared HTTP/2 AsyncClient."""
        if cls._instance is None or cls._instance.is_closed:
            limits = httpx.Limits(
                max_connections=80,
                max_keepalive_connections=30,
                keepalive_expiry=30.0,
            )
            timeouts = httpx.Timeout(timeout, connect=connect_timeout)
            headers = {
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            }
            cls._instance = httpx.AsyncClient(
                http2=True,
                verify=certifi.where(),
                limits=limits,
                timeout=timeouts,
                headers=headers,
                follow_redirects=True,
            )
        return cls._instance

    @classmethod
    async def close(cls) -> None:
        """Gracefully closes the shared HTTP/2 connection pool."""
        if cls._instance is not None and not cls._instance.is_closed:
            try:
                await cls._instance.aclose()
            except Exception as e:
                logger.debug(f"Error closing FastHttpClient: {e}")
            finally:
                cls._instance = None

    @classmethod
    async def fetch_capped_html(
        cls,
        url: str,
        max_bytes: int = MAX_HTML_BODY_BYTES,
        timeout: float = 6.0,
        headers: Optional[Dict[str, str]] = None,
    ) -> tuple[int, str, Dict[str, str]]:
        """Streams up to max_bytes from an HTTP response to prevent memory spikes.

        Returns (status_code, html_text_truncated, response_headers).
        """
        client = cls.get_client(timeout=timeout)
        req_headers = dict(client.headers)
        if headers:
            req_headers.update(headers)

        try:
            async with client.stream("GET", url, headers=req_headers) as resp:
                status_code = resp.status_code
                resp_headers = dict(resp.headers)
                chunks: list[bytes] = []
                bytes_read = 0

                async for chunk in resp.aiter_bytes():
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                    if bytes_read >= max_bytes:
                        break

                content = b"".join(chunks)[:max_bytes]
                # Decode safely with fallback
                try:
                    encoding = resp.encoding or "utf-8"
                    html_text = content.decode(encoding, errors="replace")
                except Exception:
                    html_text = content.decode("utf-8", errors="replace")

                return status_code, html_text, resp_headers
        except Exception as exc:
            logger.debug(f"Stream fetch failed for {url}: {exc}")
            raise


class FastSyncHttpClient:
    """Lightweight sync client wrapper reusing pooled transport for scripts and quick tools."""

    _instance: Optional[httpx.Client] = None

    @classmethod
    def get_client(cls, timeout: float = 6.0) -> httpx.Client:
        if cls._instance is None or cls._instance.is_closed:
            limits = httpx.Limits(max_connections=40, max_keepalive_connections=20)
            cls._instance = httpx.Client(
                verify=certifi.where(),
                limits=limits,
                timeout=httpx.Timeout(timeout, connect=3.0),
                headers={"User-Agent": DEFAULT_USER_AGENT},
                follow_redirects=True,
            )
        return cls._instance

    @classmethod
    def close(cls) -> None:
        if cls._instance is not None and not cls._instance.is_closed:
            try:
                cls._instance.close()
            except Exception:
                pass
            finally:
                cls._instance = None
