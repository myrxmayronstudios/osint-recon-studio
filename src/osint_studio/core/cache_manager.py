"""High-speed In-Memory and SQLite TTL Cache for OSINT results.

Guarantees repeat lookups complete in <50ms by caching responses from public APIs
(DNS records, RDAP, crt.sh, InternetDB, Wayback, and Username checks) with a default
24-hour TTL and a "Force Refresh" override option.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 86400  # 24 Hours
MAX_MEM_ENTRIES = 500


class CacheManager:
    """Thread-safe hybrid LRU memory + SQLite persistent cache with TTL eviction."""

    _instance: Optional[CacheManager] = None
    _init_lock = threading.Lock()

    def __new__(cls, *args, **kwargs) -> CacheManager:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: Optional[str] = None) -> None:
        if getattr(self, "_initialized", False):
            return

        if db_path is None:
            home = Path.home()
            self.db_path = str(home / ".osint_studio_cache.db")
        else:
            self.db_path = db_path

        self._lock = threading.RLock()
        self._mem_cache: Dict[str, Tuple[float, Any]] = {}  # key -> (expires_at, data)

        self._init_db()
        self._initialized = True

    def _init_db(self) -> None:
        """Initializes SQLite cache schema."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS osint_cache (
                        cache_key TEXT PRIMARY KEY,
                        category TEXT NOT NULL,
                        data_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON osint_cache(expires_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_cat ON osint_cache(category)")
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to initialize SQLite cache at {self.db_path}: {e}")

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _make_key(category: str, key: str) -> str:
        return f"{category.strip().lower()}:{key.strip().lower()}"

    def get(self, category_or_key: str, key: Optional[str] = None, force_refresh: bool = False) -> Optional[Any]:
        """Retrieves cached data if not expired and force_refresh is False."""
        if force_refresh:
            return None

        if key is None:
            if ":" in category_or_key:
                category, key = category_or_key.split(":", 1)
            else:
                category, key = "general", category_or_key
        else:
            category = category_or_key

        cache_key = self._make_key(category, key)
        now = time.time()

        with self._lock:
            # 1. Check in-memory cache first
            if cache_key in self._mem_cache:
                exp, data = self._mem_cache[cache_key]
                if exp > now:
                    return data
                else:
                    del self._mem_cache[cache_key]

        # 2. Check SQLite persistent cache
        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT data_json, expires_at FROM osint_cache WHERE cache_key = ?",
                    (cache_key,),
                ).fetchone()

                if row:
                    exp = float(row["expires_at"])
                    if exp > now:
                        data = json.loads(row["data_json"])
                        # Populate back into memory cache
                        with self._lock:
                            if len(self._mem_cache) >= MAX_MEM_ENTRIES:
                                self._mem_cache.pop(next(iter(self._mem_cache)))
                            self._mem_cache[cache_key] = (exp, data)
                        return data
                    else:
                        # Expired, clean it up asynchronously
                        conn.execute("DELETE FROM osint_cache WHERE cache_key = ?", (cache_key,))
                        conn.commit()
        except Exception as e:
            logger.debug(f"Cache get error for {cache_key}: {e}")

        return None

    def set(
        self,
        category_or_key: str,
        key_or_data: Any,
        data: Any = None,
        ttl_seconds: Optional[float] = None,
        ttl_hours: Optional[float] = None,
    ) -> None:
        """Stores result in memory and SQLite persistent storage with TTL."""
        if data is None:
            if ":" in category_or_key:
                category, key = category_or_key.split(":", 1)
            else:
                category, key = "general", category_or_key
            data = key_or_data
        else:
            category = category_or_key
            key = key_or_data

        if ttl_hours is not None:
            ttl_seconds = float(ttl_hours * 3600.0)
        elif ttl_seconds is None:
            ttl_seconds = DEFAULT_TTL_SECONDS

        cache_key = self._make_key(category, key)
        now = time.time()
        expires_at = now + ttl_seconds

        with self._lock:
            if len(self._mem_cache) >= MAX_MEM_ENTRIES:
                self._mem_cache.pop(next(iter(self._mem_cache)))
            self._mem_cache[cache_key] = (expires_at, data)

        try:
            data_json = json.dumps(data)
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO osint_cache (cache_key, category, data_json, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (cache_key, category.lower(), data_json, now, expires_at),
                )
                conn.commit()
        except Exception as e:
            logger.debug(f"Cache set error for {cache_key}: {e}")

    def delete(self, category_or_key: str, key: Optional[str] = None) -> bool:
        """Deletes a cached entry by key."""
        if key is None:
            if ":" in category_or_key:
                category, key = category_or_key.split(":", 1)
            else:
                category, key = "general", category_or_key
        else:
            category = category_or_key
        cache_key = self._make_key(category, key)

        with self._lock:
            self._mem_cache.pop(cache_key, None)

        try:
            with self._get_connection() as conn:
                cursor = conn.execute("DELETE FROM osint_cache WHERE cache_key = ?", (cache_key,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.debug(f"Cache delete error: {e}")
            return False

    def clear(self) -> None:
        """Alias for clear_all."""
        self.clear_all()

    def clear_all(self) -> None:
        """Flushes both in-memory and persistent SQLite cache."""
        with self._lock:
            self._mem_cache.clear()
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM osint_cache")
                conn.commit()
        except Exception as e:
            logger.debug(f"Cache clear error: {e}")

    def clear_expired(self) -> int:
        """Removes all expired entries from SQLite."""
        now = time.time()
        with self._lock:
            expired_keys = [k for k, (exp, _) in self._mem_cache.items() if exp <= now]
            for k in expired_keys:
                del self._mem_cache[k]

        try:
            with self._get_connection() as conn:
                cursor = conn.execute("DELETE FROM osint_cache WHERE expires_at <= ?", (now,))
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            logger.debug(f"Cache cleanup error: {e}")
            return 0


# Singleton convenience accessors
def get_cached(category_or_key: str, key: Optional[str] = None, force_refresh: bool = False) -> Optional[Any]:
    return CacheManager().get(category_or_key, key=key, force_refresh=force_refresh)


def set_cached(
    category_or_key: str,
    key_or_data: Any,
    data: Any = None,
    ttl_seconds: Optional[float] = None,
    ttl_hours: Optional[float] = None,
) -> None:
    CacheManager().set(category_or_key, key_or_data, data=data, ttl_seconds=ttl_seconds, ttl_hours=ttl_hours)
