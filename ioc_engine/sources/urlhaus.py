"""URLhaus IOC source (abuse.ch public feed).

Downloads the CSV payload dump from URLhaus:
https://urlhaus.abuse.ch/downloads/csv_recent/
"""

from __future__ import annotations

import csv
import io
import logging
from typing import List, Optional
from zipfile import BadZipFile, ZipFile

import requests

from ..models import IOC, IOCType, Severity
from .base import BaseIOCSource

logger = logging.getLogger(__name__)

_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


class URLhausSource(BaseIOCSource):
    """Pull recent malicious URLs from URLhaus (abuse.ch)."""

    name = "urlhaus"

    def __init__(
        self,
        feed_url: str = _FEED_URL,
        limit: int = 1000,
        timeout: int = 60,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.feed_url = feed_url
        self.limit = limit
        self.timeout = timeout
        self._session = session or requests.Session()

    # ------------------------------------------------------------------
    def fetch(self) -> List[IOC]:
        try:
            resp = self._session.get(self.feed_url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.error("URLhaus request failed: %s", exc)
            return []

        content = self._decode_content(resp.content)
        if content is None:
            return []

        iocs: List[IOC] = []
        reader = csv.reader(self._strip_comments(content))
        headers: Optional[list] = None
        for row in reader:
            if not row:
                continue
            if headers is None:
                headers = [h.strip().lstrip("#").strip() for h in row]
                continue
            if len(row) < len(headers):
                continue
            entry = dict(zip(headers, row))
            url = entry.get("url", "").strip()
            if not url:
                continue
            tags_raw = entry.get("tags", "")
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
            severity = (
                Severity.HIGH
                if entry.get("threat", "").lower() == "malware_download"
                else Severity.MEDIUM
            )
            ioc = IOC(
                ioc_type=IOCType.URL,
                value=url,
                source=self.name,
                confidence=80,
                severity=severity,
                tags=tags,
                description=entry.get("threat", ""),
                metadata={
                    "urlhaus_id": entry.get("id"),
                    "date_added": entry.get("dateadded"),
                    "host": entry.get("host"),
                },
            )
            iocs.append(ioc)
            if len(iocs) >= self.limit:
                break

        logger.info("URLhaus: fetched %d IOCs", len(iocs))
        return iocs

    # ------------------------------------------------------------------
    @staticmethod
    def _decode_content(raw: bytes) -> Optional[str]:
        """Handle both plain CSV and zipped CSV responses."""
        try:
            with ZipFile(io.BytesIO(raw)) as zf:
                name = zf.namelist()[0]
                return zf.read(name).decode("utf-8", errors="replace")
        except (BadZipFile, IndexError):
            pass
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            logger.error("URLhaus: failed to decode content: %s", exc)
            return None

    @staticmethod
    def _strip_comments(text: str):
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") and not stripped.startswith("# id"):
                continue
            yield line
