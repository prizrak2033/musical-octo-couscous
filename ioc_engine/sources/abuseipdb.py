"""AbuseIPDB IOC source.

Fetches the public blacklist from the AbuseIPDB v2 API.
Set ``ABUSEIPDB_API_KEY`` in the environment or pass ``api_key`` directly.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests

from ..models import IOC, IOCType, Severity
from .base import BaseIOCSource

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBSource(BaseIOCSource):
    """Pull blacklisted IPs from AbuseIPDB."""

    name = "abuseipdb"

    def __init__(
        self,
        api_key: Optional[str] = None,
        confidence_minimum: int = 90,
        limit: int = 500,
        timeout: int = 30,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.confidence_minimum = confidence_minimum
        self.limit = limit
        self.timeout = timeout
        self._session = session or requests.Session()
        if self.api_key:
            self._session.headers.update(
                {"Key": self.api_key, "Accept": "application/json"}
            )

    # ------------------------------------------------------------------
    def fetch(self) -> List[IOC]:
        if not self.api_key:
            logger.warning("AbuseIPDB: no API key set – skipping.")
            return []
        iocs: List[IOC] = []
        try:
            resp = self._session.get(
                f"{_BASE_URL}/blacklist",
                params={
                    "confidenceMinimum": self.confidence_minimum,
                    "limit": self.limit,
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.error("AbuseIPDB request failed: %s", exc)
            return iocs

        data: Dict[str, Any] = resp.json()
        for entry in data.get("data", []):
            ip = entry.get("ipAddress", "")
            if not ip:
                continue
            score = entry.get("abuseConfidenceScore", 50)
            ioc = IOC(
                ioc_type=IOCType.IP,
                value=ip,
                source=self.name,
                confidence=score,
                severity=_score_to_severity(score),
                tags=["abuse"],
                description=f"AbuseIPDB confidence score: {score}",
                metadata={
                    "country_code": entry.get("countryCode"),
                    "usage_type": entry.get("usageType"),
                    "isp": entry.get("isp"),
                    "domain": entry.get("domain"),
                    "total_reports": entry.get("totalReports"),
                },
            )
            iocs.append(ioc)

        logger.info("AbuseIPDB: fetched %d IOCs", len(iocs))
        return iocs


def _score_to_severity(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 75:
        return Severity.HIGH
    if score >= 50:
        return Severity.MEDIUM
    return Severity.LOW
