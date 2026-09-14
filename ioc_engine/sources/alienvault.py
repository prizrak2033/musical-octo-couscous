"""AlienVault OTX IOC source.

Fetches IOCs from the `OTX DirectConnect
<https://otx.alienvault.com/api>`_ pulse-subscription endpoint.

Set ``OTX_API_KEY`` in the environment or pass ``api_key`` directly.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests

from ..models import IOC, IOCType, Severity
from .base import BaseIOCSource

logger = logging.getLogger(__name__)

# Map OTX indicator types → our IOCType
_TYPE_MAP: Dict[str, IOCType] = {
    "IPv4": IOCType.IP,
    "IPv6": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "FileHash-MD5": IOCType.HASH_MD5,
    "FileHash-SHA1": IOCType.HASH_SHA1,
    "FileHash-SHA256": IOCType.HASH_SHA256,
    "email": IOCType.EMAIL,
}

_BASE_URL = "https://otx.alienvault.com/api/v1"


class AlienVaultOTXSource(BaseIOCSource):
    """Pull IOCs from AlienVault OTX pulse subscriptions."""

    name = "alienvault_otx"

    def __init__(
        self,
        api_key: Optional[str] = None,
        limit: int = 500,
        timeout: int = 30,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("OTX_API_KEY", "")
        self.limit = limit
        self.timeout = timeout
        self._session = session or requests.Session()
        if self.api_key:
            self._session.headers.update({"X-OTX-API-KEY": self.api_key})

    # ------------------------------------------------------------------
    def fetch(self) -> List[IOC]:
        if not self.api_key:
            logger.warning("AlienVault OTX: no API key set – skipping.")
            return []
        iocs: List[IOC] = []
        page = 1
        fetched = 0
        while True:
            try:
                resp = self._session.get(
                    f"{_BASE_URL}/pulses/subscribed",
                    params={"limit": min(self.limit, 100), "page": page},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
            except requests.RequestException as exc:
                logger.error("AlienVault OTX request failed: %s", exc)
                break

            data: Dict[str, Any] = resp.json()
            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                source_tag = f"otx:{pulse.get('id', 'unknown')}"
                tags = pulse.get("tags", [])
                for indicator in pulse.get("indicators", []):
                    ioc_type = _TYPE_MAP.get(indicator.get("type", ""))
                    if ioc_type is None:
                        continue
                    value = indicator.get("indicator", "")
                    if not value:
                        continue
                    ioc = IOC(
                        ioc_type=ioc_type,
                        value=value,
                        source=self.name,
                        confidence=75,
                        severity=Severity.MEDIUM,
                        tags=tags,
                        description=pulse.get("description", ""),
                        metadata={
                            "pulse_id": pulse.get("id"),
                            "pulse_name": pulse.get("name"),
                            "otx_source": source_tag,
                        },
                    )
                    iocs.append(ioc)
                    fetched += 1
                    if fetched >= self.limit:
                        return iocs

            if not data.get("next"):
                break
            page += 1

        logger.info("AlienVault OTX: fetched %d IOCs", len(iocs))
        return iocs
