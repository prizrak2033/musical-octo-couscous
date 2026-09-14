"""Local file IOC source.

Supports two formats:
  - CSV: columns ``type,value[,confidence,severity,tags,description]``
  - JSON: list of objects with the same keys, or a dict ``{"iocs": [...]}``
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from ..models import IOC, IOCType, Severity
from .base import BaseIOCSource

logger = logging.getLogger(__name__)


class LocalFileSource(BaseIOCSource):
    """Load IOCs from a local CSV or JSON file."""

    name = "local_file"

    def __init__(self, path: str, source_name: str = "local_file") -> None:
        self.path = Path(path)
        self.name = source_name

    # ------------------------------------------------------------------
    def fetch(self) -> List[IOC]:
        if not self.path.exists():
            logger.error("LocalFileSource: file not found: %s", self.path)
            return []
        suffix = self.path.suffix.lower()
        if suffix == ".json":
            return self._load_json()
        if suffix in {".csv", ".tsv", ".txt"}:
            return self._load_csv()
        # Try JSON first, then CSV
        try:
            return self._load_json()
        except (json.JSONDecodeError, ValueError):
            return self._load_csv()

    # ------------------------------------------------------------------
    def _load_json(self) -> List[IOC]:
        with self.path.open(encoding="utf-8") as fh:
            raw = json.load(fh)
        if isinstance(raw, dict):
            records = raw.get("iocs", raw.get("indicators", []))
        elif isinstance(raw, list):
            records = raw
        else:
            logger.error("LocalFileSource: unexpected JSON shape in %s", self.path)
            return []
        iocs: List[IOC] = []
        for rec in records:
            ioc = self._parse_record(rec)
            if ioc:
                iocs.append(ioc)
        logger.info("LocalFileSource(%s): loaded %d IOCs from JSON", self.path, len(iocs))
        return iocs

    def _load_csv(self) -> List[IOC]:
        delimiter = "\t" if self.path.suffix.lower() == ".tsv" else ","
        iocs: List[IOC] = []
        with self.path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh, delimiter=delimiter)
            for row in reader:
                ioc = self._parse_record(dict(row))
                if ioc:
                    iocs.append(ioc)
        logger.info("LocalFileSource(%s): loaded %d IOCs from CSV", self.path, len(iocs))
        return iocs

    # ------------------------------------------------------------------
    def _parse_record(self, rec: Dict[str, Any]) -> IOC | None:
        raw_type = str(rec.get("type", rec.get("ioc_type", ""))).strip()
        value = str(rec.get("value", rec.get("indicator", ""))).strip()
        if not raw_type or not value:
            logger.debug("LocalFileSource: skipping incomplete record: %s", rec)
            return None
        try:
            ioc_type = IOCType(raw_type.lower())
        except ValueError:
            logger.warning("LocalFileSource: unknown IOC type %r – skipping", raw_type)
            return None

        raw_sev = str(rec.get("severity", "medium")).strip().lower()
        try:
            severity = Severity(raw_sev)
        except ValueError:
            severity = Severity.MEDIUM

        raw_tags = rec.get("tags", "")
        if isinstance(raw_tags, list):
            tags = raw_tags
        else:
            tags = [t.strip() for t in str(raw_tags).split(",") if t.strip()]

        return IOC(
            ioc_type=ioc_type,
            value=value,
            source=self.name,
            confidence=int(rec.get("confidence", 70)),
            severity=severity,
            tags=tags,
            description=str(rec.get("description", "")),
            metadata=rec.get("metadata", {}),
        )
