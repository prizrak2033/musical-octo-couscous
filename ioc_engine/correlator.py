"""Core correlation engine — matches log observables against stored IOCs."""

from __future__ import annotations

import logging
from typing import Dict, Iterable, Iterator, List

from .models import CorrelationMatch, IOCType, LogEntry
from .storage import IOCStorage

logger = logging.getLogger(__name__)


class Correlator:
    """Match log entries against IOCs stored in an :class:`IOCStorage`.

    The engine builds a lookup index from the storage on first use (or when
    :meth:`refresh` is called) to keep per-entry cost O(1).
    """

    def __init__(self, storage: IOCStorage, min_confidence: int = 0) -> None:
        self.storage = storage
        self.min_confidence = min_confidence
        self._index: Dict[str, list] = {}  # value → [IOC, ...]
        self._built = False

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Rebuild the in-memory lookup index from storage."""
        self._index = {}
        for ioc in self.storage.list_all(min_confidence=self.min_confidence):
            key = ioc.value.strip().lower()
            self._index.setdefault(key, []).append(ioc)
        self._built = True
        logger.info("Correlator: index built with %d unique values", len(self._index))

    def _ensure_index(self) -> None:
        if not self._built:
            self.refresh()

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate_entry(self, entry: LogEntry) -> List[CorrelationMatch]:
        """Return all IOC matches for a single log entry."""
        self._ensure_index()
        matches: List[CorrelationMatch] = []

        checks = [
            ("source_ip", IOCType.IP, entry.all_ips()),
            ("domain", IOCType.DOMAIN, entry.all_domains()),
            ("url", IOCType.URL, [entry.url] if entry.url else []),
            ("email", IOCType.EMAIL, entry.emails),
            ("hash", None, entry.hashes),
        ]

        for field_name, expected_type, values in checks:
            for val in values:
                if not val:
                    continue
                key = val.strip().lower()
                for ioc in self._index.get(key, []):
                    if expected_type and ioc.ioc_type != expected_type:
                        # hashes can be any of the three hash types
                        if expected_type is None or field_name != "hash":
                            continue
                    matches.append(
                        CorrelationMatch(
                            ioc=ioc,
                            log_entry=entry,
                            matched_field=field_name,
                            matched_value=val,
                        )
                    )

        return matches

    def correlate_entries(
        self, entries: Iterable[LogEntry]
    ) -> Iterator[CorrelationMatch]:
        """Yield :class:`CorrelationMatch` objects for an iterable of entries."""
        self._ensure_index()
        total = 0
        hits = 0
        for entry in entries:
            total += 1
            for match in self.correlate_entry(entry):
                hits += 1
                yield match
        logger.info(
            "Correlator: processed %d log entries, produced %d matches", total, hits
        )
