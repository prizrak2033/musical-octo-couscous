"""Data models for IOCs, log entries and correlation matches."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IOCType(str, Enum):
    """Supported Indicator of Compromise types."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"


class Severity(str, Enum):
    """Severity levels for IOC matches."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IOC:
    """Represents a single Indicator of Compromise."""

    ioc_type: IOCType
    value: str
    source: str
    confidence: int = 50  # 0-100
    severity: Severity = Severity.MEDIUM
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.value = self.value.strip().lower() if self.value else self.value
        if isinstance(self.ioc_type, str):
            self.ioc_type = IOCType(self.ioc_type)
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)

    @property
    def unique_id(self) -> str:
        """Stable identifier: hash of type+value."""
        raw = f"{self.ioc_type.value}:{self.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "severity": self.severity.value,
            "tags": self.tags,
            "description": self.description,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IOC":
        return cls(
            ioc_type=IOCType(d["ioc_type"]),
            value=d["value"],
            source=d["source"],
            confidence=d.get("confidence", 50),
            severity=Severity(d.get("severity", "medium")),
            tags=d.get("tags", []),
            description=d.get("description", ""),
            first_seen=datetime.fromisoformat(d["first_seen"]),
            last_seen=datetime.fromisoformat(d["last_seen"]),
            metadata=d.get("metadata", {}),
        )


@dataclass
class LogEntry:
    """Represents a parsed log entry with extracted observable fields."""

    raw: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    hashes: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    extra_ips: List[str] = field(default_factory=list)
    extra_domains: List[str] = field(default_factory=list)
    log_source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def all_ips(self) -> List[str]:
        ips: List[str] = []
        if self.source_ip:
            ips.append(self.source_ip)
        if self.dest_ip:
            ips.append(self.dest_ip)
        ips.extend(self.extra_ips)
        return list(dict.fromkeys(ips))

    def all_domains(self) -> List[str]:
        domains: List[str] = []
        if self.domain:
            domains.append(self.domain)
        domains.extend(self.extra_domains)
        return list(dict.fromkeys(domains))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw": self.raw,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "domain": self.domain,
            "url": self.url,
            "user_agent": self.user_agent,
            "username": self.username,
            "hashes": self.hashes,
            "emails": self.emails,
            "extra_ips": self.extra_ips,
            "extra_domains": self.extra_domains,
            "log_source": self.log_source,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LogEntry":
        ts_raw = d.get("timestamp")
        return cls(
            raw=d.get("raw", ""),
            timestamp=datetime.fromisoformat(ts_raw) if ts_raw else None,
            source_ip=d.get("source_ip"),
            dest_ip=d.get("dest_ip"),
            domain=d.get("domain"),
            url=d.get("url"),
            user_agent=d.get("user_agent"),
            username=d.get("username"),
            hashes=d.get("hashes", []),
            emails=d.get("emails", []),
            extra_ips=d.get("extra_ips", []),
            extra_domains=d.get("extra_domains", []),
            log_source=d.get("log_source", ""),
            metadata=d.get("metadata", {}),
        )


@dataclass
class CorrelationMatch:
    """Represents a hit: an IOC found inside a log entry."""

    ioc: IOC
    log_entry: LogEntry
    matched_field: str  # which field of the log entry matched
    matched_value: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc": self.ioc.to_dict(),
            "log_entry": self.log_entry.to_dict(),
            "matched_field": self.matched_field,
            "matched_value": self.matched_value,
            "detected_at": self.detected_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CorrelationMatch":
        return cls(
            ioc=IOC.from_dict(d["ioc"]),
            log_entry=LogEntry.from_dict(d["log_entry"]),
            matched_field=d["matched_field"],
            matched_value=d["matched_value"],
            detected_at=datetime.fromisoformat(d["detected_at"]),
        )
