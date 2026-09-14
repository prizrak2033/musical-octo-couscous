"""Abstract base class for log parsers and shared observable extractor."""

from __future__ import annotations

import abc
import re
from typing import Iterator, List

from ..models import LogEntry

# ---------------------------------------------------------------------------
# Compiled regexes for common observables
# ---------------------------------------------------------------------------

# IPv4 — simple but not overly broad (0-255 only)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# IPv6 (abbreviated forms too)
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    r"|\b::1\b"
    r"|\b::\b"
)

# Domain (simplified — at least two labels, known-ish TLD length)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)

# URL
_RE_URL = re.compile(
    r"https?://[^\s\"'<>{}|\\^`\[\]]+",
    re.IGNORECASE,
)

# Hashes
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Email
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# Private / loopback ranges — skip these during extraction
_PRIVATE_IPV4 = re.compile(
    r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0$|255\.255\.255\.255$)"
)


def extract_observables(text: str) -> dict:
    """Extract IOC-relevant strings from arbitrary text."""
    ips: List[str] = []
    for m in _RE_IPV4.findall(text):
        if not _PRIVATE_IPV4.match(m):
            ips.append(m)
    for m in _RE_IPV6.findall(text):
        ips.append(m)

    urls = _RE_URL.findall(text)
    domains: List[str] = []
    for m in _RE_DOMAIN.findall(text):
        # Skip domains that are just parts of already-found URLs
        if not any(m in u for u in urls):
            domains.append(m)

    hashes: List[str] = []
    hashes.extend(_RE_SHA256.findall(text))
    # Remove longer hashes before searching for shorter ones to prevent partial matches
    cleaned = _RE_SHA256.sub("", text)
    hashes.extend(_RE_SHA1.findall(cleaned))
    cleaned = _RE_SHA1.sub("", cleaned)
    hashes.extend(_RE_MD5.findall(cleaned))

    emails = _RE_EMAIL.findall(text)

    return {
        "ips": list(dict.fromkeys(ips)),
        "domains": list(dict.fromkeys(domains)),
        "urls": list(dict.fromkeys(urls)),
        "hashes": list(dict.fromkeys(hashes)),
        "emails": list(dict.fromkeys(emails)),
    }


class BaseLogParser(abc.ABC):
    """All log parsers must implement :meth:`parse_file`."""

    #: Human-readable name
    name: str = "unknown"

    @abc.abstractmethod
    def parse_file(self, path: str) -> Iterator[LogEntry]:
        """Yield :class:`LogEntry` objects from *path*."""

    def parse_lines(self, lines: List[str]) -> Iterator[LogEntry]:
        """Yield :class:`LogEntry` objects from an iterable of lines."""
        for line in lines:
            entry = self.parse_line(line)
            if entry is not None:
                yield entry

    def parse_line(self, line: str) -> LogEntry | None:  # pragma: no cover
        """Parse a single line; return None to skip."""
        return None

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__} name={self.name!r}>"
