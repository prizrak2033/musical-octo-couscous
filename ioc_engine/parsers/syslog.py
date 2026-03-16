"""Syslog parser — supports RFC 3164 (BSD) syslog format."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator, Optional

from ..models import LogEntry
from .base import BaseLogParser, extract_observables

# Mar 15 10:00:01 hostname process[pid]: message
_RE_SYSLOG = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


class SyslogParser(BaseLogParser):
    """Parse standard RFC 3164 syslog lines."""

    name = "syslog"

    def parse_file(self, path: str) -> Iterator[LogEntry]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = self.parse_line(line.rstrip("\n"))
                if entry is not None:
                    yield entry

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None
        m = _RE_SYSLOG.match(line)
        ts: Optional[datetime] = None
        hostname: Optional[str] = None
        message = line

        if m:
            month = _MONTHS.get(m.group("month").lower())
            day = int(m.group("day"))
            h, mi, s = map(int, m.group("time").split(":"))
            now = datetime.now(timezone.utc)
            if month:
                year = now.year if month <= now.month else now.year - 1
                ts = datetime(year, month, day, h, mi, s, tzinfo=timezone.utc)
            hostname = m.group("host")
            message = m.group("message")

        obs = extract_observables(message)
        ips = obs["ips"]
        source_ip = ips[0] if ips else None
        extra_ips = ips[1:] if len(ips) > 1 else []

        return LogEntry(
            raw=line,
            timestamp=ts,
            source_ip=source_ip,
            extra_ips=extra_ips,
            domain=obs["domains"][0] if obs["domains"] else None,
            extra_domains=obs["domains"][1:],
            url=obs["urls"][0] if obs["urls"] else None,
            hashes=obs["hashes"],
            emails=obs["emails"],
            log_source=self.name,
            metadata={"hostname": hostname, "message": message},
        )
