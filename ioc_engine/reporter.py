"""Report generation — JSON, CSV, and self-contained HTML outputs."""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import List, Sequence

from .models import CorrelationMatch

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTML template (inline — no external assets required)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IOC Correlation Report</title>
<style>
  body{{font-family:sans-serif;margin:2rem;background:#f8f9fa;color:#212529}}
  h1{{color:#d63384}}
  table{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
  th{{background:#343a40;color:#fff;padding:.6rem .8rem;text-align:left}}
  td{{padding:.5rem .8rem;border-bottom:1px solid #dee2e6;vertical-align:top;word-break:break-all}}
  tr:hover td{{background:#e9ecef}}
  .critical{{color:#dc3545;font-weight:700}}
  .high{{color:#fd7e14;font-weight:700}}
  .medium{{color:#ffc107}}
  .low{{color:#0d6efd}}
  .info{{color:#6c757d}}
  .summary{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}}
  .card{{background:#fff;border-radius:8px;padding:1rem 1.5rem;box-shadow:0 1px 4px rgba(0,0,0,.1);min-width:120px;text-align:center}}
  .card .num{{font-size:2rem;font-weight:700;color:#d63384}}
  .card .lbl{{font-size:.85rem;color:#6c757d}}
  .ts{{color:#6c757d;font-size:.8rem}}
</style>
</head>
<body>
<h1>&#x1F6E1; IOC Correlation Report</h1>
<p class="ts">Generated: {generated_at}</p>
<div class="summary">
  <div class="card"><div class="num">{total_matches}</div><div class="lbl">Total Matches</div></div>
  <div class="card"><div class="num">{unique_iocs}</div><div class="lbl">Unique IOCs</div></div>
  <div class="card"><div class="num">{critical}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num">{high}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num">{medium}</div><div class="lbl">Medium</div></div>
</div>
{table}
</body>
</html>
"""

_TABLE_HEAD = """\
<table>
<thead><tr>
  <th>#</th><th>Severity</th><th>IOC Type</th><th>IOC Value</th>
  <th>Source</th><th>Confidence</th><th>Matched Field</th>
  <th>Log Timestamp</th><th>Raw Log (excerpt)</th>
</tr></thead>
<tbody>
"""

_TABLE_TAIL = "</tbody></table>\n"


class Reporter:
    """Turn a list of :class:`CorrelationMatch` objects into a report."""

    def __init__(self, matches: Sequence[CorrelationMatch]) -> None:
        self.matches = list(matches)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Return a JSON string representation of all matches."""
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_matches": len(self.matches),
            "matches": [m.to_dict() for m in self.matches],
        }
        return json.dumps(data, indent=indent, ensure_ascii=False)

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
        logger.info("Report saved to %s (JSON)", path)

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    _CSV_FIELDS = [
        "detected_at",
        "severity",
        "ioc_type",
        "ioc_value",
        "ioc_source",
        "confidence",
        "tags",
        "matched_field",
        "matched_value",
        "log_timestamp",
        "log_source",
        "raw_excerpt",
    ]

    def to_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self._CSV_FIELDS)
        writer.writeheader()
        for m in self.matches:
            writer.writerow(
                {
                    "detected_at": m.detected_at.isoformat(),
                    "severity": m.ioc.severity.value,
                    "ioc_type": m.ioc.ioc_type.value,
                    "ioc_value": m.ioc.value,
                    "ioc_source": m.ioc.source,
                    "confidence": m.ioc.confidence,
                    "tags": "|".join(m.ioc.tags),
                    "matched_field": m.matched_field,
                    "matched_value": m.matched_value,
                    "log_timestamp": (
                        m.log_entry.timestamp.isoformat()
                        if m.log_entry.timestamp
                        else ""
                    ),
                    "log_source": m.log_entry.log_source,
                    "raw_excerpt": m.log_entry.raw[:200],
                }
            )
        return buf.getvalue()

    def save_csv(self, path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            fh.write(self.to_csv())
        logger.info("Report saved to %s (CSV)", path)

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def to_html(self) -> str:
        sev_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for m in self.matches:
            sev_counts[m.ioc.severity.value] = sev_counts.get(m.ioc.severity.value, 0) + 1

        unique_iocs = len({m.ioc.unique_id for m in self.matches})

        rows = []
        for i, m in enumerate(self.matches, 1):
            sev = m.ioc.severity.value
            ts = m.log_entry.timestamp.isoformat() if m.log_entry.timestamp else "—"
            raw_ex = _esc(m.log_entry.raw[:120])
            rows.append(
                f"<tr>"
                f"<td>{i}</td>"
                f"<td class='{sev}'>{sev.upper()}</td>"
                f"<td>{_esc(m.ioc.ioc_type.value)}</td>"
                f"<td>{_esc(m.ioc.value)}</td>"
                f"<td>{_esc(m.ioc.source)}</td>"
                f"<td>{m.ioc.confidence}</td>"
                f"<td>{_esc(m.matched_field)}</td>"
                f"<td class='ts'>{ts}</td>"
                f"<td><small>{raw_ex}</small></td>"
                f"</tr>"
            )

        table = _TABLE_HEAD + "\n".join(rows) + _TABLE_TAIL

        return _HTML_TEMPLATE.format(
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_matches=len(self.matches),
            unique_iocs=unique_iocs,
            critical=sev_counts.get("critical", 0),
            high=sev_counts.get("high", 0),
            medium=sev_counts.get("medium", 0),
            table=table,
        )

    def save_html(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_html())
        logger.info("Report saved to %s (HTML)", path)

    # ------------------------------------------------------------------
    # Unified save
    # ------------------------------------------------------------------

    def save(self, path: str, fmt: str = "json") -> None:
        fmt = fmt.lower()
        if fmt == "json":
            self.save_json(path)
        elif fmt == "csv":
            self.save_csv(path)
        elif fmt == "html":
            self.save_html(path)
        else:
            raise ValueError(f"Unknown report format: {fmt!r}")


def _esc(s: str) -> str:
    """Minimal HTML escaping."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
