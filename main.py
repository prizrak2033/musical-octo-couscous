"""CLI entry point for the IOC Correlation Engine.

Sub-commands:
  fetch       Pull IOCs from configured sources into the local database.
  correlate   Parse log files and correlate against stored IOCs.
  report      Generate a report from the last correlation run.
  list        List IOCs stored in the database.

Usage examples:
  python main.py fetch --config config.yaml
  python main.py fetch --source urlhaus
  python main.py correlate /var/log/auth.log
  python main.py correlate /var/log/nginx/access.log --format apache
  python main.py report --format html --output report.html
  python main.py list --type ip --min-confidence 80
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

import yaml

from ioc_engine.correlator import Correlator
from ioc_engine.models import IOCType
from ioc_engine.parsers import ApacheLogParser, CEFLogParser, JSONLogParser, SyslogParser
from ioc_engine.parsers.base import BaseLogParser
from ioc_engine.reporter import Reporter
from ioc_engine.sources import (
    AbuseIPDBSource,
    AlienVaultOTXSource,
    LocalFileSource,
    URLhausSource,
)
from ioc_engine.sources.base import BaseIOCSource
from ioc_engine.storage import IOCStorage

logger = logging.getLogger("ioc_engine")

_LOG_PARSERS = {
    "syslog": SyslogParser,
    "apache": ApacheLogParser,
    "nginx": ApacheLogParser,
    "json": JSONLogParser,
    "cef": CEFLogParser,
}

_SOURCES = {
    "alienvault_otx": AlienVaultOTXSource,
    "abuseipdb": AbuseIPDBSource,
    "urlhaus": URLhausSource,
}


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        logger.warning("Config file not found: %s — using defaults", path)
        return {}
    with p.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ---------------------------------------------------------------------------
# Source factory
# ---------------------------------------------------------------------------

def _build_sources(cfg: dict, override_source: Optional[str] = None,
                   local_file: Optional[str] = None) -> List[BaseIOCSource]:
    sources_cfg = cfg.get("sources", {})
    sources: List[BaseIOCSource] = []

    def _enabled(name: str) -> bool:
        if override_source:
            return name == override_source
        return sources_cfg.get(name, {}).get("enabled", True)

    if _enabled("alienvault_otx"):
        sc = sources_cfg.get("alienvault_otx", {})
        sources.append(
            AlienVaultOTXSource(
                api_key=sc.get("api_key"),
                limit=sc.get("limit", 500),
            )
        )

    if _enabled("abuseipdb"):
        sc = sources_cfg.get("abuseipdb", {})
        sources.append(
            AbuseIPDBSource(
                api_key=sc.get("api_key"),
                confidence_minimum=sc.get("confidence_minimum", 90),
                limit=sc.get("limit", 500),
            )
        )

    if _enabled("urlhaus"):
        sc = sources_cfg.get("urlhaus", {})
        sources.append(URLhausSource(limit=sc.get("limit", 1000)))

    if local_file or _enabled("local_file"):
        fp = local_file or sources_cfg.get("local_file", {}).get("path")
        if fp:
            sources.append(LocalFileSource(fp))

    return sources


# ---------------------------------------------------------------------------
# Parser factory
# ---------------------------------------------------------------------------

def _detect_format(path: str) -> str:
    name = Path(path).name.lower()
    if "access" in name or "nginx" in name or "apache" in name:
        return "apache"
    if name.endswith(".json") or "json" in name:
        return "json"
    if "cef" in name:
        return "cef"
    return "syslog"


def _build_parser(fmt: Optional[str], path: str) -> BaseLogParser:
    fmt = fmt or _detect_format(path)
    cls = _LOG_PARSERS.get(fmt, SyslogParser)
    return cls()


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def cmd_fetch(args: argparse.Namespace, cfg: dict) -> int:
    db_path = cfg.get("database", {}).get("path", "ioc_engine.db")
    storage = IOCStorage(db_path)
    sources = _build_sources(cfg, override_source=args.source, local_file=args.file)

    if not sources:
        logger.error("No sources enabled.  Check your config or --source flag.")
        return 1

    total = 0
    for src in sources:
        logger.info("Fetching from %s …", src.name)
        iocs = src.fetch()
        n = storage.bulk_upsert(iocs)
        logger.info("  → %d IOCs stored from %s", n, src.name)
        total += n

    print(f"✔  Fetched and stored {total} IOCs into {db_path}")
    return 0


def cmd_correlate(args: argparse.Namespace, cfg: dict) -> int:
    db_path = cfg.get("database", {}).get("path", "ioc_engine.db")
    storage = IOCStorage(db_path)
    min_conf = cfg.get("correlator", {}).get("min_confidence", args.min_confidence)
    correlator = Correlator(storage, min_confidence=min_conf)

    all_matches = []
    log_paths: List[str] = args.logs

    for log_path in log_paths:
        p = Path(log_path)
        if p.is_dir():
            files = list(p.rglob("*"))
        else:
            files = [p]

        for f in files:
            if not f.is_file():
                continue
            parser = _build_parser(args.format, str(f))
            logger.info("Parsing %s with %s parser …", f, parser.name)
            entries = list(parser.parse_file(str(f)))
            matches = list(correlator.correlate_entries(iter(entries)))
            all_matches.extend(matches)
            logger.info("  → %d matches in %s", len(matches), f)

    print(f"✔  Found {len(all_matches)} IOC match(es) across {len(log_paths)} path(s).")

    # Save matches for subsequent `report` command
    cache_path = args.cache or "correlation_cache.json"
    _save_match_cache(all_matches, cache_path)
    print(f"   Cache saved to {cache_path}")

    if args.output:
        fmt = args.report_format or cfg.get("reporter", {}).get("default_format", "json")
        reporter = Reporter(all_matches)
        reporter.save(args.output, fmt=fmt)

    return 0


def cmd_report(args: argparse.Namespace, cfg: dict) -> int:
    cache_path = args.cache or "correlation_cache.json"
    matches = _load_match_cache(cache_path)
    if matches is None:
        logger.error("Cache file not found: %s  (run `correlate` first)", cache_path)
        return 1

    fmt = args.format or cfg.get("reporter", {}).get("default_format", "json")
    output = args.output or f"report.{fmt}"
    reporter = Reporter(matches)
    reporter.save(output, fmt=fmt)
    print(f"✔  Report written to {output}")
    return 0


def cmd_list(args: argparse.Namespace, cfg: dict) -> int:
    db_path = cfg.get("database", {}).get("path", "ioc_engine.db")
    storage = IOCStorage(db_path)
    ioc_type = IOCType(args.type) if args.type else None
    iocs = storage.list_all(
        ioc_type=ioc_type,
        source=args.source,
        min_confidence=args.min_confidence,
    )
    if not iocs:
        print("No IOCs found.")
        return 0
    for ioc in iocs:
        print(
            f"[{ioc.severity.value.upper():8}] {ioc.ioc_type.value:12} "
            f"{ioc.value:50}  conf={ioc.confidence}  src={ioc.source}"
        )
    print(f"\nTotal: {len(iocs)}")
    return 0


# ---------------------------------------------------------------------------
# Match cache helpers
# ---------------------------------------------------------------------------

def _save_match_cache(matches, path: str) -> None:
    """Serialize matches to a JSON file (safe, human-readable)."""
    data = [m.to_dict() for m in matches]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def _load_match_cache(path: str):
    """Load cached CorrelationMatch objects from JSON. Returns None if file missing."""
    from ioc_engine.models import CorrelationMatch  # noqa: PLC0415
    p = Path(path)
    if not p.exists():
        return None
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return [CorrelationMatch.from_dict(d) for d in data]


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-engine",
        description="Automated IOC Correlation Engine",
    )
    parser.add_argument(
        "--config", "-c", default=None,
        help="Path to config.yaml (default: auto-detect config.yaml in cwd)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- fetch ---
    p_fetch = sub.add_parser("fetch", help="Pull IOCs from threat-intel sources")
    p_fetch.add_argument(
        "--source", default=None,
        choices=list(_SOURCES.keys()) + ["local"],
        help="Fetch from a single source only",
    )
    p_fetch.add_argument("--file", default=None, help="Local CSV/JSON file path (for --source local)")

    # --- correlate ---
    p_corr = sub.add_parser("correlate", help="Correlate log files against stored IOCs")
    p_corr.add_argument("logs", nargs="+", help="Log file(s) or directory to parse")
    p_corr.add_argument(
        "--format", "-f", default=None,
        choices=list(_LOG_PARSERS.keys()),
        help="Force log format (default: auto-detect)",
    )
    p_corr.add_argument("--min-confidence", type=int, default=0,
                        help="Minimum IOC confidence to match against (0-100)")
    p_corr.add_argument("--output", "-o", default=None, help="Write report to this file")
    p_corr.add_argument("--report-format", default=None, choices=["json", "csv", "html"])
    p_corr.add_argument("--cache", default=None, help="Path for intermediate match cache")

    # --- report ---
    p_rep = sub.add_parser("report", help="Generate a report from cached correlation results")
    p_rep.add_argument("--format", "-f", default="json", choices=["json", "csv", "html"])
    p_rep.add_argument("--output", "-o", default=None, help="Output file path")
    p_rep.add_argument("--cache", default=None, help="Path to match cache (default: correlation_cache.json)")

    # --- list ---
    p_list = sub.add_parser("list", help="List IOCs in the local database")
    p_list.add_argument("--type", default=None, choices=[t.value for t in IOCType])
    p_list.add_argument("--source", default=None)
    p_list.add_argument("--min-confidence", type=int, default=0)

    return parser


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Try to auto-find config
    cfg_path = args.config
    if not cfg_path and Path("config.yaml").exists():
        cfg_path = "config.yaml"

    cfg = _load_config(cfg_path)

    handlers = {
        "fetch": cmd_fetch,
        "correlate": cmd_correlate,
        "report": cmd_report,
        "list": cmd_list,
    }
    return handlers[args.command](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
