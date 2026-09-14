"""
correlator.py - Correlates parsed log entries against loaded IOCs to detect threats.
"""

from engine.ioc_loader import load_all_feeds, get_ioc_entries
from engine.log_parser import parse_firewall_log, parse_auth_log
import re


def build_ioc_sets() -> dict:
    """
    Build lookup sets from all threat feeds.
    Returns a dict with keys like 'ip_addresses' and 'domains'.
    """
    ioc_sets = {"ip_addresses": set(), "domains": set()}
    for feed in load_all_feeds():
        for entry in get_ioc_entries(feed):
            if "ip" in entry:
                ioc_sets["ip_addresses"].add(entry["ip"])
            if "domain" in entry:
                ioc_sets["domains"].add(entry["domain"])
    return ioc_sets


def correlate_firewall_logs(ioc_sets: dict) -> list:
    """
    Check firewall log entries against known malicious IPs.
    Returns a list of matching (suspicious) entries.
    """
    hits = []
    for entry in parse_firewall_log():
        if (
            entry.get("src_ip") in ioc_sets["ip_addresses"]
            or entry.get("dst_ip") in ioc_sets["ip_addresses"]
        ):
            hits.append(entry)
    return hits


def correlate_auth_logs(ioc_sets: dict) -> list:
    """
    Check auth log entries for patterns associated with known threats.
    Returns a list of matching (suspicious) entries.
    Uses a combined regex for efficient domain matching.
    """
    hits = []
    domains = [d for d in ioc_sets["domains"] if d]
    if not domains:
        return hits
    domain_pattern = re.compile("|".join(re.escape(d) for d in domains))
    for entry in parse_auth_log():
        message = entry.get("message", entry.get("raw", ""))
        if domain_pattern.search(message):
            hits.append(entry)
    return hits


def run_correlation() -> dict:
    """
    Run full correlation across all logs and IOC feeds.
    Returns a summary dict of detected threats.
    """
    ioc_sets = build_ioc_sets()
    return {
        "firewall_hits": correlate_firewall_logs(ioc_sets),
        "auth_hits": correlate_auth_logs(ioc_sets),
    }
