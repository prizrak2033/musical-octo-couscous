"""
ioc_loader.py - Loads Indicators of Compromise (IOCs) from threat feed files.
"""

import json
import os


THREAT_FEEDS_DIR = os.path.join(os.path.dirname(__file__), "..", "threat_feeds")


def load_feed(filename: str) -> dict:
    """Load a single threat feed JSON file and return its contents."""
    filepath = os.path.join(THREAT_FEEDS_DIR, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Threat feed file not found: {filepath}")
    with open(filepath, "r") as f:
        return json.load(f)


def load_all_feeds() -> list:
    """Load all threat feed JSON files from the threat_feeds directory."""
    feeds = []
    for fname in os.listdir(THREAT_FEEDS_DIR):
        if fname.endswith(".json"):
            feeds.append(load_feed(fname))
    return feeds


def get_ioc_entries(feed: dict) -> list:
    """Extract IOC entries from a loaded feed."""
    return feed.get("entries", [])
