"""
log_parser.py - Parses log files from the logs directory.
"""

import os
import re


LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")


def parse_firewall_log(filename: str = "firewall.log") -> list:
    """
    Parse the firewall log file.
    Expected format: timestamp action src_ip dst_ip src_port dst_port protocol
    Returns a list of parsed log entry dicts.
    """
    entries = []
    filepath = os.path.join(LOGS_DIR, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 7:
                entries.append({
                    "timestamp": parts[0],
                    "action": parts[1],
                    "src_ip": parts[2],
                    "dst_ip": parts[3],
                    "src_port": parts[4],
                    "dst_port": parts[5],
                    "protocol": parts[6],
                    "raw": line,
                })
    return entries


def parse_auth_log(filename: str = "auth.log") -> list:
    """
    Parse the authentication log file.
    Expected format: timestamp hostname service[pid]: message
    Returns a list of parsed log entry dicts.
    """
    entries = []
    pattern = re.compile(
        r"^(?P<timestamp>\S+\s+\d+\s+\d+:\d+:\d+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    )
    filepath = os.path.join(LOGS_DIR, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = pattern.match(line)
            if match:
                entries.append(match.groupdict())
            else:
                entries.append({"raw": line})
    return entries
