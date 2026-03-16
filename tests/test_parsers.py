"""Tests for log parsers."""

import json
import textwrap
from datetime import timezone

import pytest

from ioc_engine.parsers.base import extract_observables
from ioc_engine.parsers.syslog import SyslogParser
from ioc_engine.parsers.apache import ApacheLogParser
from ioc_engine.parsers.json_log import JSONLogParser
from ioc_engine.parsers.cef import CEFLogParser


# ---------------------------------------------------------------------------
# extract_observables
# ---------------------------------------------------------------------------

class TestExtractObservables:
    def test_ipv4(self):
        obs = extract_observables("Connection from 203.0.113.5 refused")
        assert "203.0.113.5" in obs["ips"]

    def test_private_ip_excluded(self):
        obs = extract_observables("src=192.168.1.1 dst=10.0.0.1")
        assert obs["ips"] == []

    def test_url(self):
        obs = extract_observables("Download from http://evil.com/malware.exe now")
        assert any("evil.com" in u for u in obs["urls"])

    def test_md5(self):
        obs = extract_observables("hash: " + "a" * 32)
        assert "a" * 32 in obs["hashes"]

    def test_sha256(self):
        obs = extract_observables("sha256=" + "b" * 64)
        assert "b" * 64 in obs["hashes"]

    def test_email(self):
        obs = extract_observables("Contact attacker@evil.com for ransom")
        assert "attacker@evil.com" in obs["emails"]

    def test_empty_string(self):
        obs = extract_observables("")
        assert obs == {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []}


# ---------------------------------------------------------------------------
# SyslogParser
# ---------------------------------------------------------------------------

class TestSyslogParser:
    PARSER = SyslogParser()

    def test_parse_valid_line(self):
        line = "Mar 15 10:00:01 myhost sshd[1234]: Failed password from 203.0.113.5 port 22"
        entry = self.PARSER.parse_line(line)
        assert entry is not None
        assert entry.source_ip == "203.0.113.5"
        assert entry.timestamp is not None
        assert entry.timestamp.month == 3
        assert entry.log_source == "syslog"

    def test_parse_empty_line_returns_none(self):
        assert self.PARSER.parse_line("") is None
        assert self.PARSER.parse_line("   ") is None

    def test_parse_line_without_match_still_extracts_ip(self):
        line = "some non-standard log 203.0.113.99 something"
        entry = self.PARSER.parse_line(line)
        assert entry is not None
        assert "203.0.113.99" in entry.all_ips()

    def test_parse_file(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            "Mar 15 10:00:01 host sshd[1]: Failed password from 203.0.113.5\n"
            "Mar 15 10:00:02 host sshd[1]: Accepted from 203.0.113.6\n"
        )
        entries = list(self.PARSER.parse_file(str(log)))
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# ApacheLogParser
# ---------------------------------------------------------------------------

class TestApacheLogParser:
    PARSER = ApacheLogParser()

    COMBINED_LINE = (
        '203.0.113.5 - frank [10/Oct/2000:13:55:36 -0700] '
        '"GET /apache_pb.gif HTTP/1.0" 200 2326 '
        '"http://www.example.com/start.html" '
        '"Mozilla/4.08 [en] (Win98; I ;Nav)"'
    )

    def test_parse_combined(self):
        entry = self.PARSER.parse_line(self.COMBINED_LINE)
        assert entry is not None
        assert entry.source_ip == "203.0.113.5"
        assert entry.timestamp is not None
        assert entry.metadata["status"] == "200"

    def test_parse_empty(self):
        assert self.PARSER.parse_line("") is None

    def test_parse_malformed_still_returns_entry(self):
        entry = self.PARSER.parse_line("not an apache log 203.0.113.7")
        assert entry is not None

    def test_parse_file(self, tmp_path):
        log = tmp_path / "access.log"
        log.write_text(self.COMBINED_LINE + "\n" + self.COMBINED_LINE + "\n")
        entries = list(self.PARSER.parse_file(str(log)))
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# JSONLogParser
# ---------------------------------------------------------------------------

class TestJSONLogParser:
    PARSER = JSONLogParser()

    def test_parse_simple_line(self):
        line = json.dumps({"src_ip": "203.0.113.5", "url": "http://evil.com/x",
                           "timestamp": "2026-03-15T10:00:00Z"})
        entry = self.PARSER.parse_line(line)
        assert entry is not None
        assert entry.source_ip == "203.0.113.5"
        assert entry.url == "http://evil.com/x"
        assert entry.timestamp is not None

    def test_parse_invalid_json_returns_none(self):
        assert self.PARSER.parse_line("not json at all") is None

    def test_parse_array_file(self, tmp_path):
        records = [{"src_ip": f"203.0.113.{i}"} for i in range(3)]
        log = tmp_path / "app.json"
        log.write_text(json.dumps(records))
        entries = list(self.PARSER.parse_file(str(log)))
        assert len(entries) == 3

    def test_parse_ndjson_file(self, tmp_path):
        lines = "\n".join(json.dumps({"src": f"203.0.113.{i}"}) for i in range(4))
        log = tmp_path / "app.ndjson"
        log.write_text(lines)
        entries = list(self.PARSER.parse_file(str(log)))
        assert len(entries) == 4

    def test_hash_extraction(self):
        sha256 = "d" * 64
        line = json.dumps({"sha256": sha256, "event": "file_scan"})
        entry = self.PARSER.parse_line(line)
        assert sha256.lower() in [h.lower() for h in entry.hashes]


# ---------------------------------------------------------------------------
# CEFLogParser
# ---------------------------------------------------------------------------

class TestCEFLogParser:
    PARSER = CEFLogParser()

    CEF_LINE = (
        "CEF:0|SecurityVendor|IDS|1.0|100|Malicious Connection|8|"
        "src=203.0.113.5 dst=198.51.100.1 spt=12345 dpt=80 "
        "request=http://evil.com/payload"
    )

    def test_parse_valid_cef(self):
        entry = self.PARSER.parse_line(self.CEF_LINE)
        assert entry is not None
        assert entry.source_ip == "203.0.113.5"
        assert entry.dest_ip == "198.51.100.1"
        assert entry.url == "http://evil.com/payload"
        assert entry.metadata["vendor"] == "SecurityVendor"

    def test_parse_empty(self):
        assert self.PARSER.parse_line("") is None

    def test_non_cef_returns_none(self):
        assert self.PARSER.parse_line("just a regular log line") is None

    def test_parse_file(self, tmp_path):
        log = tmp_path / "ids.cef"
        log.write_text(self.CEF_LINE + "\n" + self.CEF_LINE + "\n")
        entries = list(self.PARSER.parse_file(str(log)))
        assert len(entries) == 2

    def test_epoch_timestamp(self):
        line = (
            "CEF:0|V|P|1|1|Test|5|"
            "src=203.0.113.5 rt=1741824000000"
        )
        entry = self.PARSER.parse_line(line)
        assert entry is not None
        assert entry.timestamp is not None
        assert entry.timestamp.tzinfo is not None
