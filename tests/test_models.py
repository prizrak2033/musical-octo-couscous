"""Tests for ioc_engine.models."""

import pytest
from datetime import datetime, timezone

from ioc_engine.models import IOC, IOCType, Severity, LogEntry, CorrelationMatch


class TestIOC:
    def test_basic_creation(self):
        ioc = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="test")
        assert ioc.ioc_type == IOCType.IP
        assert ioc.value == "1.2.3.4"
        assert ioc.source == "test"
        assert ioc.confidence == 50

    def test_value_normalised_to_lowercase(self):
        ioc = IOC(ioc_type=IOCType.DOMAIN, value="Evil.COM", source="test")
        assert ioc.value == "evil.com"

    def test_value_stripped(self):
        ioc = IOC(ioc_type=IOCType.IP, value="  10.0.0.1  ", source="test")
        assert ioc.value == "10.0.0.1"

    def test_string_type_coerced(self):
        ioc = IOC(ioc_type="ip", value="1.2.3.4", source="test")
        assert ioc.ioc_type == IOCType.IP

    def test_string_severity_coerced(self):
        ioc = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="test", severity="high")
        assert ioc.severity == Severity.HIGH

    def test_unique_id_stable(self):
        a = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="src1")
        b = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="src2")
        assert a.unique_id == b.unique_id

    def test_unique_id_differs_by_type(self):
        a = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="s")
        b = IOC(ioc_type=IOCType.DOMAIN, value="1.2.3.4", source="s")
        assert a.unique_id != b.unique_id

    def test_to_dict_keys(self):
        ioc = IOC(ioc_type=IOCType.URL, value="http://evil.com", source="s")
        d = ioc.to_dict()
        assert set(d.keys()) == {
            "ioc_type", "value", "source", "confidence", "severity",
            "tags", "description", "first_seen", "last_seen", "metadata",
        }

    def test_to_dict_serialisable(self):
        import json
        ioc = IOC(ioc_type=IOCType.HASH_SHA256, value="a" * 64, source="s",
                  tags=["malware"], severity=Severity.CRITICAL)
        json.dumps(ioc.to_dict())  # must not raise


class TestLogEntry:
    def test_all_ips_deduped(self):
        entry = LogEntry(
            raw="line",
            source_ip="1.2.3.4",
            dest_ip="5.6.7.8",
            extra_ips=["1.2.3.4", "9.9.9.9"],
        )
        ips = entry.all_ips()
        assert ips.count("1.2.3.4") == 1
        assert "5.6.7.8" in ips
        assert "9.9.9.9" in ips

    def test_all_domains_deduped(self):
        entry = LogEntry(raw="x", domain="evil.com", extra_domains=["evil.com", "bad.org"])
        domains = entry.all_domains()
        assert domains.count("evil.com") == 1
        assert "bad.org" in domains

    def test_to_dict(self):
        import json
        entry = LogEntry(raw="test line", source_ip="1.2.3.4")
        d = entry.to_dict()
        assert d["source_ip"] == "1.2.3.4"
        json.dumps(d)  # must be serialisable


class TestCorrelationMatch:
    def test_to_dict(self):
        import json
        ioc = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="s")
        entry = LogEntry(raw="raw line", source_ip="1.2.3.4")
        match = CorrelationMatch(ioc=ioc, log_entry=entry,
                                 matched_field="source_ip", matched_value="1.2.3.4")
        d = match.to_dict()
        assert "ioc" in d and "log_entry" in d
        json.dumps(d)
