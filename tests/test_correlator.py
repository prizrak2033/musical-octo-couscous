"""Tests for ioc_engine.correlator."""

import pytest

from ioc_engine.correlator import Correlator
from ioc_engine.models import IOC, IOCType, LogEntry, Severity
from ioc_engine.storage import IOCStorage


def _store(*iocs):
    s = IOCStorage(":memory:")
    s.bulk_upsert(list(iocs))
    return s


def _ip_ioc(value, confidence=80):
    return IOC(ioc_type=IOCType.IP, value=value, source="test", confidence=confidence)


def _domain_ioc(value, confidence=80):
    return IOC(ioc_type=IOCType.DOMAIN, value=value, source="test", confidence=confidence)


def _url_ioc(value, confidence=80):
    return IOC(ioc_type=IOCType.URL, value=value, source="test", confidence=confidence)


def _hash_ioc(value, confidence=80):
    return IOC(ioc_type=IOCType.HASH_SHA256, value=value, source="test", confidence=confidence)


class TestCorrelator:
    def test_ip_match(self):
        store = _store(_ip_ioc("203.0.113.5"))
        c = Correlator(store)
        entry = LogEntry(raw="x", source_ip="203.0.113.5")
        matches = c.correlate_entry(entry)
        assert len(matches) == 1
        assert matches[0].matched_value == "203.0.113.5"
        assert matches[0].matched_field == "source_ip"

    def test_domain_match(self):
        store = _store(_domain_ioc("evil.com"))
        c = Correlator(store)
        entry = LogEntry(raw="x", domain="evil.com")
        matches = c.correlate_entry(entry)
        assert len(matches) == 1

    def test_url_match(self):
        store = _store(_url_ioc("http://evil.com/payload"))
        c = Correlator(store)
        entry = LogEntry(raw="x", url="http://evil.com/payload")
        matches = c.correlate_entry(entry)
        assert len(matches) == 1

    def test_hash_match(self):
        sha = "a" * 64
        store = _store(_hash_ioc(sha))
        c = Correlator(store)
        entry = LogEntry(raw="x", hashes=[sha])
        matches = c.correlate_entry(entry)
        assert len(matches) == 1

    def test_email_match(self):
        ioc = IOC(ioc_type=IOCType.EMAIL, value="bad@evil.com", source="t")
        store = _store(ioc)
        c = Correlator(store)
        entry = LogEntry(raw="x", emails=["bad@evil.com"])
        matches = c.correlate_entry(entry)
        assert len(matches) == 1

    def test_no_match(self):
        store = _store(_ip_ioc("203.0.113.5"))
        c = Correlator(store)
        entry = LogEntry(raw="x", source_ip="8.8.8.8")
        assert c.correlate_entry(entry) == []

    def test_empty_storage(self):
        store = IOCStorage(":memory:")
        c = Correlator(store)
        entry = LogEntry(raw="x", source_ip="203.0.113.5")
        assert c.correlate_entry(entry) == []

    def test_min_confidence_filters(self):
        store = _store(_ip_ioc("203.0.113.5", confidence=30))
        c = Correlator(store, min_confidence=50)
        entry = LogEntry(raw="x", source_ip="203.0.113.5")
        assert c.correlate_entry(entry) == []

    def test_min_confidence_passes(self):
        store = _store(_ip_ioc("203.0.113.5", confidence=80))
        c = Correlator(store, min_confidence=50)
        entry = LogEntry(raw="x", source_ip="203.0.113.5")
        assert len(c.correlate_entry(entry)) == 1

    def test_correlate_entries_multiple(self):
        store = _store(_ip_ioc("203.0.113.5"), _domain_ioc("evil.com"))
        c = Correlator(store)
        entries = [
            LogEntry(raw="a", source_ip="203.0.113.5"),
            LogEntry(raw="b", domain="evil.com"),
            LogEntry(raw="c", source_ip="8.8.8.8"),
        ]
        matches = list(c.correlate_entries(iter(entries)))
        assert len(matches) == 2

    def test_refresh_updates_index(self):
        store = IOCStorage(":memory:")
        c = Correlator(store)
        entry = LogEntry(raw="x", source_ip="203.0.113.5")

        # Before adding IOC — no match
        assert c.correlate_entry(entry) == []

        store.upsert(_ip_ioc("203.0.113.5"))
        c.refresh()

        assert len(c.correlate_entry(entry)) == 1

    def test_extra_ips_matched(self):
        store = _store(_ip_ioc("203.0.113.99"))
        c = Correlator(store)
        entry = LogEntry(raw="x", source_ip="1.1.1.1", extra_ips=["203.0.113.99"])
        matches = c.correlate_entry(entry)
        assert len(matches) == 1

    def test_extra_domains_matched(self):
        store = _store(_domain_ioc("extra.evil.com"))
        c = Correlator(store)
        entry = LogEntry(raw="x", domain="safe.com", extra_domains=["extra.evil.com"])
        matches = c.correlate_entry(entry)
        assert len(matches) == 1
