"""Tests for ioc_engine.storage."""

import pytest
from datetime import datetime, timezone

from ioc_engine.models import IOC, IOCType, Severity
from ioc_engine.storage import IOCStorage


@pytest.fixture
def store():
    return IOCStorage(":memory:")


def make_ioc(value="1.2.3.4", ioc_type=IOCType.IP, source="test", confidence=70):
    return IOC(ioc_type=ioc_type, value=value, source=source, confidence=confidence,
               tags=["test"])


class TestIOCStorage:
    def test_upsert_and_lookup(self, store):
        ioc = make_ioc("1.2.3.4")
        store.upsert(ioc)
        result = store.lookup("1.2.3.4")
        assert result is not None
        assert result.value == "1.2.3.4"

    def test_lookup_case_insensitive(self, store):
        ioc = make_ioc("EVIL.COM", ioc_type=IOCType.DOMAIN)
        store.upsert(ioc)
        result = store.lookup("evil.com")
        assert result is not None

    def test_lookup_missing_returns_none(self, store):
        assert store.lookup("9.9.9.9") is None

    def test_upsert_merges_tags(self, store):
        ioc1 = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="s", tags=["a"])
        ioc2 = IOC(ioc_type=IOCType.IP, value="1.2.3.4", source="s", tags=["b"])
        store.upsert(ioc1)
        store.upsert(ioc2)
        result = store.lookup("1.2.3.4")
        assert set(result.tags) == {"a", "b"}

    def test_count(self, store):
        assert store.count() == 0
        store.upsert(make_ioc("1.1.1.1"))
        store.upsert(make_ioc("2.2.2.2"))
        assert store.count() == 2

    def test_bulk_upsert(self, store):
        iocs = [make_ioc(f"10.0.0.{i}") for i in range(5)]
        n = store.bulk_upsert(iocs)
        assert n == 5
        assert store.count() == 5

    def test_bulk_upsert_deduplicates(self, store):
        ioc = make_ioc("1.2.3.4")
        store.bulk_upsert([ioc, ioc, ioc])
        assert store.count() == 1

    def test_lookup_many(self, store):
        store.upsert(make_ioc("1.1.1.1"))
        store.upsert(make_ioc("2.2.2.2"))
        results = store.lookup_many(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        assert len(results) == 2

    def test_list_all_no_filter(self, store):
        store.upsert(make_ioc("1.1.1.1", ioc_type=IOCType.IP))
        store.upsert(make_ioc("evil.com", ioc_type=IOCType.DOMAIN))
        assert len(store.list_all()) == 2

    def test_list_all_filter_by_type(self, store):
        store.upsert(make_ioc("1.1.1.1", ioc_type=IOCType.IP))
        store.upsert(make_ioc("evil.com", ioc_type=IOCType.DOMAIN))
        ips = store.list_all(ioc_type=IOCType.IP)
        assert len(ips) == 1
        assert ips[0].ioc_type == IOCType.IP

    def test_list_all_filter_by_confidence(self, store):
        store.upsert(make_ioc("1.1.1.1", confidence=30))
        store.upsert(make_ioc("2.2.2.2", confidence=80))
        results = store.list_all(min_confidence=50)
        assert len(results) == 1

    def test_list_all_filter_by_source(self, store):
        store.upsert(make_ioc("1.1.1.1", source="otx"))
        store.upsert(make_ioc("2.2.2.2", source="local"))
        results = store.list_all(source="otx")
        assert len(results) == 1 and results[0].source == "otx"

    def test_delete(self, store):
        store.upsert(make_ioc("1.2.3.4"))
        assert store.delete("1.2.3.4") is True
        assert store.lookup("1.2.3.4") is None

    def test_delete_missing_returns_false(self, store):
        assert store.delete("9.9.9.9") is False

    def test_clear(self, store):
        store.bulk_upsert([make_ioc(f"10.0.0.{i}") for i in range(3)])
        store.clear()
        assert store.count() == 0

    def test_roundtrip_all_types(self, store):
        iocs = [
            make_ioc("1.2.3.4", IOCType.IP),
            make_ioc("evil.com", IOCType.DOMAIN),
            make_ioc("http://evil.com/x", IOCType.URL),
            make_ioc("a" * 32, IOCType.HASH_MD5),
            make_ioc("b" * 40, IOCType.HASH_SHA1),
            make_ioc("c" * 64, IOCType.HASH_SHA256),
            make_ioc("x@evil.com", IOCType.EMAIL),
        ]
        store.bulk_upsert(iocs)
        assert store.count() == 7
        for ioc in iocs:
            result = store.lookup(ioc.value)
            assert result is not None
            assert result.ioc_type == ioc.ioc_type
