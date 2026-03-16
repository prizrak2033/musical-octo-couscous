"""Tests for IOC sources (unit-level — external HTTP is mocked)."""

import csv
import io
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from ioc_engine.models import IOCType
from ioc_engine.sources.alienvault import AlienVaultOTXSource
from ioc_engine.sources.abuseipdb import AbuseIPDBSource
from ioc_engine.sources.urlhaus import URLhausSource
from ioc_engine.sources.local_file import LocalFileSource


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

def _make_otx_pulse(ip="203.0.113.5"):
    return {
        "id": "pulse1",
        "name": "Test Pulse",
        "description": "test",
        "tags": ["malware"],
        "indicators": [
            {"type": "IPv4", "indicator": ip},
            {"type": "domain", "indicator": "evil.com"},
            {"type": "URL", "indicator": "http://evil.com/x"},
        ],
    }


class TestAlienVaultOTXSource:
    def _make_session(self, pulse):
        session = MagicMock()
        resp = MagicMock()
        resp.json.side_effect = [
            {"results": [pulse], "next": None},
        ]
        resp.raise_for_status = MagicMock()
        session.get.return_value = resp
        session.headers = {}
        return session

    def test_fetch_returns_iocs(self):
        pulse = _make_otx_pulse()
        source = AlienVaultOTXSource(api_key="fakekey",
                                     session=self._make_session(pulse))
        iocs = source.fetch()
        assert len(iocs) == 3
        types = {i.ioc_type for i in iocs}
        assert IOCType.IP in types
        assert IOCType.DOMAIN in types
        assert IOCType.URL in types

    def test_fetch_no_api_key_returns_empty(self):
        source = AlienVaultOTXSource(api_key="")
        iocs = source.fetch()
        assert iocs == []

    def test_fetch_http_error_returns_empty(self):
        session = MagicMock()
        session.get.side_effect = requests.RequestException("timeout")
        session.headers = {}
        source = AlienVaultOTXSource(api_key="key", session=session)
        iocs = source.fetch()
        assert iocs == []

    def test_unknown_indicator_type_skipped(self):
        pulse = {
            "id": "p1", "name": "x", "description": "", "tags": [],
            "indicators": [{"type": "UnknownType", "indicator": "x"}],
        }
        source = AlienVaultOTXSource(api_key="k",
                                     session=self._make_session(pulse))
        assert source.fetch() == []


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

class TestAbuseIPDBSource:
    def _make_session(self, entries):
        session = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"data": entries}
        resp.raise_for_status = MagicMock()
        session.get.return_value = resp
        session.headers = {}
        return session

    def test_fetch_returns_iocs(self):
        entries = [
            {"ipAddress": "203.0.113.5", "abuseConfidenceScore": 95,
             "countryCode": "US", "usageType": "Data Center", "isp": "ISP",
             "domain": "isp.com", "totalReports": 10},
        ]
        source = AbuseIPDBSource(api_key="key", session=self._make_session(entries))
        iocs = source.fetch()
        assert len(iocs) == 1
        assert iocs[0].ioc_type == IOCType.IP
        assert iocs[0].confidence == 95

    def test_fetch_no_api_key_returns_empty(self):
        source = AbuseIPDBSource(api_key="")
        assert source.fetch() == []

    def test_fetch_http_error_returns_empty(self):
        session = MagicMock()
        session.get.side_effect = requests.RequestException("err")
        session.headers = {}
        source = AbuseIPDBSource(api_key="k", session=session)
        assert source.fetch() == []

    def test_severity_mapping(self):
        from ioc_engine.sources.abuseipdb import _score_to_severity
        from ioc_engine.models import Severity
        assert _score_to_severity(95) == Severity.CRITICAL
        assert _score_to_severity(80) == Severity.HIGH
        assert _score_to_severity(60) == Severity.MEDIUM
        assert _score_to_severity(20) == Severity.LOW


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

_CSV_CONTENT = """\
# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
1,2026-01-01 10:00:00,http://evil.com/a,online,malware_download,malware,https://urlhaus.abuse.ch/1,reporter
2,2026-01-02 10:00:00,http://bad.org/b,online,phishing,phishing,https://urlhaus.abuse.ch/2,reporter
"""


class TestURLhausSource:
    def _make_session(self, content: bytes):
        session = MagicMock()
        resp = MagicMock()
        resp.content = content
        resp.raise_for_status = MagicMock()
        session.get.return_value = resp
        return session

    def test_fetch_plain_csv(self):
        source = URLhausSource(session=self._make_session(_CSV_CONTENT.encode()))
        iocs = source.fetch()
        assert len(iocs) == 2
        assert all(i.ioc_type == IOCType.URL for i in iocs)

    def test_fetch_http_error_returns_empty(self):
        session = MagicMock()
        session.get.side_effect = requests.RequestException("err")
        source = URLhausSource(session=session)
        assert source.fetch() == []

    def test_limit_respected(self):
        rows = "\n".join(
            f"{i},2026-01-01,http://evil{i}.com/x,online,malware,tag,h,r"
            for i in range(20)
        )
        content = "# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n" + rows
        source = URLhausSource(session=self._make_session(content.encode()), limit=5)
        iocs = source.fetch()
        assert len(iocs) == 5


# ---------------------------------------------------------------------------
# LocalFileSource
# ---------------------------------------------------------------------------

class TestLocalFileSource:
    def test_load_csv(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("type,value,confidence,severity\nip,203.0.113.5,80,high\ndomain,evil.com,70,medium\n")
        source = LocalFileSource(str(f))
        iocs = source.fetch()
        assert len(iocs) == 2
        types = {i.ioc_type for i in iocs}
        assert IOCType.IP in types
        assert IOCType.DOMAIN in types

    def test_load_json_list(self, tmp_path):
        data = [
            {"type": "ip", "value": "203.0.113.5"},
            {"type": "domain", "value": "evil.com"},
        ]
        f = tmp_path / "iocs.json"
        f.write_text(json.dumps(data))
        source = LocalFileSource(str(f))
        iocs = source.fetch()
        assert len(iocs) == 2

    def test_load_json_dict_wrapper(self, tmp_path):
        data = {"iocs": [{"type": "ip", "value": "203.0.113.7"}]}
        f = tmp_path / "iocs.json"
        f.write_text(json.dumps(data))
        source = LocalFileSource(str(f))
        iocs = source.fetch()
        assert len(iocs) == 1

    def test_missing_file_returns_empty(self, tmp_path):
        source = LocalFileSource(str(tmp_path / "nonexistent.csv"))
        assert source.fetch() == []

    def test_unknown_type_skipped(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("type,value\nweird_type,somevalue\nip,203.0.113.5\n")
        source = LocalFileSource(str(f))
        iocs = source.fetch()
        assert len(iocs) == 1

    def test_missing_value_skipped(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("type,value\nip,\ndomain,evil.com\n")
        source = LocalFileSource(str(f))
        iocs = source.fetch()
        assert len(iocs) == 1

    def test_tags_from_csv(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("type,value,tags\nip,203.0.113.5,\"malware,ransomware\"\n")
        source = LocalFileSource(str(f))
        iocs = source.fetch()
        assert "malware" in iocs[0].tags
        assert "ransomware" in iocs[0].tags
