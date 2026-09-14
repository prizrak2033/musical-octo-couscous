"""Tests for ioc_engine.reporter."""

import csv
import io
import json

import pytest

from ioc_engine.models import IOC, IOCType, Severity, LogEntry, CorrelationMatch
from ioc_engine.reporter import Reporter


def _make_match(ip="203.0.113.5", severity=Severity.HIGH):
    ioc = IOC(ioc_type=IOCType.IP, value=ip, source="test",
              confidence=80, severity=severity, tags=["test"])
    entry = LogEntry(raw="raw log line with some content", source_ip=ip)
    return CorrelationMatch(ioc=ioc, log_entry=entry,
                            matched_field="source_ip", matched_value=ip)


class TestReporter:
    def test_json_output_structure(self):
        match = _make_match()
        r = Reporter([match])
        data = json.loads(r.to_json())
        assert "generated_at" in data
        assert "total_matches" in data
        assert data["total_matches"] == 1
        assert len(data["matches"]) == 1

    def test_json_empty(self):
        r = Reporter([])
        data = json.loads(r.to_json())
        assert data["total_matches"] == 0

    def test_csv_headers(self):
        r = Reporter([_make_match()])
        text = r.to_csv()
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 1
        assert "ioc_value" in rows[0]
        assert "severity" in rows[0]

    def test_csv_empty(self):
        r = Reporter([])
        text = r.to_csv()
        reader = csv.DictReader(io.StringIO(text))
        assert list(reader) == []

    def test_html_output_contains_value(self):
        match = _make_match("203.0.113.55")
        r = Reporter([match])
        html = r.to_html()
        assert "203.0.113.55" in html
        assert "<!DOCTYPE html>" in html

    def test_html_severity_counts(self):
        matches = [
            _make_match("203.0.113.1", Severity.CRITICAL),
            _make_match("203.0.113.2", Severity.HIGH),
            _make_match("203.0.113.3", Severity.HIGH),
        ]
        r = Reporter(matches)
        html = r.to_html()
        assert "CRITICAL" in html
        assert "HIGH" in html

    def test_save_json(self, tmp_path):
        r = Reporter([_make_match()])
        out = tmp_path / "report.json"
        r.save(str(out), fmt="json")
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["total_matches"] == 1

    def test_save_csv(self, tmp_path):
        r = Reporter([_make_match()])
        out = tmp_path / "report.csv"
        r.save(str(out), fmt="csv")
        assert out.exists()
        assert "ioc_value" in out.read_text()

    def test_save_html(self, tmp_path):
        r = Reporter([_make_match()])
        out = tmp_path / "report.html"
        r.save(str(out), fmt="html")
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text()

    def test_save_unknown_format_raises(self, tmp_path):
        r = Reporter([_make_match()])
        with pytest.raises(ValueError, match="Unknown report format"):
            r.save(str(tmp_path / "x.txt"), fmt="xml")

    def test_html_escaping(self):
        ioc = IOC(ioc_type=IOCType.URL, value="http://evil.com/<script>",
                  source="test", confidence=80)
        entry = LogEntry(raw='<b>raw</b> "log"', url="http://evil.com/<script>")
        match = CorrelationMatch(ioc=ioc, log_entry=entry,
                                 matched_field="url",
                                 matched_value="http://evil.com/<script>")
        r = Reporter([match])
        html = r.to_html()
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
