# IOC Correlation Engine

> **Automated Indicators of Compromise (IOC) aggregation and log correlation for Python.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Overview

The **IOC Correlation Engine** is a Python library and command-line tool that:

1. **Aggregates** Indicators of Compromise (IOCs) from multiple threat-intelligence sources — [AlienVault OTX](https://otx.alienvault.com/), [AbuseIPDB](https://www.abuseipdb.com/), [URLhaus](https://urlhaus.abuse.ch/), and local CSV/JSON files.
2. **Stores** deduplicated IOCs in a local SQLite database.
3. **Parses** common log formats — Syslog, Apache/Nginx Combined, JSON, and CEF (ArcSight).
4. **Correlates** log observables (IPs, domains, URLs, file hashes, e-mails) against the stored IOC database.
5. **Reports** findings in JSON, CSV, or self-contained HTML formats.

Designed for security analysts, incident responders, and home-lab enthusiasts who need a lightweight, dependency-minimal tool that works entirely offline once feeds are cached.

---

## Features

| Feature | Details |
|---|---|
| **IOC Types** | IPv4/IPv6, Domain, URL, MD5/SHA1/SHA256, E-mail |
| **Threat Feeds** | AlienVault OTX, AbuseIPDB, URLhaus, local CSV/JSON |
| **Log Parsers** | Syslog, Apache/Nginx Combined, JSON lines, CEF |
| **Storage** | SQLite (file or in-memory), with upsert & bulk-load |
| **Reports** | JSON, CSV, HTML (self-contained, no external assets) |
| **CLI** | `ioc-engine` command with `fetch`, `correlate`, `report`, `list` sub-commands |

---

## Installation

```bash
# Clone the repo
git clone https://github.com/prizrak2033/musical-octo-couscous.git
cd musical-octo-couscous

# Install dependencies
pip install -r requirements.txt

# Optional: install the package in editable mode
pip install -e .
```

### Requirements

- Python 3.9+
- `requests` — HTTP calls to threat-feed APIs
- `pyyaml` — YAML configuration file support
- `jinja2` — HTML report rendering

---

## Quick Start

### 1 — Configure API keys (optional)

Copy the sample config and fill in your keys:

```bash
cp config.yaml.example config.yaml
# Edit config.yaml and add your OTX / AbuseIPDB keys
```

Or export environment variables:

```bash
export OTX_API_KEY="your_otx_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

### 2 — Fetch IOCs

```bash
# Fetch from all configured sources and populate the local database
python main.py fetch --config config.yaml

# Fetch from a specific source only
python main.py fetch --source urlhaus

# Load IOCs from a local file
python main.py fetch --source local --file iocs/my_iocs.csv
```

### 3 — Correlate against logs

```bash
# Auto-detect log format
python main.py correlate /var/log/auth.log

# Specify log format explicitly
python main.py correlate /var/log/nginx/access.log --format apache

# Correlate a directory of log files
python main.py correlate /var/log/myapp/ --format json
```

### 4 — Generate a report

```bash
# JSON report (default)
python main.py report --output report.json

# HTML report
python main.py report --format html --output report.html

# CSV report
python main.py report --format csv --output report.csv
```

---

## Project Structure

```
ioc_engine/
├── __init__.py
├── models.py          # IOC, LogEntry, CorrelationMatch dataclasses
├── storage.py         # SQLite-backed IOC store
├── correlator.py      # Core matching engine
├── reporter.py        # JSON / CSV / HTML report generation
├── sources/
│   ├── base.py        # Abstract BaseIOCSource
│   ├── alienvault.py  # AlienVault OTX
│   ├── abuseipdb.py   # AbuseIPDB blacklist
│   ├── urlhaus.py     # URLhaus CSV feed
│   └── local_file.py  # Local CSV / JSON file
└── parsers/
    ├── base.py        # Abstract BaseLogParser + observable extractor
    ├── syslog.py      # RFC 3164 / BSD syslog
    ├── apache.py      # Apache/Nginx Combined Log Format
    ├── json_log.py    # JSON-lines logs
    └── cef.py         # ArcSight Common Event Format

main.py                # CLI entry point
config.yaml.example    # Annotated sample configuration
requirements.txt
tests/
```

---

## Configuration

`config.yaml` controls every aspect of the engine:

```yaml
database:
  path: ioc_engine.db        # use ":memory:" for ephemeral runs

sources:
  alienvault_otx:
    enabled: true
    api_key: ""              # or set OTX_API_KEY env var
    limit: 1000
  abuseipdb:
    enabled: true
    api_key: ""              # or set ABUSEIPDB_API_KEY env var
    confidence_minimum: 90
    limit: 500
  urlhaus:
    enabled: true
    limit: 1000
  local_file:
    enabled: false
    path: ""

correlator:
  min_confidence: 50         # ignore IOCs below this confidence score

reporter:
  default_format: json
```

---

## IOC Sources

### AlienVault OTX
Fetches pulse subscriptions via the [OTX DirectConnect API](https://otx.alienvault.com/api).
Requires a free account and API key.

### AbuseIPDB
Downloads the IP blacklist from the [AbuseIPDB v2 API](https://docs.abuseipdb.com/).
Requires a free account and API key.

### URLhaus (abuse.ch)
Downloads the [recent URL feed](https://urlhaus.abuse.ch/downloads/csv_recent/) — no key required.

### Local File (CSV / JSON)
Loads IOCs from a local file. CSV columns: `type,value[,confidence,severity,tags,description]`.

---

## Log Parsers

| Format | Example |
|---|---|
| **Syslog** | `Mar 15 10:00:01 myhost sshd[1234]: Failed password from 1.2.3.4` |
| **Apache/Nginx** | `1.2.3.4 - - [15/Mar/2026:10:00:01 +0000] "GET /path HTTP/1.1" 200 1234` |
| **JSON** | `{"timestamp": "...", "src_ip": "1.2.3.4", "url": "http://evil.com/x"}` |
| **CEF** | `CEF:0|Vendor|Product|1.0|100|Name|5|src=1.2.3.4 dst=5.6.7.8` |

---

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## License

[MIT](LICENSE) — see the `LICENSE` file for details.
