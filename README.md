# DFIR Log Parser 🔐

A Python-based **Digital Forensics & Incident Response (DFIR)** tool that parses Linux login logs and Windows Security Event Logs into CSV or JSON format with **optional anomaly detection**.

## Features 🚀

- **Parse Linux logs**: `utmp`, `wtmp`, `btmp`
- **Parse Windows logs**: `Security.evtx`
- **Export results**: CSV or JSON format
- **Anomaly Detection**:
  - Public IP logins
  - Off-hours logins
  - Repeated failed logins
  - Invalid IP addresses

## Supported Formats 📊

| Log Type | File Extension | Output Formats |
|----------|---------------|----------------|
| Linux utmp/wtmp/btmp | `.log` | CSV, JSON |
| Windows Security | `.evtx` | CSV, JSON |

## Installation 🛠️

```bash
pip install pandas python-evtx utmpx
```
