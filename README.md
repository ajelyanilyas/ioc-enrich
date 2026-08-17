# ioc-enrich

[![CI](https://github.com/YOUR_USERNAME/ioc-enrich/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/ioc-enrich/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> **IOC enrichment & triage CLI** — give it an IP, domain, URL, or file hash and it
> queries multiple threat-intelligence sources, aggregates them into a single
> weighted risk verdict, and outputs a clean table / JSON / Markdown report.

Built as a hands-on security-engineering project: it automates the repetitive
"is this indicator malicious?" lookup that SOC analysts do dozens of times a day.

## Demo

```console
$ iocenrich 123.14.127.32

123.14.127.32  (ip)  ->  SUSPICIOUS  (score 0.42)
┌────────────┬───────┬─────────────────────────────────────┐
│ Provider   │ Score │ Detail                              │
├────────────┼───────┼─────────────────────────────────────┤
│ urlhaus    │ 0.85  │ Listed in URLhaus: malware (2 URLs) │
│ virustotal │ 0.05  │ 3/91 engines flagged malicious      │
│ abuseipdb  │ 0.20  │ Abuse confidence 20% (5 reports)    │
└────────────┴───────┴─────────────────────────────────────┘
```

```console
$ iocenrich example.com

example.com  (domain)  ->  CLEAN  (score 0.00)
```

## How it works

```
input (IP / domain / URL / hash)
   → detect IOC type
   → query providers (URLhaus, VirusTotal, AbuseIPDB)
   → weighted aggregate + escalation rule
   → report (table / JSON / Markdown)
```

## Install

```bash
git clone https://github.com/YOUR_USERNAME/ioc-enrich.git
cd ioc-enrich
python -m venv .venv
.venv\Scripts\activate          # Windows  (use: source .venv/bin/activate on macOS/Linux)
pip install -e .
cp .env.example .env            # then add your API keys
```

## Usage

```bash
iocenrich 8.8.8.8                          # table output (default)
iocenrich example.com --output json        # machine-readable JSON
iocenrich "http://bad-url/" --output markdown
iocenrich 1.2.3.4 --save report.md         # write the report to a file
```

## Providers

| Provider    | IOC types             | API key                                   |
|-------------|-----------------------|-------------------------------------------|
| URLhaus     | ip, domain, url, hash | Free Auth-Key — https://auth.abuse.ch     |
| VirusTotal  | ip, domain, url, hash | Free — https://www.virustotal.com         |
| AbuseIPDB   | ip                    | Free — https://www.abuseipdb.com          |

Keys live in a local `.env` file (git-ignored). A provider whose key is missing
reports "key not set" and is skipped — the tool still works with whatever is set.

## Scoring

Each provider returns a `0.0`–`1.0` score. The verdict combines them with:

- **Weighted average** — providers are trusted differently (URLhaus lists
  *confirmed* malware distribution, so it's weighted higher than crowd-sourced
  AbuseIPDB).
- **Escalation rule** — if any single provider is highly confident
  (score ≥ 0.8), the verdict can't fall to CLEAN, even if quieter sources drag
  the average down. In security, missing a real threat costs more than a false
  alarm.

| Weighted score | Verdict     |
|----------------|-------------|
| `< 0.2`        | CLEAN       |
| `0.2 – 0.6`    | SUSPICIOUS  |
| `≥ 0.6`        | MALICIOUS   |

## Architecture

Providers implement a common `BaseProvider` interface (`supports()` + `query()`),
so adding a new intel source is a single small file — no changes to the engine.

```
src/iocenrich/
├── cli.py            # Typer CLI + rich output
├── detector.py       # classify raw input into an IOC type
├── engine.py         # orchestrates providers, isolates failures
├── scoring.py        # weighted aggregation + escalation
├── models.py         # dataclasses / enums
├── providers/        # urlhaus, virustotal, abuseipdb (+ base interface)
└── report/           # json / markdown renderers
```

## Development

```bash
pip install -e .
pytest          # 14 tests, HTTP mocked (no network needed)
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
