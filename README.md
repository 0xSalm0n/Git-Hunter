<h1 align="center">Git-Hunter</h1>

<p align="center">
  <b>Production-Grade GitHub Secret Reconnaissance Engine</b><br>
  <i>Automated credential extraction, validation, and stealth operation</i>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License"></a>
  <a href="#features"><img src="https://img.shields.io/badge/engine-TruffleHog-FF6B35?style=for-the-badge" alt="TruffleHog"></a>
  <a href="#stealth-mode"><img src="https://img.shields.io/badge/mode-stealth-blueviolet?style=for-the-badge" alt="Stealth"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#scan-modes">Scan Modes</a> •
  <a href="#usage">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#configuration">Configuration</a>
</p>

---

## Overview

**Git-Hunter** is an offensive security tool designed for large-scale GitHub reconnaissance. It automates the entire lifecycle of credential hunting — from enumerating repositories across organizations and users, to cloning, scanning for secrets, validating live credentials, and producing actionable reports.

Built for red teamers, penetration testers, and security researchers who need a reliable, memory-efficient, and stealthy pipeline to surface exposed credentials at scale.

### Why Git-Hunter?

| Problem | Git-Hunter's Answer |
|---|---|
| Manual secret scanning doesn't scale | Automated 5-phase pipeline handles thousands of repos |
| TruffleHog alone misses context | Dual-engine architecture (TruffleHog + regex fallback) with entropy analysis |
| Found secrets may be rotated | Built-in credential validators for AWS, GitHub, Slack, Stripe, OpenAI, Google |
| Rate limits kill long scans | Multi-token pool with automatic rotation and health tracking |
| Scanning leaves fingerprints | Stealth mode with proxy rotation, jittered delays, and user-agent randomization |
| Large orgs cause OOM crashes | Memory-aware scanning with streaming I/O and configurable hard limits |
| Interrupted scans lose progress | SQLite-backed state with full resume capability |

---

## Features

### 🔍 Dual Detection Engine
- **TruffleHog** (primary) — Industry-standard secret detection with verified credential checking
- **Regex** (fallback) — 40+ built-in patterns covering AWS, GitHub, Slack, Stripe, OpenAI, Azure, private keys, JWTs, connection strings, and more
- **Entropy Analysis** — Shannon entropy scanner catches high-randomness strings near sensitive keywords

### 🌐 Comprehensive Enumeration
- GitHub **REST** and **GraphQL** API support for efficient bulk fetching
- Target types: **organizations**, **users**, **single repos**, **search queries**, **file lists**
- Smart filtering by language, size, star count, fork status, archive status, last push date
- Priority-based scanning order (configurable language priority)

### ✅ Credential Validation
- Live validation for **AWS** (STS), **GitHub** (PAT/OAuth), **Slack**, **Stripe**, **Google API**, and **OpenAI**
- Parallel batch validation with configurable concurrency
- Privilege level assessment and high-value secret flagging

### 🥷 Stealth Operations
- **Proxy rotation** (SOCKS5/HTTP) with health tracking
- **Jittered delays** between operations (configurable min/max)
- **User-Agent randomization** across multiple Git client versions
- Randomized repository clone order

### 💾 State Management & Resume
- SQLite database with WAL mode for crash-safe persistence
- Full scan resume after interruption (`--resume-scan`)
- AES-256 encryption for stored secret values (optional)
- Configurable redaction mode (`--no-store-secrets`)

### 📊 Multi-Format Reporting
- **JSON** — Machine-readable, full detail
- **Markdown** — Human-friendly with summary tables
- **CSV** — Spreadsheet-compatible for triage workflows
- Rich CLI summary with high-value secret alerts

### ⚡ Performance & Memory
- Streaming `git log` parsing (no buffering hundreds of MB)
- Entry-by-entry archive scanning (ZIP/TAR) without full extraction
- Configurable memory hard/soft limits with automatic GC
- Parallel cloning with semaphore-based concurrency control

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Git** (available on PATH)
- **TruffleHog** (optional but recommended — auto-falls back to regex if missing)

### Installation

```bash
# Clone the repository
git clone https://github.com/0xSalm0n/Git-Hunter.git
cd Git-Hunter

# Install dependencies
pip install -r requirements.txt
```

### Install TruffleHog

TruffleHog is the primary detection engine. Install it separately:

```bash
# macOS / Linux
brew install trufflehog

# Go install
go install github.com/trufflesecurity/trufflehog/v3@latest

# Or download from releases:
# https://github.com/trufflesecurity/trufflehog/releases
```

### Set Up a GitHub Token

```bash
# Option 1: Environment variable
export GITHUB_TOKEN=ghp_your_token_here

# Option 2: Tokens file (one per line, supports multiple tokens)
echo "ghp_token_1" > tokens.txt
echo "ghp_token_2" >> tokens.txt
```

### Run Your First Scan

```bash
python ghrecon.py scan myorg
```

---

## Scan Modes

Git-Hunter supports three scan modes that control the detection engine behavior:

| Mode | Engine | Speed | Accuracy | Validation |
|------|--------|-------|----------|------------|
| `verified` | TruffleHog `--only-verified` | Moderate | **Highest** | Skipped (TruffleHog pre-verified) |
| `full` | TruffleHog (all findings) | Faster | Noisier | Phase 4 runs |
| `deep` | TruffleHog + regex fallback | Slowest | **Maximum coverage** | Phase 4 runs |

```bash
# Default: only verified secrets (highest signal-to-noise)
python ghrecon.py scan myorg

# All TruffleHog findings, not just verified
python ghrecon.py scan myorg --mode full

# Maximum coverage: TruffleHog first, regex fallback if 0 findings
python ghrecon.py scan myorg --mode deep

# Regex-only (no TruffleHog dependency)
python ghrecon.py scan myorg --engine regex
```

---

## Usage

### Scan Command

```bash
python ghrecon.py scan <target> [options]
```

#### Target Types

| Target | Example | Auto-Detection |
|--------|---------|----------------|
| Organization | `python ghrecon.py scan google` | Default |
| User | `python ghrecon.py scan --type user torvalds` | Needs `--type` or auto |
| Repository URL | `python ghrecon.py scan https://github.com/user/repo` | Auto-detected |
| Search Query | `python ghrecon.py scan --type search "org:google language:python"` | Needs `--type` |
| File (URL list) | `python ghrecon.py scan --type file repos.txt` | Needs `--type` |

#### Key Options

```bash
# Detection
--engine trufflehog|regex     # Detection engine (default: trufflehog)
--mode verified|full|deep     # Scan mode (default: verified)

# Scope
--max-repos 50                # Limit number of repos scanned
--max-size 200                # Skip repos larger than N MB
--depth shallow|medium|full   # Git clone depth
--skip-forks / --include-forks
--skip-archived / --include-archived
--scan-branches / --no-branches
--scan-actions                # Scan GitHub Actions logs/artifacts
--scan-prs                    # Scan closed/merged PRs

# Authentication
--tokens tokens.txt           # Path to tokens file

# Stealth
--stealth                     # Enable stealth mode
--proxy-list proxies.txt      # SOCKS5/HTTP proxy list

# Output
--output-format json,markdown,csv
--output-dir ./scans
--no-store-secrets            # Don't persist raw secret values
--keep-repos                  # Keep cloned repos after scan

# Resume
--resume-scan <scan_id>       # Resume an interrupted scan

# Parallelism
--parallel 8                  # Concurrent clone workers
```

#### Examples

```bash
# Full stealth scan of an organization
python ghrecon.py scan target-org --stealth --tokens tokens.txt --proxy-list proxies.txt

# Deep scan of a single repository
python ghrecon.py scan https://github.com/user/repo --mode deep

# Search-based scan with limits
python ghrecon.py scan --type search "org:target language:python" --max-repos 50

# Regex-only scan without TruffleHog
python ghrecon.py scan myorg --engine regex --mode full

# Resume an interrupted scan
python ghrecon.py --resume-scan 20250422_143522_myorg
```

### Export Command

```bash
# Export results from a completed scan
python ghrecon.py export <scan_id> --format json
python ghrecon.py export <scan_id> --format csv --validated-only
python ghrecon.py export <scan_id> --format markdown
```

### Status Command

```bash
# Check the status of a specific scan
python ghrecon.py status <scan_id>

# Check the latest scan
python ghrecon.py status
```

---

## Architecture

### Pipeline Overview

Git-Hunter operates as a 5-phase pipeline, with each phase persisted to SQLite for crash-safe resumption:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Git-Hunter Pipeline                        │
├─────────────┬─────────────┬──────────────┬───────────┬─────────────┤
│   Phase 1   │   Phase 2   │   Phase 3    │  Phase 4  │   Phase 5   │
│ Enumeration │   Cloning   │  Detection   │ Validation│  Reporting  │
│             │             │              │           │             │
│ REST/GraphQL│ Async Git   │ TruffleHog   │ AWS STS   │ JSON        │
│ API calls   │ clone with  │ → Normalize  │ GitHub    │ Markdown    │
│ + filtering │ proxy/      │ → Deduplicate│ Slack     │ CSV         │
│ + priority  │ stealth     │ → Store      │ Stripe    │ + Rich CLI  │
│   scoring   │ support     │              │ OpenAI    │   summary   │
│             │             │ Regex        │ Google    │             │
│             │             │ fallback     │           │             │
└─────────────┴─────────────┴──────────────┴───────────┴─────────────┘
```

### Project Structure

```
Git-Hunter/
├── ghrecon.py                 # Entry point
├── config.yaml                # Default configuration
├── requirements.txt           # Python dependencies
│
├── ghrecon/
│   ├── __init__.py            # Package metadata & version
│   ├── cli.py                 # Typer CLI with Rich output
│   ├── config.py              # Pydantic config loader
│   │
│   ├── core/
│   │   ├── enumerator.py      # GitHub API enumeration (REST + GraphQL)
│   │   ├── cloner.py          # Async git clone with stealth & retry
│   │   ├── scanner.py         # Regex + entropy secret scanner
│   │   ├── validator.py       # Credential validation orchestrator
│   │   ├── analyzer.py        # Dependency confusion, CI/CD, timelines
│   │   │
│   │   ├── detection/
│   │   │   ├── base.py        # Abstract DetectionEngine interface
│   │   │   ├── trufflehog_engine.py  # TruffleHog CLI wrapper
│   │   │   └── regex_engine.py       # Regex fallback engine
│   │   │
│   │   └── processing/
│   │       ├── normalizer.py  # Unified finding schema transformer
│   │       └── deduplicator.py # Fingerprint-based deduplication
│   │
│   ├── validators/
│   │   ├── aws.py             # AWS STS GetCallerIdentity
│   │   ├── github_val.py      # GitHub /user endpoint
│   │   ├── slack.py           # Slack auth.test
│   │   ├── stripe.py          # Stripe /v1/balance
│   │   ├── google.py          # Google API validation
│   │   └── openai_val.py      # OpenAI /v1/models
│   │
│   ├── reporting/
│   │   ├── json_report.py     # JSON report generator
│   │   ├── markdown_report.py # Markdown report generator
│   │   └── csv_report.py      # CSV report generator
│   │
│   ├── patterns/
│   │   └── secrets.yaml       # Extensible regex pattern definitions
│   │
│   └── utils/
│       ├── db.py              # SQLite state management with encryption
│       ├── logger.py          # Structured logging setup
│       ├── token_pool.py      # GitHub token rotation with health tracking
│       └── proxy.py           # SOCKS5/HTTP proxy manager
```

### Design Decisions

1. **Single engine per repo** — Only one detection engine runs per repository (no parallel TruffleHog + regex)
2. **Raw output never stored** — All findings pass through the normalizer before reaching the database
3. **Regex is fallback only** — In `deep` mode, regex triggers only when TruffleHog returns zero findings
4. **Validation is mode-dependent** — In `verified` mode, TruffleHog already validates credentials, so Phase 4 is skipped
5. **Auto-fallback** — If TruffleHog binary is not found, Git-Hunter automatically falls back to the regex engine with a warning
6. **Non-destructive DB migration** — Existing databases get new columns via `ALTER TABLE` (no data loss)

---

## Configuration

### Config File (`config.yaml`)

Git-Hunter loads configuration from `config.yaml` with CLI arguments taking precedence:

```yaml
github:
  tokens_file: tokens.txt       # One GitHub token per line
  graphql_enabled: true          # Use GraphQL for faster enumeration

scanning:
  parallel_jobs: 8               # Concurrent clone/scan workers
  clone_depth: 1                 # 1 = shallow, 0 = full history
  max_repo_size_mb: 500          # Skip repos larger than this
  scan_branches: true            # Scan all remote branches
  skip_forks: true               # Skip forked repositories
  skip_archived: true            # Skip archived repositories
  max_repos: 0                   # 0 = unlimited
  priority_languages:            # Scanned first
    - Python
    - JavaScript
    - Go
    - TypeScript

stealth:
  enabled: false                 # Enable stealth mode
  proxy_list: proxies.txt        # One proxy per line (socks5://host:port)
  min_delay: 3                   # Min delay between operations (seconds)
  max_delay: 15                  # Max delay between operations (seconds)

validation:
  enabled: true                  # Validate discovered credentials
  validate_aws: true
  validate_github: true
  validate_slack: true
  validate_stripe: true
  validate_google: true
  validate_openai: true
  timeout: 15                    # Per-credential timeout (seconds)

output:
  formats: [json, markdown, csv]
  directory: ./scans
  database: ghrecon.db
  no_store_secrets: false        # Set true to store hashes only
  keep_repos: false              # Delete cloned repos after scan
  encryption_key: null           # AES-256 key for secret encryption
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub personal access token (fallback if no tokens file) |
| `GHRECON_MEM_LIMIT_MB` | Memory hard limit in MB (default: `1500`) |

### Custom Patterns

Add custom regex patterns by editing `ghrecon/patterns/secrets.yaml`:

```yaml
patterns:
  my_internal_key: 'MYCO_[a-zA-Z0-9]{32}'
  custom_api_token: 'custom-token-[0-9a-f]{64}'
```

---

## Supported Secret Types

<details>
<summary><b>Click to expand full list (40+ patterns)</b></summary>

| Category | Types |
|----------|-------|
| **Cloud** | AWS Access Key, AWS Secret Key, Azure Storage, Azure Connection String, GCP Service Account |
| **GitHub** | Personal Access Token, OAuth Token, App Token, Refresh Token |
| **Communication** | Slack Token, Slack Webhook, Discord Token, Telegram Bot Token |
| **Payment** | Stripe Live/Restricted/Publishable Key, Square Token/OAuth |
| **AI/ML** | OpenAI API Key (v1 & v2) |
| **Email** | SendGrid API Key, Mailgun API Key |
| **Telephony** | Twilio API Key, Twilio Auth Token |
| **Infrastructure** | Private Keys (RSA, EC, DSA, PGP), JWTs, Connection Strings (JDBC, MongoDB, MySQL, PostgreSQL, Redis, AMQP) |
| **Platform** | Heroku API Key, Shopify Token/Secret, Databricks Token, DigitalOcean Token, NPM Token, PyPI Token, Firebase Key |
| **Generic** | Password variables, API keys, Secret keys, Access tokens, Auth tokens |
| **Entropy** | High-entropy strings near sensitive keywords |

</details>

---

## Memory Management

Git-Hunter is designed for scanning large organizations (1000+ repos) without running out of memory:

- **Streaming git log** — Reads `git log -p` line-by-line instead of buffering
- **Single-pass directory scan** — Regex + entropy combined in one file read
- **Bounded archive scanning** — Per-entry and total budget limits for ZIP/TAR files
- **Periodic GC** — Garbage collection between scan phases and every 200 files
- **Configurable limits** — `GHRECON_MEM_LIMIT_MB` sets the hard ceiling (default: 1500 MB)
- **Graceful degradation** — Scan aborts cleanly when limits are hit, with progress saved for resumption

---

## Legal Disclaimer

> [!CAUTION]
> **Git-Hunter is intended for authorized security testing and research only.**
>
> You are solely responsible for ensuring you have proper authorization before scanning any GitHub organization, user, or repository. Unauthorized access to computer systems is illegal. The authors are not liable for any misuse of this tool.
>
> Always obtain written permission before conducting security assessments.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Built with ❤️ for the security community</b><br>
  <sub>If Git-Hunter helped you find something interesting, consider ⭐ starring the repo</sub>
</p>
