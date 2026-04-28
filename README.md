# GHRecon — GitHub Secret Reconnaissance Engine

**Production-grade offensive security tool** for automated GitHub organization/user reconnaissance with credential extraction, validation, and stealth operation.

## Architecture Overview

```mermaid
graph TB
    CLI["CLI (Typer)"] --> Config["Config Manager<br/>YAML + ENV + CLI"]
    CLI --> Core

    subgraph Core["Core Engine"]
        Enum["Enumerator<br/>REST + GraphQL"] --> Cloner["Async Cloner<br/>Parallel + Stealth"]
        Cloner --> Scanner["Secret Scanner<br/>40+ Patterns"]
        Scanner --> Validator["Credential Validator<br/>Multi-Platform"]
        Scanner --> Analyzer["Advanced Analyzer<br/>Entropy + Timeline"]
    end

    subgraph Utils["Utilities"]
        TokenPool["Token Pool<br/>Rotation + Health"]
        ProxyMgr["Proxy Manager<br/>SOCKS5 Rotation"]
        DB["SQLite DB<br/>AES-256 Encrypted"]
        Logger["JSON Logger<br/>Structured Output"]
    end

    subgraph Reports["Reporting"]
        JSON["JSON Report"]
        MD["Markdown Report"]
        CSV["CSV Report"]
    end

    Core --> Utils
    Core --> Reports
```


```markdown
## Installation
```

```bash
git clone https://github.com/youruser/Git-Hunter.git
cd Git-Hunter
pip install -r requirements.txt
```

## Setup

```
# Set your GitHub token (required)
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Here's the complete usage reference you can paste into your README:

```
## Commands

### `scan` — Run a reconnaissance scan

```
# Scan an organization
python ghrecon.py scan <target> [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--type` | `-t` | auto-detect | Target type: `org`, `user`, `repo`, `search`, `file` |
| `--config` | `-c` | `config.yaml` | Path to config YAML |
| `--tokens` | | | Path to tokens file (one per line) |
| `--parallel` | `-p` | `8` | Parallel clone/scan workers |
| `--depth` | | `shallow` | Clone depth: `shallow`, `medium`, `full` |
| `--validate-secrets / --no-validate` | | `true` | Validate discovered secrets |
| `--scan-branches / --no-branches` | | `true` | Scan all branches |
| `--scan-actions` | | `false` | Scan GitHub Actions artifacts/logs |
| `--scan-prs` | | `false` | Scan pull request diffs |
| `--skip-forks / --include-forks` | | `true` | Skip forked repos |
| `--skip-archived / --include-archived` | | `true` | Skip archived repos |
| `--max-size` | | `500` | Max repo size in MB |
| `--max-repos` | | `0` | Max repos to scan (0 = unlimited) |
| `--proxy-list` | | | Path to proxy list file |
| `--stealth` | | `false` | Enable stealth mode (delays, UA rotation) |
| `--output-format` | `-f` | `json,markdown,csv` | Output formats (comma-separated) |
| `--output-dir` | `-o` | `./scans` | Output directory |
| `--no-store-secrets` | | `false` | Don't store secret values in DB (hash only) |
| `--keep-repos` | | `false` | Keep cloned repos after scan |
| `--resume-scan` | | | Resume an interrupted scan by ID |

### `export` — Export scan results

```
python ghrecon.py export <scan_id> [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format` | `-f` | `json` | Export format: `json`, `csv`, `markdown` |
| `--validated-only` | | `false` | Export only validated secrets |
| `--output-dir` | `-o` | `./scans` | Output directory |
| `--db` | | `./scans/ghrecon.db` | Database path |

### `status` — Check scan status

```
python ghrecon.py status [SCAN_ID]   # omit ID for latest scan
```

| Option | Default | Description |
|--------|---------|-------------|
| `--db` | `./scans/ghrecon.db` | Database path |

### Global Options

```
python ghrecon.py --version   # Show version
python ghrecon.py --help      # Show help
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Single GitHub token |
| `GITHUB_TOKENS` | Comma-separated token list |
| `GHRECON_PARALLEL` | Override parallel job count |
| `GHRECON_STEALTH` | Enable stealth (`1` / `true`) |
| `GHRECON_OUTPUT_DIR` | Override output directory |
| `GHRECON_ENCRYPTION_KEY` | AES-256 key for secret storage |
| `GHRECON_MEM_LIMIT_MB` | Memory limit in MB (default: `1500`) |

## Examples

```
# Scan an organization
python ghrecon.py scan myorg

# Scan a single repo with full history
python ghrecon.py scan https://github.com/user/repo --depth full

# Search-based scan with repo limit
python ghrecon.py scan --type search "org:google language:python stars:>1000" --max-repos 50

# Stealth scan with proxies and custom tokens
python ghrecon.py scan myorg --stealth --tokens tokens.txt --proxy-list proxies.txt

# Full-featured scan
python ghrecon.py scan myorg \
    --tokens tokens.txt \
    --parallel 12 \
    --depth medium \
    --validate-secrets \
    --scan-branches \
    --scan-actions \
    --scan-prs \
    --skip-forks \
    --max-size 500 \
    --max-repos 100 \
    --stealth \
    --output-format json,markdown,csv \
    --output-dir ./scans/myorg

# Resume an interrupted scan
python ghrecon.py scan myorg --resume-scan 20250422_143522_myorg

# Export validated secrets only
python ghrecon.py export 20250422_143522_myorg --validated-only --format csv

# Check latest scan status
python ghrecon.py status
```