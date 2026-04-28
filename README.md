# Git-Hunter v2 — TruffleHog Integration Summary


## New CLI Flags

```bash
--engine trufflehog    # Default. Uses TruffleHog binary
--engine regex         # Fallback to v1 regex scanner

--mode verified        # Default. TruffleHog --only-verified (highest accuracy)
--mode full            # TruffleHog without --only-verified (noisier)
--mode deep            # TruffleHog + regex fallback if 0 findings (max coverage)
```

## Scan Modes

| Mode | Engine | Speed | Accuracy | Validation |
|------|--------|-------|----------|------------|
| `verified` | TruffleHog `--only-verified` | Slower | Highest | Skipped (TruffleHog verified) |
| `full` | TruffleHog (all findings) | Faster | Noisier | Phase 4 runs |
| `deep` | TruffleHog + regex fallback | Slowest | Maximum | Phase 4 runs |

## Key Design Decisions

1. **No parallel regex + TruffleHog** — Only one engine runs per repo (spec rule)
2. **Raw output NEVER stored** — Everything goes through normalizer (spec rule)
3. **Regex is fallback only** — Triggers only when TruffleHog returns 0 AND mode is `deep`
4. **Validator is now optional** — In `verified` mode, TruffleHog already validates credentials
5. **Auto-fallback** — If TruffleHog binary is missing, falls back to regex with a warning
6. **DB migration** — Existing databases get new columns via `ALTER TABLE` (no data loss)

## Installation Requirement

TruffleHog must be installed separately:

```bash
# macOS / Linux
brew install trufflehog

# Or via Go
go install github.com/trufflesecurity/trufflehog/v3@latest

# Or download binary from:
https://github.com/trufflesecurity/trufflehog/releases
```

## Usage Examples

```bash
# Default: TruffleHog verified mode (highest accuracy)
python ghrecon.py scan myorg

# Full scan (all TruffleHog findings, not just verified)
python ghrecon.py scan myorg --mode full

# Maximum coverage (TruffleHog + regex fallback)
python ghrecon.py scan myorg --mode deep

# Force regex-only (no TruffleHog needed)
python ghrecon.py scan myorg --engine regex

# Combined with existing flags
python ghrecon.py scan myorg --mode deep --stealth --tokens tokens.txt
```
