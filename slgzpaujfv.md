# github-scraper

Curated GitHub search → download pipeline focused on Ollama, Dolphin uncensored
variants, and REST-API LLM agent frameworks.

## What it does
- Runs a set of curated GitHub queries (`config/queries.yaml`) per category.
- Merges per-query JSON into one deduped result file per category.
- Hands the merged file to `downloader.py` which pulls the actual artifacts.

## Setup
Only requirement is the `GITHUB_TOKEN` env var (already present on this box).
PyYAML is used when available; otherwise `config/queries.json` is read instead.

```powershell
python -c "import yaml, requests"   # sanity check
```

## Usage
```powershell
# Full pipeline, all categories
python run_all.py

# Single category
python run_all.py --category ollama_deploy

# Just scrape, no downloads
python run_all.py --scrape-only

# Just download from existing output/*.json
python run_all.py --download-only

# Plan only (no API calls)
python run_all.py --dry-run
```

## Output layout
```
config/
  queries.yaml            # curated queries grouped by category
output/
  <category>__<slug>.json # one file per query
  <category>__MERGED.json # deduped union per category
downloads/
  <category>/...          # files / cloned repos pulled by downloader.py
logs/
  run_all.log             # per-run log (also echoed to stdout)
```

## Adding a new category
Add a new top-level key under `categories:` in `config/queries.yaml`, then a
list of `{q, kind, max, qualifiers}` entries. `kind` is `repos` or `code`,
`qualifiers` is a flat mapping passed straight through to `scraper.search(...)`
as kwargs (e.g. `filename`, `extension`, `language`). The runner discovers new
categories automatically — no code change needed.

## Components
- `scraper.py` — GitHub search (sibling agent).
- `downloader.py` — artifact fetcher (sibling agent).
- `run_all.py` — this orchestrator: scrape → merge → download per category.
- Rate-limit safety: before each category, `/rate_limit` is polled; if
  `search.remaining < 5` or `core.remaining < 50`, the runner sleeps until the
  reset window.
