# GitHub API — Full Capability Map

## Search Surfaces (all REST endpoints)

| Endpoint | Rate Limit | Best For | Auth Required | Implemented? |
|---|---|---|---|---|
| `GET /search/code` | **10 req/min** (authenticated) | File contents, .env files, hardcoded secrets | YES (always) | YES |
| `GET /search/repositories` | 30 req/min | Repo discovery, stars/forks/topic filters | No | YES |
| `GET /search/commits` | 30 req/min | Commit messages containing "remove key", "oops" | No | NO — add |
| `GET /search/issues` | 30 req/min | Issue/PR bodies with pasted credentials | No | NO — add |
| `GET /search/users` | 30 req/min | Suspicious account patterns, org hunters | No* | NO |
| `GET /search/topics` | 30 req/min | Finding repos by topic tag | No | NO |
| `GET /search/labels` | 30 req/min | (requires repo id; low value for secret hunting) | No | NO |
| `GET /gists/public` | 5000 core req/h | Public gist stream — HUGELY underexploited | No | NO — add |
| `GET /gists/{id}` | 5000 core req/h | Individual gist file contents | No | NO — add |
| `POST /graphql` | 5000 pts/h (5pts/mutation, 1pt/query) | Rich nested queries, repo enrichment | YES | NO — add |

*Users endpoint does not accept authentication.

**Code search limit note:** `/search/code` is capped at **10 req/min** (not 30 like other search). Plan around this — 10 dork queries per minute max.

**Hard cap:** All search endpoints return at most 1000 results regardless of pagination.

---

## Rate Limit Summary

| Resource | Limit | Reset Window |
|---|---|---|
| Core REST (non-search) | 5,000 req/h | 1 hour |
| Search (repos/commits/issues/users) | 30 req/min | 1 minute |
| Code search (`/search/code`) | 10 req/min | 1 minute |
| GraphQL | 5,000 pts/h; max 2,000 pts/min | 1 hour |
| Unauthenticated (any) | 60 req/h total | 1 hour |

**Headers to watch:**
- `X-RateLimit-Remaining` — calls left in window
- `X-RateLimit-Reset` — epoch second of reset
- `X-RateLimit-Resource` — which bucket (core/search/code_search/graphql)
- `X-RateLimit-Used` — calls consumed this window

**Secondary rate limits (global):**
- Max 100 concurrent requests
- Max 900 REST points/min
- Max 90s CPU time per 60s real time
- Content creation: ~80 req/min

---

## Gist Hunting Strategy

Gists are a high-signal surface because:
1. Developers use them as quick paste-bins and forget to remove secrets
2. GitHub's secret scanning does NOT cover Gist comments (only file contents)
3. They are indexed in real-time — a gist created 10 minutes ago is in the public feed
4. Research (TruffleHog/TruffleSecurity 2024): 37K gists scanned → 11 with credentials, 74% still active

### Streaming Public Gists
```
GET /gists/public?per_page=100&page=N
```
- Returns gists sorted by most recently updated
- Max pagination: 30 pages × 100 per page = 3,000 gists (API hard cap)
- Response already includes `files` object with `raw_url` for each file
- No extra API call needed to get file contents (files ≤1MB are inline via `raw_url`)

### File content strategy
Each gist item has a `files` dict. Each file entry has:
- `filename`, `type`, `language`, `raw_url`, `size`, `truncated`
- If `truncated=false` AND size ≤1MB: content available via `raw_url` (no token needed — public)
- If `truncated=true`: clone via `git_pull_url`

### Gist-specific dorks (web search — NOT API)
The official Gist search at `https://gist.github.com/search?q=` is web-only, not in the REST API.
Use it manually; cannot automate without scraping HTML.

### Best file types to hit in gists
`.env`, `.sh`, `.py`, `.js`, `.ts`, `.json`, `.yaml`, `.conf`, `.ini`, `.rb`, `.php`

---

## Commit Search Dorks

Endpoint: `GET /search/commits?q=QUERY&sort=committer-date&order=desc`

Requires `Accept: application/vnd.github.cloak-preview+json` (preview header still needed as of 2025).

### High-signal query strings
```
"remove api key"
"accidentally committed"
"forgot to remove"
"do not share"
"oops key"
"oops token"
"remove secret"
"delete credentials"
"leaked key"
"revoke token"
"add api key"
"api key hardcoded"
"test credentials"
"my api key"
"temp credentials"
```

### Qualifiers available for commits
- `repo:owner/name` — scope to one repo
- `user:USERNAME` — all of a user's repos
- `org:ORGNAME` — all org repos
- `author:USERNAME` — by git author
- `committer:USERNAME` — by git committer
- `author-date:>2024-01-01` — date filter
- `merge:false` — exclude merge commits (reduces noise)
- `is:public` — public repos only

### Example ready-to-use queries
```python
COMMIT_DORK_QUERIES = [
    "remove api key merge:false is:public",
    "accidentally committed merge:false is:public",
    "forgot to remove token merge:false is:public",
    "oops key merge:false is:public",
    "delete credentials merge:false is:public",
    "add credentials merge:false is:public",
    "do not share merge:false is:public",
    "leaked key merge:false is:public",
    "revoke token merge:false is:public",
    "hardcoded api key merge:false is:public",
]
```

---

## Issue/PR Search Dorks

Endpoint: `GET /search/issues?q=QUERY`

Issues and PRs are often where developers discuss accidentally committed secrets.

```python
ISSUE_DORK_QUERIES = [
    "leaked api key in:body",
    "accidentally committed token in:body",
    "api key exposed in:body",
    "removed credentials in:title",
    "revoked key in:body",
    "secret key exposed in:title",
]
```

Qualifiers: `is:issue`, `is:pr`, `is:open`, `is:closed`, `in:title`, `in:body`, `in:comments`

---

## GraphQL API

### Auth
Same token as REST. POST to `https://api.github.com/graphql` with JSON body `{"query": "..."}`.

### Rate limits
- 5,000 points/hour per user
- Point cost: 1 pt per query, 5 pts per mutation
- Max 2,000 pts/min

### Repo search + enrichment in one query
```graphql
query SearchReposWithDetails($q: String!, $cursor: String) {
  search(query: $q, type: REPOSITORY, first: 100, after: $cursor) {
    pageInfo {
      hasNextPage
      endCursor
    }
    repositoryCount
    nodes {
      ... on Repository {
        nameWithOwner
        url
        stargazerCount
        forkCount
        pushedAt
        primaryLanguage { name }
        repositoryTopics(first: 10) {
          nodes { topic { name } }
        }
        defaultBranchRef { name }
        licenseInfo { spdxId }
        isArchived
        isPrivate
      }
    }
  }
}
```

### Code search via GraphQL (same surface, different syntax)
```graphql
query CodeSearch($q: String!, $cursor: String) {
  search(query: $q, type: REPOSITORY, first: 50, after: $cursor) {
    nodes {
      ... on Repository { nameWithOwner url stargazerCount }
    }
  }
}
```

Note: GraphQL search uses the same `SearchType` enum: `REPOSITORY`, `ISSUE`, `USER`, `DISCUSSION`.
There is no `CODE` search type in GraphQL — code search is REST-only.

### Advantage of GraphQL
- Get repo metadata + topics + language in ONE request instead of repo-search + N enrichment calls
- Currently `scraper.py` does N separate `/repos/{owner}/{repo}` calls for enrichment after code search — GraphQL would collapse this into one query

---

## Advanced Search Operators (code search)

All work in `GET /search/code`:

| Operator | Example | Effect |
|---|---|---|
| `filename:` | `filename:.env` | Exact filename match |
| `extension:` | `extension:py` | File extension |
| `path:` | `path:config/` | Path component |
| `language:` | `language:python` | Language filter |
| `repo:` | `repo:owner/name` | Scope to repo |
| `user:` | `user:octocat` | Scope to user's repos |
| `org:` | `org:openai` | Scope to org |
| `size:` | `size:>0` | File size in bytes |
| `in:file` | `sk-proj- in:file` | Match in file body |
| `in:path` | `.env in:path` | Match in file path |
| `fork:true` | `fork:true` | Include forked repos |

---

## Less-Known Endpoints

| Endpoint | Notes |
|---|---|
| `GET /repos/{owner}/{repo}/tarball/{ref}` | Download whole repo as .tar.gz — no token needed for public repos |
| `GET /repos/{owner}/{repo}/git/blobs/{sha}` | Fetch blob by SHA directly; base64 encoded; useful for deleted file content from commits |
| `GET /repos/{owner}/{repo}/commits/{sha}` | Get full patch diff for a commit (file-level changes with +/- lines) |
| `GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1` | Full file tree in one call |
| `GET /users/{username}/gists` | All public gists for a specific user |
| `GET /gists/public?since=ISO8601` | Gists updated since timestamp — enables incremental polling |

---

## New Scraper Functions to Build

### 1. `scraper.search_commits(query, max_results=100) -> list[dict]`
- Endpoint: `GET /search/commits`
- Special header: `Accept: application/vnd.github.cloak-preview+json`
- Returns: sha, message, author, date, repo name, commit url
- Normalizes: `{sha, message_preview, author_login, committed_date, repo_full_name, commit_url}`

### 2. `scraper.search_issues(query, max_results=100) -> list[dict]`
- Endpoint: `GET /search/issues`
- Returns: title, body preview, html_url, state, repo, created_at
- Qualifiers: pass `is:issue` or `is:pr` in query string

### 3. `gist_hunter.search_gists(query, max=500) -> list[dict]`
- New file: `gist_hunter.py`
- GET `/gists/public?per_page=100` paginated
- For each gist: scan all file `raw_url` contents via direct HTTP GET (no token needed)
- Run `patterns.scan_text()` on each file content
- Output same schema as `hunt_secrets.py` findings

### 4. `gist_hunter.stream_public_gists(max=1000) -> Iterator[dict]`
- Paginate through `/gists/public` up to `max` gists
- Yields each gist dict with id, description, files, owner, created_at, updated_at

### 5. GraphQL repo enrichment (optional refactor of `_enrich_repos`)
- Replace N individual `/repos/{owner}/{repo}` calls with one GraphQL batch query
- Saves quota: 1 GraphQL call = 1 point vs N REST calls = N core points

---

## Implementation Priority

1. **gist_hunter.py** — highest ROI; gists are unscanned by existing tools
2. **search_commits** in scraper.py — commit message dorks find active deletions (oops commits)
3. **search_issues** in scraper.py — low effort, finds issue discussions about leaks
4. **GraphQL enrichment** — optimization, not new capability; defer

---

## Smoke Test Results

See HANDOFF.md for full results after `gist_hunter.py` is built.
