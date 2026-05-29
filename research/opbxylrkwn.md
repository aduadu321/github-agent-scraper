# Forum & Community Techniques
> Researched: 2026-05-26 | Sources: HackTricks, Medium/InfoSecWriteups, TruffleHog blog, techgaun/github-dorks, GitDorker alldorksv3, tillsongalloway.com, EdOverflow gist, GitHub Docs

---

## Top Dork Queries (NEW — not in our queries.yaml)

### Private Keys & SSH
1. `extension:pem private`
2. `extension:ppk private`
3. `filename:id_rsa OR filename:id_dsa`
4. `"-----BEGIN RSA PRIVATE KEY-----"`
5. `"-----BEGIN OPENSSH PRIVATE KEY-----"`
6. `"-----BEGIN EC PRIVATE KEY-----"`
7. `"-----BEGIN PGP PRIVATE KEY BLOCK-----"`
8. `filename:id_ed25519`
9. `filename:sshd_config`
10. `filename:known_hosts`

### Credential Files
11. `filename:.npmrc _auth`
12. `filename:.dockercfg auth`
13. `filename:.git-credentials`
14. `filename:.netrc password`
15. `filename:_netrc password`
16. `filename:.pgpass`
17. `filename:.htpasswd`
18. `filename:.s3cfg`
19. `filename:.ftpconfig`
20. `filename:.remote-sync.json`
21. `filename:sftp-config.json`
22. `filename:sftp.json path:.vscode`
23. `filename:robomongo.json`
24. `filename:filezilla.xml Pass`
25. `filename:recentservers.xml Pass`
26. `filename:dbeaver-data-sources.xml`
27. `filename:logins.json`
28. `filename:hub oauth_token`
29. `filename:config.json auths`
30. `filename:idea14.key`

### Shell History / Profile Files
31. `filename:.bash_history`
32. `filename:.sh_history`
33. `filename:.bash_profile aws`
34. `filename:.bashrc password`
35. `filename:.bashrc mailchimp`
36. `filename:.cshrc`
37. `filename:.history`

### Database & Infrastructure
38. `extension:sql mysql dump password`
39. `rds.amazonaws.com password`
40. `extension:json mongolab.com`
41. `extension:yaml mongolab.com`
42. `extension:json api.forecast.io`
43. `.mlab.com password`
44. `filename:connections.xml`
45. `filename:wp-config.php`
46. `path:sites databases password`
47. `filename:configuration.php JConfig password`
48. `filename:config.php dbpasswd`
49. `filename:database.yml production`
50. `filename:settings.py SECRET_KEY`
51. `filename:secrets.yml password`
52. `filename:master.key path:config`
53. `filename:prod.secret.exs`
54. `filename:prod.exs NOT prod.secret.exs`
55. `filename:application.properties spring.datasource.password`
56. `"jdbc:mysql://" "password" extension:java`

### Cloud Services & SaaS
57. `filename:.env DB_USERNAME NOT homestead`
58. `filename:.env MAIL_HOST=smtp.gmail.com`
59. `filename:.env MYSQL_PASSWORD`
60. `filename:.tugboat NOT _tugboat`
61. `HEROKU_API_KEY language:shell`
62. `HEROKU_API_KEY language:json`
63. `HOMEBREW_GITHUB_API_TOKEN language:shell`
64. `JEKYLL_GITHUB_TOKEN`
65. `shodan_api_key language:python`
66. `shodan_api_key language:shell`
67. `PT_TOKEN language:bash`
68. `SF_USERNAME salesforce`
69. `jsforce extension:js conn.login`

### Slack / Messaging
70. `xoxp OR xoxb`
71. `"https://hooks.slack.com/services/"`
72. `slack_api_token filename:.env`
73. `slack_signing_secret`
74. `slack_webhook`

### Stripe / Payments
75. `"sk_live_" extension:js`
76. `"sk_live_" filename:.env`
77. `stripe_key OR stripe_secret`
78. `"sq0atp-" OR "sq0csp-"`
79. `paypal_secret filename:.env`
80. `braintree merchant_id`

### Twilio / SendGrid / Mailgun
81. `twilio_account_sid filename:.env`
82. `TWILIO_SID NOT env`
83. `sendgrid_api_key filename:.env`
84. `"SG." extension:env`
85. `mailgun_api_key`
86. `mailgun_priv_key`

### JWT & Auth
87. `jwt_secret filename:.env`
88. `secret_key_base filename:.env`
89. `"Authorization: Bearer" extension:js`
90. `"x-api-key" filename:.config`

### Recovery Codes (high value)
91. `filename:github-recovery-codes.txt`
92. `filename:gitlab-recovery-codes.txt`
93. `filename:discord_backup_codes.txt`

### Other High-Value Patterns
94. `filename:proftpdpasswd`
95. `filename:ventrilo_srv.ini`
96. `filename:server.cfg rcon password`
97. `filename:CCCam.cfg`
98. `filename:express.conf path:.openshift`
99. `msg nickserv identify filename:config`
100. `filename:jupyter_notebook_config.json`
101. `"api_hash" "api_id"`
102. `extension:yaml cloud.redislabs.com`
103. `extension:json cloud.redislabs.com`
104. `DATADOG_API_KEY language:shell`
105. `filename:deployment-config.json`
106. `filename:WebServers.xml`
107. `extension:json googleusercontent client_secret`
108. `extension:avastlic "support.avast.com"`
109. `[WFClient] Password= extension:ica`
110. `filename:dhcpd.conf`
111. `filename:shadow path:etc`
112. `filename:passwd path:etc`
113. `filename:.esmtprc password`

### Temporal / Date-filtered (reduce noise)
114. `pushed:>2024-01-01 filename:.env "password"`
115. `created:>2024-01-01 "AKIA" extension:env`
116. `pushed:>2024-01-01 "sk_live_" extension:js`
117. `pushed:>2024-01-01 "BEGIN RSA PRIVATE KEY"`

### Organization-targeted templates
118. `org:TARGET "api_key" filename:.env`
119. `org:TARGET filename:config.json "password"`
120. `org:TARGET extension:pem`
121. `"targetcompany.com" extension:env`
122. `"@targetcompany.com" "token" extension:json`

---

## Advanced GitHub Search Operators

### New Code Search (github.com/search — Blackbird/Elasticsearch backend)

| Operator | Syntax | Notes |
|---|---|---|
| `path:` | `path:*.env` / `path:src/**/*.js` | Glob and regex supported |
| `language:` | `language:python` | 400+ languages |
| `symbol:` | `symbol:getPassword` | Finds function/class defs |
| `content:` | `content:sk-` | Searches only file content, not paths |
| `is:` | `is:archived`, `is:fork`, `is:vendored` | Repo property filter |
| `org:` | `org:microsoft` | Scope to org |
| `user:` | `user:torvalds` | Scope to user |
| `repo:` | `repo:owner/name` | Scope to single repo |
| `NOT` | `filename:.env NOT homestead` | Boolean negation |
| `AND` / `OR` | `(language:ruby OR language:python)` | Boolean logic with parens |
| Regex | `/sk-[a-zA-Z0-9]{48}/` | Wrap in `/pattern/` |

### Commit Search (github.com/search?type=commits)
Operators: `author:`, `committer:`, `author-email:`, `committer-email:`, `author-date:`, `committer-date:`, `merge:`, `hash:`, `parent:`, `tree:`, `is:public`, `is:private`, `org:`, `repo:`, `user:`

**Secret-hunting commit dorks:**
- `author-email:"@corp.com" password` — targeted commit search by corporate email
- `committer-date:>2024-01-01 "AKIA"` — fresh AWS key commits
- `"removed api key" OR "deleted secret" OR "forgot to remove"` — "oops commits"
- `"accidentally committed" OR "revert" password`
- `hash:COMMITHASH` — access a specific deleted commit directly

### Issue / PR Search (github.com/search?type=issues)
- `type:issue "api_key" "please help"` — developers asking for help after accidental push
- `type:issue "accidentally pushed" secret`
- `type:pr label:security "credentials"`
- `is:issue is:open "database password"` — open issues leaking creds

### Gist Search (gist.github.com)
- Gists are indexed by GitHub search: `site:gist.github.com "api_key"`
- TruffleHog v3 can scan gists directly: `trufflehog github --endpoint=https://api.github.com --token=TOKEN --include-repos=gist`
- GitHub API: `GET /gists/public` — returns public gists, paginate to scan
- Google dork: `site:gist.github.com "AKIA"` or `site:gist.github.com "sk-"` (OpenAI)

### Wiki Search
- `"password" in:wiki repo:TARGET/REPO` — wiki pages often contain creds
- GitHub API: `GET /repos/{owner}/{repo}/git/trees/HEAD?recursive=1` — enumerate wiki files

---

## Rate Limit Strategies

### GitHub REST API Limits
- **Unauthenticated:** 60 req/hr (IP-based)
- **Authenticated PAT:** 5,000 req/hr primary; 900 points/min secondary
- **GitHub Enterprise Cloud:** 15,000 req/hr
- **Code Search (REST legacy):** 30 req/min with auth, 10 without
- **New Code Search (web UI):** No documented hard limit but WAF rate-limits aggressive patterns

### Ethical Rate Limit Management (token rotation)
1. **Token pool rotation:** Maintain a pool of PATs; rotate on `X-RateLimit-Remaining < 100`. Header: `x-ratelimit-remaining`.
2. **Exponential backoff:** On 429, parse `Retry-After` header or `x-ratelimit-reset` (Unix timestamp).
3. **GitHub App tokens:** Apps get 5,000 + scaling requests. Install on a dummy org for +50/hr per repo (capped at 12,500/hr total).
4. **Distribute across accounts:** Create separate accounts for different search categories; never exceed 30 code search requests/min per token.
5. **GH Archive BigQuery:** For commit scanning at scale — download hourly archives from `https://data.gharchive.org/YYYY-MM-DD-HH.json.gz` instead of polling API. Free BigQuery public dataset.
6. **Web scraping fallback:** GitHub's web UI (`github.com/search`) has no *documented* hard code-search limit (differs from REST API). Use headless browser with delays of 2-5s between pages. WAF may block without warning.
7. **Jitter:** Add random 1-3s sleep between requests to avoid pattern detection.
8. **Avoid UA string "python-requests":** Use custom User-Agent strings.

---

## Tools Referenced by Community

| Tool | Description | URL |
|---|---|---|
| **TruffleHog v3** | 700+ detectors with live verification; scans repos, gists, GitHub Actions, wikis | github.com/trufflesecurity/trufflehog |
| **GitLeaks** | TOML-based rule config; fast, standalone binary | github.com/gitleaks/gitleaks |
| **GitHound** | Breadth-first GitHub dorking with regex and entropy scoring; `--dig-commits`, `--many-results` | github.com/tillson/git-hound |
| **Gitrob** | Multi-repo org scanner, visualizes findings | github.com/michenriksen/gitrob |
| **git-all-secrets** | Combines TruffleHog + Gitrob | github.com/anshumanbh/git-all-secrets |
| **GitDorker** | 239-dork query automation against GitHub Code Search | github.com/obheda12/GitDorker |
| **github-dork.py** | techgaun's original Python dorker | github.com/techgaun/github-dorks |
| **detect-secrets (Yelp)** | Entropy-based pre-commit scanning | github.com/Yelp/detect-secrets |
| **SecretHunter** | Lightweight multi-source scanner | github.com/rahmansec/SecretHunter |
| **credentialthreat** | Scans websites + repos for credentials | github.com/PAST2212/credentialthreat |
| **keyhacks** | Post-discovery: validates if found keys are live | github.com/streaak/keyhacks |
| **JAZ** | Finds secrets hidden in commits | github.com/jonaylor89/JAZ |
| **LinkFinder** | Finds endpoints in JS files | github.com/GerbenJavado/LinkFinder |

---

## New Search Endpoints to Exploit

### 1. Commit Search API
- **Endpoint:** `GET https://api.github.com/search/commits?q=QUERY`
- **Header required:** `Accept: application/vnd.github.cloak-preview`
- **Limit:** 30 req/min authenticated
- **Power:** Search commit *messages* — find "oops", "revert", "forgot" keywords
- **Deleted commit access:** Even after force-push deletion, commits accessible at `https://github.com/ORG/REPO/commit/HASH` and `.patch`/`.diff` variants if hash is known
- **GH Archive:** Zero-commit push events in archive reveal deleted commit hashes

### 2. Issues/PR Comment Search
- **Endpoint:** `GET https://api.github.com/search/issues?q=QUERY`
- Covers: issue bodies, PR bodies, **not** inline PR review comments (different endpoint)
- Issue *comments* API: `GET /repos/{owner}/{repo}/issues/comments`
- Search operators: `type:issue`, `type:pr`, `is:open`, `is:closed`, `label:`, `author:`

### 3. Gist API
- **List public gists:** `GET https://api.github.com/gists/public?per_page=100&page=N`
- **Search gists (no official endpoint):** Use Google: `site:gist.github.com "PATTERN"`
- **Scan gist history:** `GET /gists/{gist_id}/commits` — gist revisions can contain removed secrets

### 4. GitHub Actions Artifacts / Workflow Logs
- Logs (if public): `GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs`
- Artifacts: `GET /repos/{owner}/{repo}/actions/artifacts`
- Secrets masked as `***` in logs but memory-dumping attacks on `Runner.Listener` process expose them
- Dork for misconfigured workflows: `path:.github/workflows "echo ${{ secrets."` or `path:.github/workflows "env:" language:yaml`

### 5. Wiki Search
- GitHub search supports `in:wiki` qualifier
- API tree endpoint: `GET /repos/{owner}/{repo}/git/trees/HEAD?recursive=1` on `{owner}/{repo}.wiki` repo

### 6. GitHub Archive (BigQuery) — Bulk Historical Scanning
- Dataset: `bigquery-public-data.github_repos`
- Query: `SELECT * FROM bigquery-public-data.github_repos.contents WHERE content LIKE '%AKIA%'`
- GH Archive events: `https://data.gharchive.org/YYYY-MM-DD-HH.json.gz`
- Find PushEvent with `size=0` on `before` ref → deleted commits

### 7. Raw Content (Google Dork bypass)
- `site:raw.githubusercontent.com filetype:env intext:"api_key"` — Google indexes raw files
- `site:raw.githubusercontent.com intext:"sk-" filetype:env`
- `site:raw.githubusercontent.com intext:"AKIA" filetype:cfg`
- Even after repo deletion, Google cache may persist

---

## ML/AI Approaches Referenced by Community

- **Entropy scoring:** High Shannon entropy strings flagged as likely secrets (base64, hex tokens) — used by detect-secrets, TruffleHog
- **GitHound `--regex-file`:** Custom regex patterns with `--dig-files` for deeper scanning
- **TruffleHog Analyze:** Determines token permissions/scope after finding a secret
- **Context-aware filtering:** Use NOT to exclude test/example/demo files to reduce false positives: `NOT "example" NOT "sample" NOT "test" NOT "placeholder" NOT "homestead" NOT "localhost"`
- **Validity checking:** TruffleHog v3 actively pings SaaS APIs (Stripe, AWS, Anthropic, etc.) to verify liveness — reduces false positive triage time from hours to seconds

---

## False Positive Reduction Best Practices

1. Add `NOT homestead NOT example NOT placeholder NOT sample NOT demo NOT test NOT fake NOT YOUR_API_KEY NOT REPLACE_ME` to `.env` dorks
2. Use `size:>0` to filter empty files
3. Combine with `pushed:>2023-01-01` to target recently active repos
4. For AWS keys: validate format with regex `/AKIA[0-9A-Z]{16}/` before pursuing
5. For OpenAI: `sk-proj-` prefix (new format since 2024) is more precise than `sk-`
6. Use `is:public NOT is:fork` for cleaner hits (forks often copy parent secrets but are stale)
7. Search commit messages for "revert" or "remove" — these repos almost certainly had a real secret

---

## Sources

- [techgaun/github-dorks (raw)](https://raw.githubusercontent.com/techgaun/github-dorks/master/github-dorks.txt)
- [GitDorker alldorksv3](https://github.com/obheda12/GitDorker/blob/master/Dorks/alldorksv3)
- [tillsongalloway.com — $15k bug bounties from GitHub leaks](https://tillsongalloway.com/finding-sensitive-information-on-github/index.html)
- [Medium — GitHub Dorking: The Hunter's Guide](https://medium.com/@N0aziXss/github-dorking-the-hunters-guide-to-finding-secrets-in-public-code-f1b8582309e8)
- [Medium — GitHub Dorking 2026 Complete Guide](https://medium.com/@thenewdate24/github-dorking-the-complete-2026-hunters-guide-to-finding-exposed-secrets-9a72331ed5bb)
- [Medium — GitHub Search Syntax for Leaked Keys](https://medium.com/@vladrosca93/github-search-syntax-for-finding-leaked-api-keys-secrets-and-tokens-c7f826d7bae8)
- [Medium — Advanced Google Dorking on raw.githubusercontent.com](https://medium.com/@ioldman/hidden-secrets-advanced-google-dorking-on-githubs-raw-githubusercontent-com-675374870756)
- [TruffleHog blog — Scanning GitHub Oops Commits](https://trufflesecurity.com/blog/guest-post-how-i-scanned-all-of-github-s-oops-commits-for-leaked-secrets)
- [GitHub Docs — Code Search Syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitHub Docs — Commit Search](https://docs.github.com/en/search-github/searching-on-github/searching-commits)
- [GitHub Docs — REST Rate Limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [AllAboutBugBounty — Github Dorks.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Reconnaissance/Github%20Dorks.md)
- [InfoSecWriteups — GitHub Dorking Beginner's Guide](https://infosecwriteups.com/github-dorking-a-beginners-guide-to-finding-secrets-in-repositories-2d4d36287913)
