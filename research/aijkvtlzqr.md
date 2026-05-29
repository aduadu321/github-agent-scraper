# Tool Analysis — Secret Scanning Landscape
*Generated: 2026-05-26*

---

## Summary

| Tool | Rules/Detectors | Entropy | ML/Semantic |
|------|----------------|---------|-------------|
| Gitleaks | 222 rules | Yes (per-rule, 2–4.5) | No — regex + entropy |
| TruffleHog | 700+ detectors | Yes (per-detector) | Some validators call live APIs |
| detect-secrets (Yelp) | 27 plugins | Yes (Base64: 4.5, Hex: 3.0) | No — regex + entropy |
| GitHub Secret Scanning | 200+ partner patterns | Not public | No |
| Semgrep secret rules | ~60 rules | No | No — regex only |
| **Our patterns.py** | **137 patterns** | **Yes (generic, 4.5)** | **No** |

---

## Gitleaks (222 rules)

Gold standard. Per-rule entropy thresholds, prefix-based keywords for fast pre-filter, elaborate context-capture regexes.

**Entropy approach**: per-rule field `entropy = X` (values seen: 2.0, 3.0, 3.5, 4.0, 4.5). Applied to the captured group, not the full match.

**Key techniques**:
- Uses capture group `([...]{N})` so entropy is computed on the secret only, not surrounding context
- Prefix/keyword list for pre-filtering (fast skip before full regex)
- `secretGroup` index to isolate high-entropy portion
- Allowlists per-rule for FP reduction

### Rules we are MISSING (not already in our patterns.py):

**Priority: HIGH (prefix-anchored, trivially matched, high occurrence)**

| Rule ID | Description | Regex (key part) |
|---------|-------------|-----------------|
| `1password-secret-key` | 1Password secret key | `A3-[A-Z0-9]{6}-...-[A-Z0-9]{5}` |
| `1password-service-account-token` | 1Password service acct | `ops_eyJ[a-zA-Z0-9+/]{250,}` |
| `alibaba-access-key-id` | Alibaba Cloud access key | `LTAI[a-z0-9]{20}` |
| `anthropic-admin-api-key` | Anthropic Admin key | `sk-ant-admin01-[a-zA-Z0-9_-]{93}AA` |
| `atlassian-api-token` | Jira/Confluence API token | `ATATT3[A-Za-z0-9_-=]{186}` |
| `databricks-api-token` | Databricks token | `dapi[a-f0-9]{32}` |
| `doppler-api-token` | Doppler secrets manager | `dp\.pt\.[a-z0-9]{43}` |
| `duffel-api-token` | Duffel travel API | `duffel_(test\|live)_[a-z0-9_-=]{43}` |
| `dynatrace-api-token` | Dynatrace monitoring | `dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}` |
| `flyio-access-token` | Fly.io token | `fo1_[\w-]{43}` or `fm1[ar]_[base64]{100+}` |
| `frameio-api-token` | Frame.io video | `fio-u-[a-z0-9-_=]{64}` |
| `grafana-api-key` | Grafana API key | `eyJrIjoi[A-Za-z0-9]{70,400}` |
| `grafana-cloud-api-token` | Grafana Cloud token | `glc_[A-Za-z0-9+/]{32,400}` |
| `grafana-service-account-token` | Grafana service account | `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}` |
| `harness-api-key` | Harness CI/CD | `(pat\|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}` |
| `hashicorp-tf-api-token` | Terraform Cloud API token | `[a-z0-9]{14}\.atlasv1\.[a-z0-9-_=]{60,70}` |
| `heroku-api-key-v2` | Heroku v2 API key | `HRKU-AA[0-9a-zA-Z_-]{58}` |
| `hubspot-api-key` | HubSpot CRM | `[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-...` (UUID format) |
| `infracost-api-token` | Infracost cloud cost | `ico-[a-zA-Z0-9]{32}` |
| `launchdarkly-access-token` | LaunchDarkly feature flags | `context-matched [a-z0-9-_=]{40}` |
| `maxmind-license-key` | MaxMind IP geolocation | `[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk` |
| `messagebird-api-token` | MessageBird SMS | `context-matched [a-z0-9]{25}` |
| `microsoft-teams-webhook` | MS Teams webhook URL | `webhook.office.com/webhookb2/...` |
| `new-relic-browser-api-token` | New Relic browser ingest | `NRJS-[a-f0-9]{19}` |
| `new-relic-insert-key` | New Relic insert key | `NRII-[a-z0-9-]{32}` |
| `new-relic-user-api-key` | New Relic user key | `NRAK-[a-z0-9]{27}` |
| `notion-api-token` | Notion (new format) | `ntn_[0-9]{11}[A-Za-z0-9]{35}` |
| `okta-access-token` | Okta auth | `00[\w=-]{40}` context-matched |
| `openshift-user-token` | OpenShift k8s | `sha256~[\w-]{43}` |
| `perplexity-api-key` | Perplexity AI | `pplx-[a-zA-Z0-9]{48}` |
| `planetscale-oauth-token` | PlanetScale OAuth | `pscale_oauth_[\w=.-]{32,64}` |
| `planetscale-password` | PlanetScale DB password | `pscale_pw_[\w=.-]{32,64}` |
| `postman-api-token` | Postman API | `PMAK-[a-f0-9]{24}-[a-f0-9]{34}` |
| `prefect-api-token` | Prefect workflow | `pnu_[a-zA-Z0-9]{36}` |
| `pulumi-api-token` | Pulumi IaC | `pul-[a-f0-9]{40}` |
| `readme-api-token` | Readme.io docs | `rdme_[a-z0-9]{70}` |
| `rubygems-api-token` | RubyGems registry | `rubygems_[a-f0-9]{48}` |
| `scalingo-api-token` | Scalingo PaaS | `tk-us-[\w-]{48}` |
| `sendinblue-api-token` | Brevo/Sendinblue email | `xkeysib-[a-f0-9]{64}-[a-z0-9]{16}` |
| `sentry-org-token` | Sentry org token | `sntrys_eyJpYXQiO[a-zA-Z0-9+/]{...}` |
| `sentry-user-token` | Sentry user token | `sntryu_[a-f0-9]{64}` |
| `shippo-api-token` | Shippo shipping | `shippo_(live\|test)_[a-fA-F0-9]{40}` |
| `shopify-access-token` | Shopify merchant | `shpat_[a-fA-F0-9]{32}` |
| `shopify-custom-access-token` | Shopify custom app | `shpca_[a-fA-F0-9]{32}` |
| `shopify-private-app-access-token` | Shopify private app | `shppa_[a-fA-F0-9]{32}` |
| `shopify-shared-secret` | Shopify shared secret | `shpss_[a-fA-F0-9]{32}` |
| `snyk-api-token` | Snyk security scanning | UUID format near `snyk` |
| `sonar-api-token` | SonarQube/SonarCloud | `squ_\|sqp_\|sqa_` prefix near sonar |
| `sourcegraph-access-token` | Sourcegraph code search | `sgp_[a-fA-F0-9]{16\|local}_[a-fA-F0-9]{40}` |
| `travisci-access-token` | Travis CI | context-matched `[a-z0-9]{22}` |
| `twitch-api-token` | Twitch streaming | context-matched `[a-z0-9]{30}` |
| `typeform-api-token` | Typeform surveys | `tfp_[a-z0-9-_.=]{59}` |
| `vault-batch-token` | HashiCorp Vault batch | `hvb\.[\w-]{138,300}` |
| `zendesk-secret-key` | Zendesk support | context-matched `[a-z0-9]{40}` |
| `age-secret-key` | Age encryption tool | `AGE-SECRET-KEY-1[bech32]{58}` |
| `artifactory-api-key` | JFrog Artifactory | `AKCp[A-Za-z0-9]{69}` |
| `clojars-api-token` | Clojars Clojure pkg mgr | `CLOJARS_[a-z0-9]{60}` |
| `codecov-access-token` | Codecov coverage | context-matched `[a-z0-9]{32}` |
| `contentful-delivery-api-token` | Contentful CMS | context-matched `[a-z0-9=-]{43}` |
| `digitalocean-refresh-token` | DigitalOcean OAuth refresh | `dor_v1_[a-f0-9]{64}` |
| `droneci-access-token` | Drone CI | context-matched `[a-z0-9]{32}` |
| `dropbox-api-token` | Dropbox | context-matched `[a-z0-9]{15}` |
| `easypost-api-token` | EasyPost shipping | `EZAK[a-z0-9]{54}` |
| `etsy-access-token` | Etsy marketplace | context-matched `[a-z0-9]{24}` |
| `fastly-api-token` | Fastly CDN | context-matched `[a-z0-9=-]{32}` |
| `finicity-api-token` | Finicity fintech | context-matched `[a-f0-9]{32}` |
| `finnhub-access-token` | Finnhub stock data | context-matched `[a-z0-9]{20}` |
| `flickr-access-token` | Flickr photo | context-matched `[a-z0-9]{32}` |
| `freshbooks-access-token` | FreshBooks invoicing | context-matched `[a-z0-9]{64}` |
| `gitter-access-token` | Gitter chat | context-matched `[a-z0-9]{40}` |
| `gitlab-cicd-job-token` | GitLab CI job | `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}` |
| `gitlab-deploy-token` | GitLab deploy | `gldt-[0-9a-zA-Z_-]{20}` |
| `gocardless-api-token` | GoCardless payments | `live_[a-z0-9-_=]{40}` near gocardless |
| `intercom-api-key` | Intercom customer msg | context-matched `[a-z0-9=-]{60}` |
| `jfrog-api-key` | JFrog Xray/Artifactory | context-matched `[a-z0-9]{73}` |
| `lob-api-key` | Lob direct mail API | `(live\|test)_[a-f0-9]{35}` |
| `looker-client-id` | Looker BI | context-matched `[a-z0-9]{20}` |
| `mailgun-signing-key` | Mailgun webhook sign key | `[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}` |
| `mattermost-access-token` | Mattermost team chat | context-matched `[a-z0-9]{26}` |
| `nytimes-access-token` | NY Times API | context-matched `[a-z0-9=-]{32}` |
| `plaid-api-token` | Plaid fintech | `access-(sandbox\|development\|production)-[uuid]` |
| `rapidapi-access-token` | RapidAPI marketplace | context-matched `[a-z0-9_-]{50}` |
| `sendbird-access-token` | Sendbird chat | context-matched `[a-f0-9]{40}` |
| `settlemint-application-access-token` | SettleMint blockchain | `sm_aat_[a-zA-Z0-9]{16}` |
| `sidekiq-secret` | Sidekiq Pro/Enterprise | `[a-f0-9]{8}:[a-f0-9]{8}` near BUNDLE_CONTRIBSYS |
| `slack-config-access-token` | Slack config token | `xoxe.xox[bp]-\d-[A-Z0-9]{163,166}` |
| `slack-legacy-token` | Slack legacy user/OAuth | `xox[os]-\d+-\d+-\d+-[a-fA-F0-9]+` |
| `sumologic-access-id` | Sumo Logic SIEM | `su[a-zA-Z0-9]{12}` near sumo |
| `sumologic-access-token` | Sumo Logic access token | context-matched `[a-z0-9]{64}` |
| `twitter-access-secret` | Twitter/X access secret | context-matched `[a-z0-9]{45}` |
| `twitter-access-token` | Twitter/X access token | context-matched `[0-9]{15,25}-[a-zA-Z0-9]{20,40}` |
| `twitter-api-key` | Twitter/X API key | context-matched `[a-z0-9]{25}` |
| `twitter-api-secret` | Twitter/X API secret | context-matched `[a-z0-9]{50}` |
| `yandex-access-token` | Yandex OAuth token | `t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}` |
| `yandex-api-key` | Yandex API key | `AQVN[A-Za-z0-9_-]{35,38}` |
| `yandex-aws-access-token` | Yandex AWS-compat token | `YC[a-zA-Z0-9_-]{38}` |
| `alibaba-secret-key` | Alibaba Cloud secret | context-matched `[a-z0-9]{30}` |
| `cisco-meraki-api-key` | Cisco Meraki network | `[0-9a-f]{40}` near meraki |
| `beamer-api-token` | Beamer changelog | `b_[a-z0-9=_-]{44}` near beamer |
| `clickhouse-cloud-api-secret-key` | ClickHouse Cloud | entropy-based near `4b1d` |
| `confluent-access-token` | Confluent Kafka | context-matched |
| `confluent-secret-key` | Confluent Kafka secret | context-matched |

---

## TruffleHog (700+ detectors)

TruffleHog's killer feature: **live secret validation** — it calls the actual API to verify if the secret is active, dramatically cutting FPs.

**Services covered we don't have (sample of TH-only detectors from alpha listing):**

abstract, abuseipdb, abyssale, accuweather, adafruitio, adobeio, adzuna, aeroworkflow, agora, aha, airbrakeprojectkey, airbrakeuserkey, airship, airtableoauth, airvisual, aiven, alconost, alegra, aletheiaapi, alienvault, allsports, amadeus, ambee, amplitudeapikey, anypoint, anypointoauth2, apacta, api2cart, apideck, apiflash, apifonica, apify, apilayer, apimatic, apimetrics, apitemplate, apollo, appcues, appfollow, appointedd, appoptics, appsynergy, apptivo, artsy, assemblyai, atera, atlassiandatacenter, audd, auth0managementapitoken, auth0oauth, autodesk, autoklose, autopilot, avazapersonalaccesstoken, aviationstack, axonaut, aylien, ayrshare, azure_batch, azure_cosmosdb, azure_entra, azure_openai, azure_storage, azureapimanagement, azureapimanagementsubscriptionkey, azureappconfigconnectionstring, azurecontainerregistry, azuredevopspersonalaccesstoken, azuredirectmanagementkey, azurefunctionkey, azuresastoken, azuresearchadminkey, azuresearchquerykey, bannerbear, baremetrics, beebole, besnappy, besttime, betterstack, billomat, bingsubscriptionkey, bitbar, bitbucketapppassword, bitcoinaverage, bitfinex, bitlyaccesstoken, bitmex, blazemeter ...

**High-value TH-only patterns to add:**
- `azure_entra` — Azure Entra ID tokens (modern AAD)
- `azure_openai` — Azure OpenAI API keys
- `azuredevopspersonalaccesstoken` — Azure DevOps PAT
- `azurefunctionkey` — Azure Function keys
- `azuresastoken` — Azure SAS tokens (URL-embedded)
- `azuresearchadminkey` / `azuresearchquerykey` — Azure AI Search
- `auth0managementapitoken` — Auth0 Management API token
- `bitbucketapppassword` — Bitbucket App Password
- `bingsubscriptionkey` — Bing/Azure Cognitive search key

---

## detect-secrets (Yelp) — 27 plugins

**Entropy thresholds:**
- Base64 high-entropy string: **4.5 bits/char** (same as ours)
- Hex high-entropy string: **3.0 bits/char**

**Notable plugins we're missing:**
- `IbmCloudIamDetector` — IBM Cloud IAM keys (`ibm_api_key` format)
- `IbmCosHmacDetector` — IBM Cloud Object Storage HMAC
- `CloudantDetector` — IBM Cloudant DB credentials
- `SoftlayerDetector` — IBM SoftLayer/Classic Infrastructure
- `BasicAuthDetector` — `http://user:pass@host` in URLs
- `IPPublicDetector` — public IPs in configs (info severity)
- `NpmDetector` — npm auth in `.npmrc` (we only have `npm_token`)
- `SquareOAuthDetector` — Square OAuth token (`sq0csp-` prefix)
- `HexHighEntropyString` — pure hex blobs ≥ 3.0 entropy (we only do base64-style)

**detect-secrets key insight**: `KeywordDetector` scans for high-risk variable names (`password`, `secret`, `token`, `key`, `pwd`, `passwd`, `private`, `credential`) with high-entropy values adjacent — pure variable-name + entropy heuristic, no provider-specific regex.

---

## GitHub Partner Patterns (200+ providers)

GitHub's secret scanning covers these providers not yet in our patterns.py:

**High-priority new providers:**
- **Adafruit** — `adafruit_` prefix API keys
- **Authress** — `sc_` / `ext_` / `scauth_` prefix
- **Buildkite** — `bkua_` prefix agent tokens
- **Canva** — Connect API tokens
- **Checkout.com** — `sk_` prefix payment keys
- **Cockroach Labs** — CockroachDB cloud keys
- **Contentful** — CMS delivery tokens
- **Databricks** — `dapi` prefix (we're missing)
- **Doppler** — `dp.pt.` prefix
- **Dropbox** — OAuth tokens
- **Dynatrace** — `dt0c01.` prefix
- **Fastly** — CDN API tokens
- **Figma** — Design API tokens (`figd_` prefix)
- **Frame.io** — Video API (`fio-u-` prefix)
- **FullStory** — Analytics tokens
- **GoCardless** — Payments (`live_` prefix)
- **Grafana** — `glc_` / `glsa_` / `eyJrIjoi` prefixes
- **Harness** — `pat.` / `sat.` prefix
- **Highnote** — Financial platform
- **Infracost** — `ico-` prefix
- **JFrog** — `AKCp` or context-matched Artifactory
- **LaunchDarkly** — Feature flags
- **Lark** — ByteDance enterprise messaging
- **MaxMind** — `_mmk` suffix geolocation keys
- **Mercury** — Banking API
- **MessageBird** — SMS/voice
- **MongoDB Atlas** — Database cloud tokens
- **New Relic** — `NRJS-` / `NRII-` / `NRAK-` prefixes
- **Octopus Deploy** — CD platform
- **OpenRouter** — LLM proxy API keys
- **Paddle** — Payments
- **Palantir** — Data platform
- **Planning Center** — Church management SaaS
- **Plivo** — Communications
- **Polar** — Developer payments
- **Postman** — `PMAK-` prefix
- **Proctorio** — EdTech
- **Pulumi** — `pul-` prefix IaC
- **Raycast** — macOS productivity
- **ReadMe** — `rdme_` prefix docs platform
- **RunPod** — GPU cloud
- **Scalr** — Terraform automation (`tk-us-` prefix)
- **Segment** — Analytics
- **Sendbird** — Chat API
- **Shopify** — `shpat_` / `shpca_` / `shppa_` / `shpss_` prefixes
- **Sindri** — ZK proof API
- **Snyk** — Security scanning (UUID near snyk)
- **Squarespace** — Website builder
- **Tailscale** — VPN mesh API keys
- **Telnyx** — Communications
- **Temporal** — Workflow orchestration
- **Typeform** — `tfp_` prefix survey API
- **Workato** — iPaaS automation
- **WorkOS** — Enterprise SSO
- **Yandex** — `AQVN` / `YC` / `t1.` prefixes

---

## Semgrep Secret Rules (~60 rules)

Semgrep's rules largely overlap with Gitleaks (many are ported). Unique additions:
- `bcrypt-hash` — detects committed bcrypt hashes (password hashes = credential exposure)
- `username-password-uri` — `http://user:pass@host` URI pattern (similar to BasicAuthDetector)
- Sauce Labs, HockeyApp, Picatic, Onfido, Kolide — niche SaaS
- CodeClimate token pattern
- Squarespace access token

---

## FINAL: Patterns to Add to patterns.py (priority order)

### 1. HIGH PRIORITY — Prefix-anchored, high occurrence in wild:
1. `shopify_access_token` — `shpat_[a-fA-F0-9]{32}` (Shopify is massive)
2. `shopify_custom_access_token` — `shpca_[a-fA-F0-9]{32}`
3. `shopify_private_app_token` — `shppa_[a-fA-F0-9]{32}`
4. `shopify_shared_secret` — `shpss_[a-fA-F0-9]{32}`
5. `databricks_api_token` — `dapi[a-f0-9]{32}` (widely used in data engineering)
6. `anthropic_admin_key` — `sk-ant-admin01-[a-zA-Z0-9_-]{93}AA`
7. `atlassian_api_token` — `ATATT3[A-Za-z0-9_-=]{186}` (Jira/Confluence ubiquitous)
8. `new_relic_browser_token` — `NRJS-[a-f0-9]{19}`
9. `new_relic_insert_key` — `NRII-[a-z0-9-]{32}`
10. `new_relic_user_key` — `NRAK-[a-z0-9]{27}`
11. `grafana_api_key` — `eyJrIjoi[A-Za-z0-9]{70,400}`
12. `grafana_cloud_token` — `glc_[A-Za-z0-9+/]{32,400}`
13. `grafana_service_account` — `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`
14. `doppler_api_token` — `dp\.pt\.[a-z0-9]{43}`
15. `postman_api_token` — `PMAK-[a-f0-9]{24}-[a-f0-9]{34}`
16. `perplexity_api_key` — `pplx-[a-zA-Z0-9]{48}`
17. `pulumi_api_token` — `pul-[a-f0-9]{40}`
18. `snyk_api_token` — UUID near snyk keyword
19. `dynatrace_api_token` — `dt0c01.[a-z0-9]{24}.[a-z0-9]{64}`
20. `notion_api_token_v2` — `ntn_[0-9]{11}[A-Za-z0-9]{35}` (new Notion format)

### 2. MEDIUM PRIORITY — Common services, prefix-anchored:
21. `sendinblue_api_token` (Brevo) — `xkeysib-[a-f0-9]{64}-[a-z0-9]{16}`
22. `sentry_user_token` — `sntryu_[a-f0-9]{64}`
23. `sentry_org_token` — `sntrys_eyJpYXQiO...`
24. `typeform_api_token` — `tfp_[a-z0-9-_.=]{59}`
25. `frameio_api_token` — `fio-u-[a-z0-9-_=]{64}`
26. `1password_service_account` — `ops_eyJ[a-zA-Z0-9+/]{250,}`
27. `harness_api_key` — `(pat|sat).[a-zA-Z0-9_-]{22}.[a-zA-Z0-9]{24}.[a-zA-Z0-9]{20}`
28. `okta_access_token` — `00[\w=-]{40}` near okta
29. `openshift_user_token` — `sha256~[\w-]{43}`
30. `rubygems_api_token` — `rubygems_[a-f0-9]{48}`
31. `shippo_api_token` — `shippo_(live|test)_[a-fA-F0-9]{40}`
32. `easypost_api_token` — `EZAK[a-z0-9]{54}`
33. `artifactory_api_key` — `AKCp[A-Za-z0-9]{69}`
34. `scalingo_api_token` — `tk-us-[\w-]{48}`
35. `prefect_api_token` — `pnu_[a-zA-Z0-9]{36}`
36. `readme_api_token` — `rdme_[a-z0-9]{70}`
37. `vault_batch_token` — `hvb\.[\w-]{138,300}`
38. `planetscale_oauth_token` — `pscale_oauth_[\w=.-]{32,64}`
39. `planetscale_password` — `pscale_pw_[\w=.-]{32,64}`
40. `age_secret_key` — `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`

### 3. LOWER PRIORITY — Context-matched, niche, or lower FP risk:
41. `alibaba_access_key` — `LTAI[a-z0-9]{20}` (Alibaba Cloud)
42. `alibaba_secret_key` — context-matched near alibaba
43. `clojars_api_token` — `CLOJARS_[a-z0-9]{60}`
44. `maxmind_license_key` — `[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`
45. `yandex_access_token` — `t1.[A-Z0-9a-z_-]+.[A-Z0-9a-z_-]{86}`
46. `yandex_api_key` — `AQVN[A-Za-z0-9_-]{35,38}`
47. `yandex_aws_token` — `YC[a-zA-Z0-9_-]{38}`
48. `microsoft_teams_webhook` — `webhook.office.com/webhookb2/...`
49. `hubspot_api_key` — UUID-format near hubspot
50. `hashicorp_tf_api_token` — `atlasv1.` prefix token
51. `launchdarkly_token` — context-matched near launchdarkly
52. `heroku_api_key_v2` — `HRKU-AA[0-9a-zA-Z_-]{58}`
53. `twitch_api_token` — context-matched near twitch
54. `twitter_access_token` — `[0-9]{15,25}-[a-zA-Z0-9]{20,40}` near twitter
55. `twitter_api_secret` — context-matched `[a-z0-9]{50}` near twitter
56. `sonar_api_token` — `squ_|sqp_|sqa_` prefix near sonar
57. `cisco_meraki_api_key` — `[0-9a-f]{40}` near meraki
58. `ibm_cloud_api_key` — `ibm_cloud_` or context-matched IBM IAM key format
59. `square_oauth_token` — `sq0csp-[A-Za-z0-9-_]{43}` (Square OAuth, differs from sq0atp)
60. `basic_auth_url` — `https?://[^:]+:[^@]{6,}@[^/\s"']+` (credentials in URLs)
