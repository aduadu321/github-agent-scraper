"""
missing_patterns.py — New patterns to add to patterns.py
Sources: Gitleaks 222 rules, TruffleHog 700+ detectors, detect-secrets, GitHub partner patterns
Target: Bring patterns.py from 137 → 300+ entries.

Schema matches patterns.py PATTERNS dict:
  {
    "regex": str,
    "severity": str,          # CRITICAL / HIGH / MEDIUM / LOW
    "description": str,
    "false_positive_hints": list[str],
    # optional:
    "entropy_min": float,     # minimum Shannon entropy for the captured group
    "keywords": list[str],    # fast pre-filter keywords (gitleaks style)
  }

Integrate by merging NEW_PATTERNS into patterns.PATTERNS.
Do NOT add keys already present in patterns.PATTERNS (see existing 137 keys).
"""

NEW_PATTERNS: dict[str, dict] = {

    # ── SHOPIFY (4 token types — massive e-commerce platform) ─────────────────
    "shopify_access_token": {
        "regex": r"shpat_[a-fA-F0-9]{32}",
        "severity": "CRITICAL",
        "description": "Shopify merchant access token (shpat_ prefix)",
        "keywords": ["shpat_"],
        "false_positive_hints": ["shpat_xxxx", "shpat_example", "shpat_test"],
    },
    "shopify_custom_access_token": {
        "regex": r"shpca_[a-fA-F0-9]{32}",
        "severity": "CRITICAL",
        "description": "Shopify custom app access token (shpca_ prefix)",
        "keywords": ["shpca_"],
        "false_positive_hints": ["shpca_xxxx", "shpca_example"],
    },
    "shopify_private_app_token": {
        "regex": r"shppa_[a-fA-F0-9]{32}",
        "severity": "CRITICAL",
        "description": "Shopify private app access token (shppa_ prefix)",
        "keywords": ["shppa_"],
        "false_positive_hints": ["shppa_xxxx", "shppa_example"],
    },
    "shopify_shared_secret": {
        "regex": r"shpss_[a-fA-F0-9]{32}",
        "severity": "HIGH",
        "description": "Shopify shared secret (shpss_ prefix)",
        "keywords": ["shpss_"],
        "false_positive_hints": ["shpss_xxxx", "shpss_example"],
    },

    # ── DATABRICKS ─────────────────────────────────────────────────────────────
    "databricks_api_token": {
        "regex": r"\bdapi[a-f0-9]{32}(?:-\d)?\b",
        "severity": "CRITICAL",
        "description": "Databricks personal access token (dapi prefix)",
        "keywords": ["dapi"],
        "entropy_min": 3.0,
        "false_positive_hints": ["dapi0000000000000000000000000000", "example", "xxxx"],
    },

    # ── ANTHROPIC ADMIN KEY ────────────────────────────────────────────────────
    "anthropic_admin_key": {
        "regex": r"\bsk-ant-admin01-[a-zA-Z0-9_\-]{93}AA\b",
        "severity": "CRITICAL",
        "description": "Anthropic Admin API key (sk-ant-admin01- prefix, full account access)",
        "keywords": ["sk-ant-admin01-"],
        "false_positive_hints": ["sk-ant-admin01-xxxx", "example"],
    },

    # ── ATLASSIAN (Jira/Confluence) ────────────────────────────────────────────
    "atlassian_api_token": {
        "regex": r"\bATATT3[A-Za-z0-9_\-=]{186}\b",
        "severity": "CRITICAL",
        "description": "Atlassian API token (ATATT3 prefix — Jira/Confluence access)",
        "keywords": ["atatt3"],
        "entropy_min": 3.5,
        "false_positive_hints": ["ATATT3xxxx", "example"],
    },

    # ── NEW RELIC (3 key types) ────────────────────────────────────────────────
    "new_relic_browser_api_token": {
        "regex": r"\bNRJS-[a-f0-9]{19}\b",
        "severity": "HIGH",
        "description": "New Relic browser ingest API token (NRJS- prefix)",
        "keywords": ["nrjs-"],
        "false_positive_hints": ["NRJS-xxxx", "NRJS-example"],
    },
    "new_relic_insert_key": {
        "regex": r"\bNRII-[a-zA-Z0-9\-]{32}\b",
        "severity": "HIGH",
        "description": "New Relic Insights insert key (NRII- prefix)",
        "keywords": ["nrii-"],
        "false_positive_hints": ["NRII-xxxx", "NRII-example"],
    },
    "new_relic_user_api_key": {
        "regex": r"\bNRAK-[a-zA-Z0-9]{27}\b",
        "severity": "HIGH",
        "description": "New Relic user API key (NRAK- prefix)",
        "keywords": ["nrak-"],
        "false_positive_hints": ["NRAK-xxxx", "NRAK-example"],
    },

    # ── GRAFANA (3 token types) ────────────────────────────────────────────────
    "grafana_api_key": {
        "regex": r"\beyJrIjoi[A-Za-z0-9+/]{70,400}={0,3}\b",
        "severity": "HIGH",
        "description": "Grafana API key (eyJrIjoi base64 prefix)",
        "keywords": ["eyjrijoi"],
        "entropy_min": 3.0,
        "false_positive_hints": ["eyJrIjoixxxx", "example"],
    },
    "grafana_cloud_api_token": {
        "regex": r"\bglc_[A-Za-z0-9+/]{32,400}={0,3}",
        "severity": "HIGH",
        "description": "Grafana Cloud API token (glc_ prefix)",
        "keywords": ["glc_"],
        "entropy_min": 3.0,
        "false_positive_hints": ["glc_xxxx", "glc_example"],
    },
    "grafana_service_account_token": {
        "regex": r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b",
        "severity": "HIGH",
        "description": "Grafana service account token (glsa_ prefix)",
        "keywords": ["glsa_"],
        "false_positive_hints": ["glsa_xxxx_00000000", "example"],
    },

    # ── DOPPLER ────────────────────────────────────────────────────────────────
    "doppler_api_token": {
        "regex": r"\bdp\.pt\.[a-zA-Z0-9]{43}\b",
        "severity": "HIGH",
        "description": "Doppler secrets manager API token (dp.pt. prefix)",
        "keywords": ["dp.pt."],
        "entropy_min": 2.0,
        "false_positive_hints": ["dp.pt.xxxx", "dp.pt.example"],
    },

    # ── POSTMAN ────────────────────────────────────────────────────────────────
    "postman_api_token": {
        "regex": r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
        "severity": "HIGH",
        "description": "Postman API token (PMAK- prefix)",
        "keywords": ["pmak-"],
        "false_positive_hints": ["PMAK-xxxx", "PMAK-example"],
    },

    # ── PERPLEXITY AI ──────────────────────────────────────────────────────────
    "perplexity_api_key": {
        "regex": r"\bpplx-[a-zA-Z0-9]{48}\b",
        "severity": "CRITICAL",
        "description": "Perplexity AI API key (pplx- prefix)",
        "keywords": ["pplx-"],
        "entropy_min": 4.0,
        "false_positive_hints": ["pplx-xxxx", "pplx-example"],
    },

    # ── PULUMI ─────────────────────────────────────────────────────────────────
    "pulumi_api_token": {
        "regex": r"\bpul-[a-f0-9]{40}\b",
        "severity": "HIGH",
        "description": "Pulumi Infrastructure-as-Code API token (pul- prefix)",
        "keywords": ["pul-"],
        "entropy_min": 2.0,
        "false_positive_hints": ["pul-xxxx", "pul-example"],
    },

    # ── SNYK ───────────────────────────────────────────────────────────────────
    "snyk_api_token": {
        "regex": r"(?i)(?:snyk[_.\-]?(?:(?:api|oauth)[_.\-]?)?(?:key|token))\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "severity": "HIGH",
        "description": "Snyk security scanning API token (UUID format, context-matched near snyk)",
        "keywords": ["snyk"],
        "false_positive_hints": ["00000000-0000-0000-0000-000000000000", "example", "xxxx"],
    },

    # ── DYNATRACE ──────────────────────────────────────────────────────────────
    "dynatrace_api_token": {
        "regex": r"\bdt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}\b",
        "severity": "HIGH",
        "description": "Dynatrace API token (dt0c01. prefix)",
        "keywords": ["dt0c01."],
        "entropy_min": 4.0,
        "false_positive_hints": ["dt0c01.xxxx", "example"],
    },

    # ── NOTION (new ntn_ format) ───────────────────────────────────────────────
    "notion_api_token_v2": {
        "regex": r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b",
        "severity": "HIGH",
        "description": "Notion integration token (new ntn_ format, 2024+)",
        "keywords": ["ntn_"],
        "entropy_min": 4.0,
        "false_positive_hints": ["ntn_00000000000xxxx", "example"],
    },

    # ── SENDINBLUE / BREVO ─────────────────────────────────────────────────────
    "sendinblue_api_token": {
        "regex": r"\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b",
        "severity": "HIGH",
        "description": "Brevo/Sendinblue email API token (xkeysib- prefix)",
        "keywords": ["xkeysib-"],
        "entropy_min": 2.0,
        "false_positive_hints": ["xkeysib-xxxx", "example"],
    },

    # ── SENTRY (2 new token formats) ──────────────────────────────────────────
    "sentry_user_token": {
        "regex": r"\bsntryu_[a-f0-9]{64}\b",
        "severity": "HIGH",
        "description": "Sentry.io user auth token (sntryu_ prefix)",
        "keywords": ["sntryu_"],
        "entropy_min": 3.5,
        "false_positive_hints": ["sntryu_xxxx", "example"],
    },
    "sentry_org_token": {
        "regex": r"\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}",
        "severity": "CRITICAL",
        "description": "Sentry.io organization auth token (sntrys_ prefix)",
        "keywords": ["sntrys_"],
        "entropy_min": 4.5,
        "false_positive_hints": ["sntrys_xxxx", "example"],
    },

    # ── TYPEFORM ───────────────────────────────────────────────────────────────
    "typeform_api_token": {
        "regex": r"(?i)(?:typeform)(?:[\s\w.-]{0,20})[\s=:\"']{1,5}(tfp_[a-zA-Z0-9\-_\.=]{59})",
        "severity": "MEDIUM",
        "description": "Typeform survey API token (tfp_ prefix, context-matched)",
        "keywords": ["typeform", "tfp_"],
        "false_positive_hints": ["tfp_xxxx", "example"],
    },

    # ── FRAME.IO ───────────────────────────────────────────────────────────────
    "frameio_api_token": {
        "regex": r"\bfio-u-[a-zA-Z0-9\-_=]{64}\b",
        "severity": "HIGH",
        "description": "Frame.io video collaboration API token (fio-u- prefix)",
        "keywords": ["fio-u-"],
        "false_positive_hints": ["fio-u-xxxx", "example"],
    },

    # ── 1PASSWORD ──────────────────────────────────────────────────────────────
    "onepassword_service_account": {
        "regex": r"\bops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
        "severity": "CRITICAL",
        "description": "1Password service account token (ops_eyJ prefix)",
        "keywords": ["ops_eyj"],
        "entropy_min": 4.0,
        "false_positive_hints": ["ops_eyJxxxx", "example"],
    },
    "onepassword_secret_key": {
        "regex": r"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b",
        "severity": "CRITICAL",
        "description": "1Password account secret key (A3- prefix with structured format)",
        "keywords": ["a3-"],
        "false_positive_hints": ["A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX", "example"],
    },

    # ── HARNESS ────────────────────────────────────────────────────────────────
    "harness_api_key": {
        "regex": r"\b(?:pat|sat)\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}\b",
        "severity": "HIGH",
        "description": "Harness CI/CD platform API token (pat./sat. structured prefix)",
        "keywords": ["pat.", "sat."],
        "false_positive_hints": ["pat.xxxx", "sat.xxxx", "example"],
    },

    # ── OKTA ───────────────────────────────────────────────────────────────────
    "okta_access_token": {
        "regex": r"(?i)(?:okta)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}(00[\w=\-]{40})",
        "severity": "HIGH",
        "description": "Okta API access token (00 prefix, 42 chars, context-matched near okta)",
        "keywords": ["okta"],
        "entropy_min": 4.0,
        "false_positive_hints": ["00xxxx", "example", "your_token"],
    },

    # ── OPENSHIFT ─────────────────────────────────────────────────────────────
    "openshift_user_token": {
        "regex": r"\bsha256~[\w\-]{43}\b",
        "severity": "HIGH",
        "description": "OpenShift/Kubernetes user auth token (sha256~ prefix)",
        "keywords": ["sha256~"],
        "entropy_min": 3.5,
        "false_positive_hints": ["sha256~xxxx", "example"],
    },

    # ── RUBYGEMS ───────────────────────────────────────────────────────────────
    "rubygems_api_token": {
        "regex": r"\brubygems_[a-f0-9]{48}\b",
        "severity": "HIGH",
        "description": "RubyGems.org API token (rubygems_ prefix)",
        "keywords": ["rubygems_"],
        "false_positive_hints": ["rubygems_xxxx", "example"],
    },

    # ── SHIPPO ─────────────────────────────────────────────────────────────────
    "shippo_api_token": {
        "regex": r"\bshippo_(?:live|test)_[a-fA-F0-9]{40}\b",
        "severity": "HIGH",
        "description": "Shippo shipping API token (shippo_live_ or shippo_test_ prefix)",
        "keywords": ["shippo_live_", "shippo_test_"],
        "false_positive_hints": ["shippo_live_xxxx", "shippo_test_xxxx", "example"],
    },

    # ── EASYPOST ───────────────────────────────────────────────────────────────
    "easypost_api_token": {
        "regex": r"\bEZAK[a-zA-Z0-9]{54}\b",
        "severity": "HIGH",
        "description": "EasyPost shipping API token (EZAK prefix)",
        "keywords": ["ezak"],
        "false_positive_hints": ["EZAKxxxx", "example"],
    },
    "easypost_test_token": {
        "regex": r"\bEZTK[a-zA-Z0-9]{54}\b",
        "severity": "MEDIUM",
        "description": "EasyPost test API token (EZTK prefix)",
        "keywords": ["eztk"],
        "false_positive_hints": ["EZTKxxxx", "example"],
    },

    # ── JFROG ARTIFACTORY ─────────────────────────────────────────────────────
    "artifactory_api_key": {
        "regex": r"\bAKCp[A-Za-z0-9]{69}\b",
        "severity": "HIGH",
        "description": "JFrog Artifactory API key (AKCp prefix)",
        "keywords": ["akcp"],
        "entropy_min": 4.5,
        "false_positive_hints": ["AKCpxxxx", "example"],
    },
    "jfrog_identity_token": {
        "regex": r"(?i)(?:jfrog|artifactory|bintray|xray)(?:[\s\w.-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{73})",
        "severity": "HIGH",
        "description": "JFrog identity/reference token (context-matched near jfrog/artifactory)",
        "keywords": ["jfrog", "artifactory", "xray"],
        "entropy_min": 4.5,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── SCALINGO ───────────────────────────────────────────────────────────────
    "scalingo_api_token": {
        "regex": r"\btk-us-[\w\-]{48}\b",
        "severity": "HIGH",
        "description": "Scalingo PaaS API token (tk-us- prefix)",
        "keywords": ["tk-us-"],
        "entropy_min": 2.0,
        "false_positive_hints": ["tk-us-xxxx", "example"],
    },

    # ── PREFECT ────────────────────────────────────────────────────────────────
    "prefect_api_token": {
        "regex": r"\bpnu_[a-zA-Z0-9]{36}\b",
        "severity": "HIGH",
        "description": "Prefect workflow orchestration API token (pnu_ prefix)",
        "keywords": ["pnu_"],
        "entropy_min": 2.0,
        "false_positive_hints": ["pnu_xxxx", "example"],
    },

    # ── README.IO ─────────────────────────────────────────────────────────────
    "readme_api_token": {
        "regex": r"\brdme_[a-zA-Z0-9]{70}\b",
        "severity": "MEDIUM",
        "description": "ReadMe.io documentation API token (rdme_ prefix)",
        "keywords": ["rdme_"],
        "entropy_min": 2.0,
        "false_positive_hints": ["rdme_xxxx", "example"],
    },

    # ── HASHICORP VAULT (batch token — different from service token) ───────────
    "vault_batch_token": {
        "regex": r"\bhvb\.[\w\-]{138,300}\b",
        "severity": "HIGH",
        "description": "HashiCorp Vault batch token (hvb. prefix — longer than service tokens)",
        "keywords": ["hvb."],
        "entropy_min": 4.0,
        "false_positive_hints": ["hvb.xxxx", "example"],
    },

    # ── PLANETSCALE EXTENDED ───────────────────────────────────────────────────
    "planetscale_oauth_token": {
        "regex": r"\bpscale_oauth_[\w=.\-]{32,64}\b",
        "severity": "HIGH",
        "description": "PlanetScale OAuth token (pscale_oauth_ prefix)",
        "keywords": ["pscale_oauth_"],
        "entropy_min": 3.0,
        "false_positive_hints": ["pscale_oauth_xxxx", "example"],
    },
    "planetscale_password": {
        "regex": r"\bpscale_pw_[\w=.\-]{32,64}\b",
        "severity": "HIGH",
        "description": "PlanetScale database password (pscale_pw_ prefix)",
        "keywords": ["pscale_pw_"],
        "entropy_min": 3.0,
        "false_positive_hints": ["pscale_pw_xxxx", "example"],
    },

    # ── AGE ENCRYPTION ────────────────────────────────────────────────────────
    "age_secret_key": {
        "regex": r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b",
        "severity": "CRITICAL",
        "description": "Age encryption tool secret key (AGE-SECRET-KEY-1 bech32 prefix)",
        "keywords": ["age-secret-key-1"],
        "false_positive_hints": ["AGE-SECRET-KEY-1xxxx", "example"],
    },

    # ── ALIBABA CLOUD ─────────────────────────────────────────────────────────
    "alibaba_access_key_id": {
        "regex": r"\bLTAI[a-zA-Z0-9]{20}\b",
        "severity": "HIGH",
        "description": "Alibaba Cloud AccessKey ID (LTAI prefix)",
        "keywords": ["ltai"],
        "entropy_min": 2.0,
        "false_positive_hints": ["LTAIxxxx", "LTAIexample"],
    },
    "alibaba_secret_key": {
        "regex": r"(?i)(?:alibaba)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-z0-9]{30})",
        "severity": "HIGH",
        "description": "Alibaba Cloud secret key (context-matched near alibaba, 30-char lowercase hex)",
        "keywords": ["alibaba"],
        "entropy_min": 2.0,
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── CLOJARS ────────────────────────────────────────────────────────────────
    "clojars_api_token": {
        "regex": r"(?i)\bCLOJARS_[a-zA-Z0-9]{60}\b",
        "severity": "HIGH",
        "description": "Clojars Clojure package registry API token (CLOJARS_ prefix)",
        "keywords": ["clojars_"],
        "entropy_min": 2.0,
        "false_positive_hints": ["CLOJARS_xxxx", "example"],
    },

    # ── MAXMIND ────────────────────────────────────────────────────────────────
    "maxmind_license_key": {
        "regex": r"\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\b",
        "severity": "MEDIUM",
        "description": "MaxMind GeoIP database license key (_mmk suffix)",
        "keywords": ["_mmk"],
        "entropy_min": 4.0,
        "false_positive_hints": ["xxxxxx_xxxx_mmk", "example"],
    },

    # ── YANDEX (3 token types) ────────────────────────────────────────────────
    "yandex_access_token": {
        "regex": r"(?i)(?:yandex)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}(t1\.[A-Z0-9a-z_\-]+={0,2}\.[A-Z0-9a-z_\-]{86}={0,2})",
        "severity": "HIGH",
        "description": "Yandex OAuth access token (t1. prefix, context-matched)",
        "keywords": ["yandex"],
        "false_positive_hints": ["t1.xxxx", "example"],
    },
    "yandex_api_key": {
        "regex": r"\bAQVN[A-Za-z0-9_\-]{35,38}\b",
        "severity": "HIGH",
        "description": "Yandex Cloud API key (AQVN prefix)",
        "keywords": ["aqvn"],
        "false_positive_hints": ["AQVNxxxx", "example"],
    },
    "yandex_aws_access_token": {
        "regex": r"\bYC[a-zA-Z0-9_\-]{38}\b",
        "severity": "HIGH",
        "description": "Yandex AWS-compatible access token (YC prefix)",
        "keywords": ["yc"],
        "false_positive_hints": ["YCxxxx", "example"],
    },

    # ── MICROSOFT TEAMS ────────────────────────────────────────────────────────
    "microsoft_teams_webhook": {
        "regex": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}",
        "severity": "HIGH",
        "description": "Microsoft Teams incoming webhook URL (contains org/tenant identifiers)",
        "keywords": ["webhook.office.com"],
        "false_positive_hints": ["example", "your_webhook"],
    },

    # ── HUBSPOT ────────────────────────────────────────────────────────────────
    "hubspot_api_key": {
        "regex": r"(?i)(?:hubspot)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
        "severity": "HIGH",
        "description": "HubSpot CRM API key (UUID format, context-matched near hubspot)",
        "keywords": ["hubspot"],
        "false_positive_hints": ["00000000-0000-0000-0000-000000000000", "example"],
    },

    # ── HASHICORP TERRAFORM CLOUD ─────────────────────────────────────────────
    "hashicorp_tf_api_token": {
        "regex": r"(?i)[a-z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_=]{60,70}",
        "severity": "HIGH",
        "description": "HashiCorp Terraform Cloud user/team API token (atlasv1. prefix segment)",
        "keywords": ["atlasv1"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx.atlasv1.xxxx", "example"],
    },

    # ── HEROKU V2 ─────────────────────────────────────────────────────────────
    "heroku_api_key_v2": {
        "regex": r"\bHRKU-AA[0-9a-zA-Z_\-]{58}\b",
        "severity": "HIGH",
        "description": "Heroku API key v2 format (HRKU-AA prefix)",
        "keywords": ["hrku-aa"],
        "entropy_min": 4.0,
        "false_positive_hints": ["HRKU-AAxxxx", "example"],
    },

    # ── LAUNCHDARKLY ──────────────────────────────────────────────────────────
    "launchdarkly_access_token": {
        "regex": r"(?i)(?:launchdarkly)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_\-=]{40})",
        "severity": "HIGH",
        "description": "LaunchDarkly feature flag access token (context-matched near launchdarkly)",
        "keywords": ["launchdarkly"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── TWITCH ─────────────────────────────────────────────────────────────────
    "twitch_api_token": {
        "regex": r"(?i)(?:twitch)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-z0-9]{30})",
        "severity": "HIGH",
        "description": "Twitch streaming platform API token (context-matched near twitch)",
        "keywords": ["twitch"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── TWITTER/X (extended) ──────────────────────────────────────────────────
    "twitter_access_token": {
        "regex": r"(?i)(?:twitter)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})",
        "severity": "HIGH",
        "description": "Twitter/X OAuth access token (numeric_id-alphanumeric format, context-matched)",
        "keywords": ["twitter"],
        "false_positive_hints": ["xxxx", "example", "your_token", "123456789012345-xxxx"],
    },
    "twitter_access_secret": {
        "regex": r"(?i)(?:twitter)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-z0-9]{45})",
        "severity": "HIGH",
        "description": "Twitter/X OAuth access secret (45-char, context-matched near twitter)",
        "keywords": ["twitter"],
        "false_positive_hints": ["xxxx", "example"],
    },
    "twitter_api_secret": {
        "regex": r"(?i)(?:twitter[_\s]?(?:api[_\s]?)?secret|twitter[_\s]?consumer[_\s]?secret)[\s=:\"']{1,5}([a-z0-9]{50})",
        "severity": "HIGH",
        "description": "Twitter/X API consumer secret (50-char, context-matched)",
        "keywords": ["twitter"],
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── SONARQUBE / SONARCLOUD ────────────────────────────────────────────────
    "sonarqube_api_token": {
        "regex": r"(?i)(?:sonar[_.\-]?(?:login|token))(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}((?:squ_|sqp_|sqa_)[a-zA-Z0-9_\-=]{40}|[a-zA-Z0-9_\-=]{40})",
        "severity": "HIGH",
        "description": "SonarQube/SonarCloud API token (squ_/sqp_/sqa_ prefix or context-matched near sonar)",
        "keywords": ["sonar"],
        "entropy_min": 3.5,
        "false_positive_hints": ["squ_xxxx", "sqp_xxxx", "example"],
    },

    # ── SOURCEGRAPH ────────────────────────────────────────────────────────────
    "sourcegraph_access_token": {
        "regex": r"\bsgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}\b",
        "severity": "HIGH",
        "description": "Sourcegraph code search access token (sgp_ prefix)",
        "keywords": ["sgp_"],
        "entropy_min": 3.0,
        "false_positive_hints": ["sgp_xxxx_xxxx", "example"],
    },

    # ── CISCO MERAKI ──────────────────────────────────────────────────────────
    "cisco_meraki_api_key": {
        "regex": r"(?i)(?:meraki)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([0-9a-f]{40})",
        "severity": "HIGH",
        "description": "Cisco Meraki network management API key (40-char hex, context-matched near meraki)",
        "keywords": ["meraki"],
        "entropy_min": 3.0,
        "false_positive_hints": ["xxxx", "example", "0000000000000000000000000000000000000000"],
    },

    # ── TRAVIS CI ─────────────────────────────────────────────────────────────
    "travisci_access_token": {
        "regex": r"(?i)(?:travis)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_\-]{22})",
        "severity": "MEDIUM",
        "description": "Travis CI access token (22-char, context-matched near travis)",
        "keywords": ["travis"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── ZENDESK ────────────────────────────────────────────────────────────────
    "zendesk_api_token": {
        "regex": r"(?i)(?:zendesk)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{40})",
        "severity": "HIGH",
        "description": "Zendesk support platform API token (context-matched near zendesk)",
        "keywords": ["zendesk"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── IBM CLOUD ─────────────────────────────────────────────────────────────
    "ibm_cloud_api_key": {
        "regex": r"(?i)(?:ibm[_\s]?(?:cloud[_\s]?)?api[_\s]?key|IBMCLOUD_API_KEY)[\s=:\"']{1,5}([A-Za-z0-9_\-]{44})",
        "severity": "CRITICAL",
        "description": "IBM Cloud API key (context-matched near ibm_cloud_api_key or IBMCLOUD_API_KEY)",
        "keywords": ["ibm"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── SQUARE OAUTH TOKEN ────────────────────────────────────────────────────
    "square_oauth_token": {
        "regex": r"\bsq0csp-[A-Za-z0-9\-_]{43}\b",
        "severity": "CRITICAL",
        "description": "Square OAuth application secret (sq0csp- prefix, differs from access token sq0atp-)",
        "keywords": ["sq0csp-"],
        "false_positive_hints": ["sq0csp-xxxx", "example"],
    },

    # ── BASIC AUTH IN URLS ────────────────────────────────────────────────────
    "basic_auth_url": {
        "regex": r"https?://[^:\s/\"']+:[^@\s\"']{6,}@[a-zA-Z0-9._\-]+(?::[0-9]+)?",
        "severity": "HIGH",
        "description": "HTTP Basic Auth credentials embedded in URL (user:pass@host)",
        "false_positive_hints": ["user:password@", "admin:admin@", "root:root@", "localhost", "example.com", "xxxx"],
    },

    # ── DOPPLER (short token variant) ─────────────────────────────────────────
    "doppler_token_short": {
        "regex": r"(?i)(?:DOPPLER[_\s]?TOKEN|DOPPLER[_\s]?(?:API[_\s]?)?KEY)[\s=:\"']{1,5}([a-zA-Z0-9.]{43,})",
        "severity": "HIGH",
        "description": "Doppler API token (context-matched near DOPPLER_TOKEN)",
        "keywords": ["doppler"],
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── DUFFEL TRAVEL API ─────────────────────────────────────────────────────
    "duffel_api_token": {
        "regex": r"\bduffel_(?:test|live)_[a-zA-Z0-9_\-=]{43}\b",
        "severity": "HIGH",
        "description": "Duffel travel API token (duffel_test_ or duffel_live_ prefix)",
        "keywords": ["duffel_test_", "duffel_live_"],
        "entropy_min": 2.0,
        "false_positive_hints": ["duffel_test_xxxx", "duffel_live_xxxx", "example"],
    },

    # ── CONTENTFUL CMS ────────────────────────────────────────────────────────
    "contentful_delivery_api_token": {
        "regex": r"(?i)(?:contentful)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_\-=]{43})",
        "severity": "HIGH",
        "description": "Contentful CMS delivery API token (context-matched near contentful)",
        "keywords": ["contentful"],
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── CONFLUENT KAFKA ────────────────────────────────────────────────────────
    "confluent_access_token": {
        "regex": r"(?i)(?:confluent)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{16})",
        "severity": "HIGH",
        "description": "Confluent Kafka Cloud API key (context-matched near confluent)",
        "keywords": ["confluent"],
        "entropy_min": 3.0,
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "confluent_secret_key": {
        "regex": r"(?i)(?:CONFLUENT[_\s]?SECRET|CONFLUENT[_\s]?API[_\s]?SECRET)[\s=:\"']{1,5}([a-zA-Z0-9+/]{64})",
        "severity": "CRITICAL",
        "description": "Confluent Kafka Cloud API secret (context-matched near CONFLUENT_SECRET)",
        "keywords": ["confluent"],
        "entropy_min": 4.0,
        "false_positive_hints": ["xxxx", "example", "your_secret"],
    },

    # ── LARK / FEISHU (ByteDance) ─────────────────────────────────────────────
    "lark_app_token": {
        "regex": r"(?i)(?:LARK[_\s]?(?:APP[_\s]?)?(?:SECRET|TOKEN)|FEISHU[_\s]?(?:APP[_\s]?)?SECRET)[\s=:\"']{1,5}([a-zA-Z0-9]{32,50})",
        "severity": "HIGH",
        "description": "Lark/Feishu (ByteDance) app token or secret (context-matched)",
        "keywords": ["lark", "feishu"],
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── AZURE EXTENDED ────────────────────────────────────────────────────────
    "azure_devops_pat": {
        "regex": r"(?i)(?:AZURE[_\s]?DEVOPS[_\s]?(?:PERSONAL[_\s]?ACCESS[_\s]?)?TOKEN|AZDO[_\s]?TOKEN)[\s=:\"']{1,5}([a-zA-Z0-9+/]{52}={0,2})",
        "severity": "CRITICAL",
        "description": "Azure DevOps personal access token (context-matched, base64 format)",
        "keywords": ["azure devops", "azdo"],
        "entropy_min": 4.0,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },
    "azure_sas_token": {
        "regex": r"(?:sig=[a-zA-Z0-9%+/]{43,}(?:%3D|=){0,2}(?:&|$))",
        "severity": "HIGH",
        "description": "Azure Storage SAS token signature (sig= parameter in SAS URL)",
        "keywords": ["sig="],
        "false_positive_hints": ["sig=xxxx", "sig=example"],
    },
    "azure_function_key": {
        "regex": r"(?i)(?:AZURE[_\s]?FUNCTION[_\s]?(?:APP[_\s]?)?(?:KEY|CODE)|FUNCTIONS[_\s]?KEY)[\s=:\"']{1,5}([a-zA-Z0-9+/\-_]{40,88}={0,2})",
        "severity": "HIGH",
        "description": "Azure Function App key (context-matched near AZURE_FUNCTION_KEY)",
        "keywords": ["azure function"],
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "azure_search_admin_key": {
        "regex": r"(?i)(?:AZURE[_\s]?SEARCH[_\s]?(?:ADMIN[_\s]?)?(?:KEY|API[_\s]?KEY))[\s=:\"']{1,5}([A-Z0-9]{32})",
        "severity": "HIGH",
        "description": "Azure AI Search (Cognitive Search) admin key (context-matched)",
        "keywords": ["azure search"],
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── AUTH0 ─────────────────────────────────────────────────────────────────
    "auth0_management_api_token": {
        "regex": r"(?i)(?:AUTH0[_\s]?(?:MANAGEMENT[_\s]?)?(?:API[_\s]?)?TOKEN)[\s=:\"']{1,5}(eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,})",
        "severity": "CRITICAL",
        "description": "Auth0 Management API token (JWT format, context-matched near AUTH0_TOKEN)",
        "keywords": ["auth0"],
        "entropy_min": 3.0,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── FIGMA ─────────────────────────────────────────────────────────────────
    "figma_personal_access_token": {
        "regex": r"\bfigd_[a-zA-Z0-9_\-]{42}\b",
        "severity": "HIGH",
        "description": "Figma personal access token (figd_ prefix)",
        "keywords": ["figd_"],
        "false_positive_hints": ["figd_xxxx", "example"],
    },
    "figma_oauth_token": {
        "regex": r"(?i)(?:FIGMA[_\s]?(?:ACCESS[_\s]?)?TOKEN|FIGMA[_\s]?API[_\s]?KEY)[\s=:\"']{1,5}([a-zA-Z0-9_\-]{43,})",
        "severity": "HIGH",
        "description": "Figma OAuth access token (context-matched near FIGMA_TOKEN)",
        "keywords": ["figma"],
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── GOCARDLESS ────────────────────────────────────────────────────────────
    "gocardless_api_token": {
        "regex": r"(?i)(?:gocardless)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}(live_[a-zA-Z0-9_\-=]{40})",
        "severity": "HIGH",
        "description": "GoCardless payment API token (live_ prefix, context-matched near gocardless)",
        "keywords": ["gocardless"],
        "false_positive_hints": ["live_xxxx", "example"],
    },

    # ── INTERCOM ───────────────────────────────────────────────────────────────
    "intercom_api_key": {
        "regex": r"(?i)(?:intercom)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_\-=]{60})",
        "severity": "HIGH",
        "description": "Intercom customer messaging API key (context-matched near intercom)",
        "keywords": ["intercom"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── SUMOLOGIC ─────────────────────────────────────────────────────────────
    "sumologic_access_id": {
        "regex": r"(?i)(?:sumo)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}(su[a-zA-Z0-9]{12})",
        "severity": "HIGH",
        "description": "Sumo Logic SIEM access ID (su prefix, context-matched near sumo)",
        "keywords": ["sumo"],
        "entropy_min": 3.0,
        "false_positive_hints": ["suxxxx", "example"],
    },
    "sumologic_access_token": {
        "regex": r"(?i)(?:sumo)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{64})",
        "severity": "HIGH",
        "description": "Sumo Logic SIEM access token (64-char, context-matched near sumo)",
        "keywords": ["sumo"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── MATTERMOST ────────────────────────────────────────────────────────────
    "mattermost_access_token": {
        "regex": r"(?i)(?:mattermost)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{26})",
        "severity": "HIGH",
        "description": "Mattermost team communication access token (context-matched near mattermost)",
        "keywords": ["mattermost"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── MESSAGEBIRD ────────────────────────────────────────────────────────────
    "messagebird_api_token": {
        "regex": r"(?i)(?:message[_\-]?bird)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{25})",
        "severity": "HIGH",
        "description": "MessageBird SMS/voice API token (context-matched near messagebird)",
        "keywords": ["messagebird"],
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── SENDBIRD ───────────────────────────────────────────────────────────────
    "sendbird_access_token": {
        "regex": r"(?i)(?:sendbird)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-f0-9]{40})",
        "severity": "HIGH",
        "description": "Sendbird in-app chat API token (40-char hex, context-matched near sendbird)",
        "keywords": ["sendbird"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── PLAID ─────────────────────────────────────────────────────────────────
    "plaid_api_token": {
        "regex": r"(?i)(?:plaid)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "severity": "CRITICAL",
        "description": "Plaid fintech access token (access-{env}-UUID format, context-matched)",
        "keywords": ["plaid"],
        "false_positive_hints": ["access-sandbox-00000000-0000-0000-0000-000000000000", "example"],
    },

    # ── LOOT (Lob) ────────────────────────────────────────────────────────────
    "lob_api_key": {
        "regex": r"(?i)(?:lob)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}((?:live|test)_[a-f0-9]{35})",
        "severity": "HIGH",
        "description": "Lob direct mail API key (live_/test_ prefix, context-matched near lob)",
        "keywords": ["lob"],
        "false_positive_hints": ["live_xxxx", "test_xxxx", "example"],
    },

    # ── OPENROUTER ────────────────────────────────────────────────────────────
    "openrouter_api_key": {
        "regex": r"\bsk-or-v1-[a-zA-Z0-9]{64}\b",
        "severity": "CRITICAL",
        "description": "OpenRouter LLM proxy API key (sk-or-v1- prefix)",
        "keywords": ["sk-or-v1-"],
        "false_positive_hints": ["sk-or-v1-xxxx", "example"],
    },

    # ── GITLAB (extended token types) ─────────────────────────────────────────
    "gitlab_cicd_job_token": {
        "regex": r"\bglcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_\-]{20}\b",
        "severity": "HIGH",
        "description": "GitLab CI/CD job token (glcbt- prefix)",
        "keywords": ["glcbt-"],
        "false_positive_hints": ["glcbt-xxxx", "example"],
    },
    "gitlab_deploy_token": {
        "regex": r"\bgldt-[0-9a-zA-Z_\-]{20}\b",
        "severity": "HIGH",
        "description": "GitLab deploy token (gldt- prefix)",
        "keywords": ["gldt-"],
        "false_positive_hints": ["gldt-xxxx", "example"],
    },
    "gitlab_runner_token": {
        "regex": r"\bglrt-[0-9a-zA-Z_\-]{20}\b",
        "severity": "HIGH",
        "description": "GitLab runner authentication token (glrt- prefix)",
        "keywords": ["glrt-"],
        "false_positive_hints": ["glrt-xxxx", "example"],
    },
    "gitlab_pipeline_trigger": {
        "regex": r"\bglptt-[0-9a-zA-Z_\-]{20}\b",
        "severity": "HIGH",
        "description": "GitLab pipeline trigger token (glptt- prefix)",
        "keywords": ["glptt-"],
        "false_positive_hints": ["glptt-xxxx", "example"],
    },
    "gitlab_feed_token": {
        "regex": r"\bglft-[0-9a-zA-Z_\-]{20}\b",
        "severity": "MEDIUM",
        "description": "GitLab feed token (glft- prefix)",
        "keywords": ["glft-"],
        "false_positive_hints": ["glft-xxxx", "example"],
    },

    # ── BEAMER ────────────────────────────────────────────────────────────────
    "beamer_api_token": {
        "regex": r"(?i)(?:beamer)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}(b_[a-zA-Z0-9_\-=]{44})",
        "severity": "MEDIUM",
        "description": "Beamer product changelog API token (b_ prefix, context-matched near beamer)",
        "keywords": ["beamer"],
        "false_positive_hints": ["b_xxxx", "example"],
    },

    # ── INFRACOST ─────────────────────────────────────────────────────────────
    "infracost_api_token": {
        "regex": r"\bico-[a-zA-Z0-9]{32}\b",
        "severity": "MEDIUM",
        "description": "Infracost cloud cost API token (ico- prefix)",
        "keywords": ["ico-"],
        "false_positive_hints": ["ico-xxxx", "example"],
    },

    # ── SETTLEMINT ────────────────────────────────────────────────────────────
    "settlemint_access_token": {
        "regex": r"\bsm_(?:aat|pat|sat)_[a-zA-Z0-9]{16}\b",
        "severity": "HIGH",
        "description": "SettleMint blockchain platform access token (sm_aat/pat/sat_ prefix)",
        "keywords": ["sm_aat_", "sm_pat_", "sm_sat_"],
        "false_positive_hints": ["sm_aat_xxxx", "example"],
    },

    # ── SIDEKIQ PRO/ENTERPRISE ────────────────────────────────────────────────
    "sidekiq_secret": {
        "regex": r"(?i)(?:BUNDLE_(?:ENTERPRISE|GEMS)__CONTRIBSYS__COM)[\s=:\"']{1,5}([a-f0-9]{8}:[a-f0-9]{8})",
        "severity": "HIGH",
        "description": "Sidekiq Pro/Enterprise gem server credentials (BUNDLE_CONTRIBSYS format)",
        "keywords": ["contribsys"],
        "false_positive_hints": ["00000000:00000000", "example"],
    },

    # ── SLACK EXTENDED ────────────────────────────────────────────────────────
    "slack_config_access_token": {
        "regex": r"(?i)\bxoxe\.xox[bp]-\d-[A-Z0-9]{163,166}\b",
        "severity": "HIGH",
        "description": "Slack configuration access token (xoxe.xoxb- or xoxe.xoxp- prefix)",
        "keywords": ["xoxe."],
        "false_positive_hints": ["xoxe.xoxb-xxxx", "example"],
    },
    "slack_legacy_token": {
        "regex": r"\bxox[os]-\d+-\d+-\d+-[a-fA-F0-9]+\b",
        "severity": "HIGH",
        "description": "Slack legacy user/workspace token (xoxo- or xoxs- prefix)",
        "keywords": ["xoxo-", "xoxs-"],
        "false_positive_hints": ["xoxo-xxxx", "xoxs-xxxx", "example"],
    },

    # ── CODECOV ────────────────────────────────────────────────────────────────
    "codecov_access_token": {
        "regex": r"(?i)(?:codecov)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{32})",
        "severity": "HIGH",
        "description": "Codecov code coverage upload token (context-matched near codecov)",
        "keywords": ["codecov"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── GITTER ────────────────────────────────────────────────────────────────
    "gitter_access_token": {
        "regex": r"(?i)(?:gitter)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_]{40})",
        "severity": "MEDIUM",
        "description": "Gitter chat access token (context-matched near gitter)",
        "keywords": ["gitter"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── NY TIMES ───────────────────────────────────────────────────────────────
    "nytimes_api_key": {
        "regex": r"(?i)(?:nytimes|new-york-times|newyorktimes)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_\-=]{32})",
        "severity": "LOW",
        "description": "NY Times API key (context-matched, low severity — public API)",
        "keywords": ["nytimes"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── FINNHUB ────────────────────────────────────────────────────────────────
    "finnhub_access_token": {
        "regex": r"(?i)(?:finnhub)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_]{20})",
        "severity": "MEDIUM",
        "description": "Finnhub stock market data API token (context-matched near finnhub)",
        "keywords": ["finnhub"],
        "entropy_min": 3.0,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── FRESHBOOKS ────────────────────────────────────────────────────────────
    "freshbooks_access_token": {
        "regex": r"(?i)(?:freshbooks)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{64})",
        "severity": "HIGH",
        "description": "FreshBooks invoicing OAuth access token (64-char, context-matched)",
        "keywords": ["freshbooks"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── ETSY ──────────────────────────────────────────────────────────────────
    "etsy_access_token": {
        "regex": r"(?i)(?:etsy)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{24})",
        "severity": "HIGH",
        "description": "Etsy marketplace OAuth access token (context-matched near etsy)",
        "keywords": ["etsy"],
        "entropy_min": 3.0,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── FLICKR ────────────────────────────────────────────────────────────────
    "flickr_access_token": {
        "regex": r"(?i)(?:flickr)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{32})",
        "severity": "MEDIUM",
        "description": "Flickr photo sharing OAuth access token (context-matched near flickr)",
        "keywords": ["flickr"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── FASTLY CDN ────────────────────────────────────────────────────────────
    "fastly_api_token": {
        "regex": r"(?i)(?:fastly)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9_\-=]{32})",
        "severity": "HIGH",
        "description": "Fastly CDN API token (context-matched near fastly)",
        "keywords": ["fastly"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── FINICITY ─────────────────────────────────────────────────────────────
    "finicity_api_token": {
        "regex": r"(?i)(?:finicity)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-f0-9]{32})",
        "severity": "HIGH",
        "description": "Finicity financial data API token (context-matched near finicity)",
        "keywords": ["finicity"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── DRONECI ───────────────────────────────────────────────────────────────
    "droneci_access_token": {
        "regex": r"(?i)(?:droneci|drone[_\-]ci)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{32})",
        "severity": "HIGH",
        "description": "Drone CI/CD access token (context-matched near droneci)",
        "keywords": ["droneci", "drone_ci"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── DROPBOX (context-matched) ─────────────────────────────────────────────
    "dropbox_access_token": {
        "regex": r"(?i)(?:dropbox)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{15})",
        "severity": "HIGH",
        "description": "Dropbox file storage OAuth access token (context-matched near dropbox)",
        "keywords": ["dropbox"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── MAILGUN EXTENDED ──────────────────────────────────────────────────────
    "mailgun_signing_key": {
        "regex": r"(?i)(?:mailgun)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})",
        "severity": "HIGH",
        "description": "Mailgun webhook signing key (structured hex-hex-hex format, context-matched)",
        "keywords": ["mailgun"],
        "false_positive_hints": ["00000000000000000000000000000000-00000000-00000000", "example"],
    },

    # ── KUBERNETES SECRET YAML ────────────────────────────────────────────────
    "kubernetes_secret_yaml": {
        "regex": r"(?:kind:\s*Secret[\s\S]{0,200}data:\s*\n(?:[ \t]+[a-zA-Z0-9_\-]+:\s*[a-zA-Z0-9+/]{20,}={0,2}\n)+)",
        "severity": "HIGH",
        "description": "Kubernetes Secret manifest with base64-encoded data values",
        "keywords": ["kind: secret", "kind:secret"],
        "false_positive_hints": ["example", "test", "placeholder"],
    },

    # ── LOOKER ────────────────────────────────────────────────────────────────
    "looker_client_id": {
        "regex": r"(?i)(?:looker)(?:[\s\w.\-]{0,20})[\s=:\"']{1,5}([a-zA-Z0-9]{20})",
        "severity": "HIGH",
        "description": "Looker Business Intelligence client ID/secret (context-matched near looker)",
        "keywords": ["looker"],
        "entropy_min": 3.0,
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── TAILSCALE ─────────────────────────────────────────────────────────────
    "tailscale_api_key": {
        "regex": r"\btskey-(?:api|client|user)-[a-zA-Z0-9_\-]{25,50}\b",
        "severity": "HIGH",
        "description": "Tailscale VPN mesh network API key (tskey- prefix)",
        "keywords": ["tskey-"],
        "false_positive_hints": ["tskey-api-xxxx", "example"],
    },

    # ── SEGMENT ────────────────────────────────────────────────────────────────
    "segment_write_key": {
        "regex": r"(?i)(?:SEGMENT[_\s]?(?:WRITE[_\s]?)?KEY|ANALYTICS[_\s]?WRITE[_\s]?KEY)[\s=:\"']{1,5}([a-zA-Z0-9]{32,50})",
        "severity": "HIGH",
        "description": "Segment analytics write key (context-matched near SEGMENT_WRITE_KEY)",
        "keywords": ["segment"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── RUNPOD ────────────────────────────────────────────────────────────────
    "runpod_api_key": {
        "regex": r"(?i)(?:RUNPOD[_\s]?API[_\s]?KEY)[\s=:\"']{1,5}([a-zA-Z0-9]{32,48})",
        "severity": "HIGH",
        "description": "RunPod GPU cloud API key (context-matched near RUNPOD_API_KEY)",
        "keywords": ["runpod"],
        "entropy_min": 3.5,
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── WORKATO ────────────────────────────────────────────────────────────────
    "workato_api_token": {
        "regex": r"(?i)(?:WORKATO[_\s]?(?:API[_\s]?)?TOKEN)[\s=:\"']{1,5}([a-zA-Z0-9]{32,64})",
        "severity": "HIGH",
        "description": "Workato iPaaS automation API token (context-matched)",
        "keywords": ["workato"],
        "false_positive_hints": ["xxxx", "example"],
    },

    # ── GENERIC: High-entropy hex blob ────────────────────────────────────────
    # detect-secrets uses entropy >= 3.0 for hex strings
    "generic_high_entropy_hex": {
        "regex": r"(?i)(?:api[_\s]?key|access[_\s]?key|secret|password|token|passwd|private[_\s]?key|credential)\s*[=:]\s*['\"]?([0-9a-f]{32,64})['\"]?",
        "severity": "MEDIUM",
        "description": "High-entropy hex secret near key/password/token keyword (entropy >= 3.0)",
        "entropy_min": 3.0,
        "false_positive_hints": ["0000000000000000", "ffffffffffffffff", "deadbeef", "example", "xxxx", "test"],
    },

}

# ---------------------------------------------------------------------------
# Integration helper
# ---------------------------------------------------------------------------

def get_new_pattern_count() -> int:
    return len(NEW_PATTERNS)


def merge_into(existing: dict) -> dict:
    """Merge NEW_PATTERNS into an existing PATTERNS dict. Skip duplicates."""
    added = 0
    for key, val in NEW_PATTERNS.items():
        if key not in existing:
            existing[key] = val
            added += 1
    print(f"Added {added} new patterns. Total: {len(existing)}")
    return existing


if __name__ == "__main__":
    print(f"New patterns defined: {get_new_pattern_count()}")
    print(f"Target total after merge: 137 + {get_new_pattern_count()} = {137 + get_new_pattern_count()}")
    print("\nNew pattern keys:")
    for k in NEW_PATTERNS:
        print(f"  {k}")
