"""
patterns.py — Regex pattern library for detecting leaked API keys, tokens, and secrets.
Stdlib only (re, math, collections). No external deps.
"""

import re
import math
import collections

# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

PATTERNS: dict[str, dict] = {

    # ── OpenAI ──────────────────────────────────────────────────────────────
    "openai_key": {
        "regex": r"sk-[a-zA-Z0-9]{20,60}",
        "severity": "CRITICAL",
        "description": "OpenAI API key (legacy format)",
        "false_positive_hints": ["sk-xxxx", "sk-your", "sk-test", "sk-example", "sk-placeholder"],
    },
    "openai_project_key": {
        "regex": r"sk-proj-[a-zA-Z0-9_\-]{40,120}",
        "severity": "CRITICAL",
        "description": "OpenAI project-scoped API key (sk-proj-... format)",
        "false_positive_hints": ["sk-proj-xxxx", "sk-proj-your", "sk-proj-test", "sk-proj-example"],
    },
    "openai_org": {
        "regex": r"org-[a-zA-Z0-9]{24}",
        "severity": "MEDIUM",
        "description": "OpenAI organization ID",
        "false_positive_hints": ["org-xxxx", "org-your", "org-example"],
    },

    # ── Anthropic ───────────────────────────────────────────────────────────
    "anthropic_key": {
        "regex": r"sk-ant-(?:api03-)?[a-zA-Z0-9_\-]{90,120}",
        "severity": "CRITICAL",
        "description": "Anthropic / Claude API key",
        "false_positive_hints": ["sk-ant-xxxx", "sk-ant-your", "sk-ant-test", "sk-ant-example"],
    },

    # ── HuggingFace ─────────────────────────────────────────────────────────
    "huggingface_token": {
        "regex": r"hf_[a-zA-Z0-9]{34,50}",
        "severity": "HIGH",
        "description": "HuggingFace API token",
        "false_positive_hints": ["hf_xxxx", "hf_your", "hf_test", "hf_example"],
    },

    # ── GitHub ──────────────────────────────────────────────────────────────
    "github_pat_classic": {
        "regex": r"ghp_[a-zA-Z0-9]{36}",
        "severity": "CRITICAL",
        "description": "GitHub Personal Access Token (classic)",
        "false_positive_hints": ["ghp_xxxx", "ghp_your", "ghp_test", "ghp_example"],
    },
    "github_pat_fine": {
        "regex": r"github_pat_[a-zA-Z0-9_]{82}",
        "severity": "CRITICAL",
        "description": "GitHub fine-grained Personal Access Token",
        "false_positive_hints": ["github_pat_xxxx", "github_pat_your", "github_pat_test"],
    },
    "github_oauth": {
        "regex": r"gho_[a-zA-Z0-9]{36}",
        "severity": "HIGH",
        "description": "GitHub OAuth access token",
        "false_positive_hints": ["gho_xxxx", "gho_your", "gho_test"],
    },
    "github_server_token": {
        "regex": r"ghs_[a-zA-Z0-9]{36}",
        "severity": "HIGH",
        "description": "GitHub Actions server-to-server token",
        "false_positive_hints": ["ghs_xxxx", "ghs_your", "ghs_test"],
    },
    "github_refresh_token": {
        "regex": r"ghr_[a-zA-Z0-9]{76}",
        "severity": "HIGH",
        "description": "GitHub OAuth refresh token",
        "false_positive_hints": ["ghr_xxxx", "ghr_your", "ghr_test"],
    },

    # ── AWS ─────────────────────────────────────────────────────────────────
    "aws_access_key": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "description": "AWS IAM Access Key ID",
        "false_positive_hints": ["AKIAIOSFODNN7EXAMPLE", "AKIAXXXXXXXXXXXXXXXX", "YOUR_ACCESS_KEY"],
    },
    "aws_secret_key": {
        "regex": r"(?i)(?:aws[_\-\s]?secret|secret[_\-\s]?access[_\-\s]?key)\s*[=:]\s*['\"]?([0-9a-zA-Z/+]{40})['\"]?",
        "severity": "CRITICAL",
        "description": "AWS Secret Access Key (context-matched near 'secret'/'aws')",
        "false_positive_hints": ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "YOUR_SECRET", "xxxx", "example"],
    },
    "aws_session_token": {
        "regex": r"(?i)aws[_\-\s]?session[_\-\s]?token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        "severity": "HIGH",
        "description": "AWS STS session token",
        "false_positive_hints": ["example", "xxxx", "your_token"],
    },

    # ── Google ──────────────────────────────────────────────────────────────
    "google_api_key": {
        "regex": r"AIza[0-9A-Za-z\-_]{30,40}",
        "severity": "HIGH",
        "description": "Google API key / Gemini API key (AIza... prefix)",
        "false_positive_hints": ["AIzaxxxx", "AIzaYOUR", "AIzaSyEXAMPLE", "AIzaSyD-YOUR"],
    },
    "google_oauth_client": {
        "regex": r"[0-9]{12,18}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "severity": "MEDIUM",
        "description": "Google OAuth 2.0 client ID",
        "false_positive_hints": ["example", "xxxx", "your-client"],
    },
    "google_service_account": {
        "regex": r'"type"\s*:\s*"service_account"',
        "severity": "HIGH",
        "description": "Google service account JSON credential (type field)",
        "false_positive_hints": ["example", "test"],
    },
    "firebase_url": {
        "regex": r"https://[a-z0-9-]{3,25}-default-rtdb\.firebaseio\.com",
        "severity": "MEDIUM",
        "description": "Firebase Realtime Database URL",
        "false_positive_hints": ["example", "test", "demo"],
    },

    # ── Stripe ──────────────────────────────────────────────────────────────
    "stripe_secret_key": {
        "regex": r"sk_live_[0-9a-zA-Z]{24,48}",
        "severity": "CRITICAL",
        "description": "Stripe live secret key",
        "false_positive_hints": ["sk_live_xxxx", "sk_live_your", "sk_live_test"],
    },
    "stripe_restricted_key": {
        "regex": r"rk_live_[0-9a-zA-Z]{24,48}",
        "severity": "CRITICAL",
        "description": "Stripe live restricted key",
        "false_positive_hints": ["rk_live_xxxx", "rk_live_your"],
    },
    "stripe_publishable_key": {
        "regex": r"pk_live_[0-9a-zA-Z]{24,48}",
        "severity": "HIGH",
        "description": "Stripe live publishable key",
        "false_positive_hints": ["pk_live_xxxx", "pk_live_your"],
    },
    "stripe_webhook_secret": {
        "regex": r"whsec_[a-zA-Z0-9]{32,64}",
        "severity": "HIGH",
        "description": "Stripe webhook signing secret",
        "false_positive_hints": ["whsec_xxxx", "whsec_your", "whsec_test"],
    },

    # ── Twilio ──────────────────────────────────────────────────────────────
    "twilio_sid": {
        "regex": r"AC[a-z0-9]{32}",
        "severity": "HIGH",
        "description": "Twilio Account SID",
        "false_positive_hints": ["ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "ACxxxx", "your_sid"],
    },
    "twilio_auth_token": {
        "regex": r"(?i)twilio[_\s]?auth[_\s]?token\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "CRITICAL",
        "description": "Twilio Auth Token (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },
    "twilio_api_key": {
        "regex": r"SK[0-9a-fA-F]{32}",
        "severity": "HIGH",
        "description": "Twilio API Key SID",
        "false_positive_hints": ["SKxxxx", "SKyour", "SKtest", "SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"],
    },

    # ── SendGrid ────────────────────────────────────────────────────────────
    "sendgrid_key": {
        "regex": r"SG\.[a-zA-Z0-9_\-]{20,30}\.[a-zA-Z0-9_\-]{40,50}",
        "severity": "CRITICAL",
        "description": "SendGrid API key",
        "false_positive_hints": ["SG.xxxx", "SG.your", "SG.example"],
    },

    # ── Groq ────────────────────────────────────────────────────────────────
    "groq_key": {
        "regex": r"gsk_[a-zA-Z0-9]{50,70}",
        "severity": "CRITICAL",
        "description": "Groq API key",
        "false_positive_hints": ["gsk_xxxx", "gsk_your", "gsk_test", "gsk_example"],
    },

    # ── Mistral ─────────────────────────────────────────────────────────────
    "mistral_key": {
        "regex": r"(?i)MISTRAL[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([a-zA-Z0-9]{32})['\"]?",
        "severity": "CRITICAL",
        "description": "Mistral API key (context-matched near MISTRAL_API_KEY)",
        "false_positive_hints": ["xxxx", "example", "your_key", "placeholder"],
    },

    # ── Replicate ───────────────────────────────────────────────────────────
    "replicate_key": {
        "regex": r"r8_[a-zA-Z0-9]{40}",
        "severity": "CRITICAL",
        "description": "Replicate API token",
        "false_positive_hints": ["r8_xxxx", "r8_your", "r8_test", "r8_example"],
    },

    # ── Together AI ─────────────────────────────────────────────────────────
    "together_key": {
        "regex": r"(?i)TOGETHER[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([a-f0-9]{64})['\"]?",
        "severity": "CRITICAL",
        "description": "Together AI API key (context-matched hex near TOGETHER_API_KEY)",
        "false_positive_hints": ["xxxx", "example", "your_key", "0000000000000000"],
    },

    # ── Cohere ──────────────────────────────────────────────────────────────
    "cohere_key": {
        "regex": r"(?i)(?:COHERE[_\s]?API[_\s]?KEY|CO[_\s]?API[_\s]?KEY)\s*[=:]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",
        "severity": "CRITICAL",
        "description": "Cohere API key (context-matched near COHERE_API_KEY or CO_API_KEY)",
        "false_positive_hints": ["xxxx", "example", "your_key", "placeholder"],
    },

    # ── xAI / Grok ──────────────────────────────────────────────────────────
    "xai_key": {
        "regex": r"xai-[a-zA-Z0-9]{50,90}",
        "severity": "CRITICAL",
        "description": "xAI (Grok) API key",
        "false_positive_hints": ["xai-xxxx", "xai-your", "xai-test", "xai-example"],
    },

    # ── Slack ───────────────────────────────────────────────────────────────
    "slack_bot_token": {
        "regex": r"xoxb-[0-9A-Za-z\-]{10,72}",
        "severity": "CRITICAL",
        "description": "Slack bot token",
        "false_positive_hints": ["xoxb-xxxx", "xoxb-your", "xoxb-test"],
    },
    "slack_user_token": {
        "regex": r"xoxp-[0-9A-Za-z\-]{10,72}",
        "severity": "CRITICAL",
        "description": "Slack user token",
        "false_positive_hints": ["xoxp-xxxx", "xoxp-your", "xoxp-test"],
    },
    "slack_app_token": {
        "regex": r"xapp-[0-9A-Za-z\-]{10,72}",
        "severity": "HIGH",
        "description": "Slack app-level token",
        "false_positive_hints": ["xapp-xxxx", "xapp-your"],
    },
    "slack_refresh_token": {
        "regex": r"xoxr-[0-9A-Za-z\-]{10,72}",
        "severity": "HIGH",
        "description": "Slack refresh token",
        "false_positive_hints": ["xoxr-xxxx", "xoxr-your"],
    },
    "slack_webhook": {
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
        "severity": "HIGH",
        "description": "Slack incoming webhook URL",
        "false_positive_hints": ["example", "your_webhook", "TXXXXXXXX"],
    },

    # ── Discord ─────────────────────────────────────────────────────────────
    "discord_bot_token": {
        "regex": r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}",
        "severity": "CRITICAL",
        "description": "Discord bot token",
        "false_positive_hints": ["xxxx", "your_token", "example"],
    },
    "discord_webhook": {
        "regex": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,21}/[a-zA-Z0-9_\-]{60,70}",
        "severity": "HIGH",
        "description": "Discord webhook URL",
        "false_positive_hints": ["example", "your_webhook", "000000000000000000"],
    },

    # ── Telegram ────────────────────────────────────────────────────────────
    "telegram_bot_token": {
        "regex": r"[0-9]{8,10}:AA[a-zA-Z0-9_\-]{27,40}",
        "severity": "CRITICAL",
        "description": "Telegram Bot API token",
        "false_positive_hints": ["123456789:AA", "your_token", "xxxx"],
    },

    # ── JWT ─────────────────────────────────────────────────────────────────
    "jwt_token": {
        "regex": r"ey[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}",
        "severity": "MEDIUM",
        "description": "JSON Web Token (JWT) — may contain sensitive claims or be a live session token",
        "false_positive_hints": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example", "your_token", "test_jwt"],
    },

    # ── Ollama / LM Studio ──────────────────────────────────────────────────
    "ollama_host": {
        "regex": r"OLLAMA_HOST\s*=\s*(https?://[^\s\"']+)",
        "severity": "MEDIUM",
        "description": "Ollama host URL exposed — internal LLM inference endpoint",
        "false_positive_hints": ["localhost", "127.0.0.1", "0.0.0.0", "example.com"],
    },
    "lm_studio_host": {
        "regex": r"LM_STUDIO[_\s]?(?:HOST|URL|API)\s*[=:]\s*(https?://[^\s\"']+)",
        "severity": "MEDIUM",
        "description": "LM Studio API host exposed",
        "false_positive_hints": ["localhost", "127.0.0.1", "example.com"],
    },

    # ── Mailgun ─────────────────────────────────────────────────────────────
    "mailgun_key": {
        "regex": r"key-[0-9a-zA-Z]{32}",
        "severity": "CRITICAL",
        "description": "Mailgun API key",
        "false_positive_hints": ["key-xxxx", "key-your", "key-example", "key-00000000000000000000000000000000"],
    },

    # ── Mailchimp ────────────────────────────────────────────────────────────
    "mailchimp_key": {
        "regex": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "severity": "HIGH",
        "description": "Mailchimp API key",
        "false_positive_hints": ["xxxx-us1", "your_key-us1", "00000000000000000000000000000000-us"],
    },

    # ── Datadog ─────────────────────────────────────────────────────────────
    "datadog_api_key": {
        "regex": r"(?i)(?:DD|DATADOG)[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "HIGH",
        "description": "Datadog API key",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "datadog_app_key": {
        "regex": r"(?i)(?:DD|DATADOG)[_\s]?APP[_\s]?KEY\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?",
        "severity": "HIGH",
        "description": "Datadog Application key",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── NPM ─────────────────────────────────────────────────────────────────
    "npm_token": {
        "regex": r"npm_[a-zA-Z0-9]{36}",
        "severity": "HIGH",
        "description": "NPM access token",
        "false_positive_hints": ["npm_xxxx", "npm_your", "npm_test"],
    },

    # ── PyPI ─────────────────────────────────────────────────────────────────
    "pypi_token": {
        "regex": r"pypi-[a-zA-Z0-9_\-]{100,200}",
        "severity": "HIGH",
        "description": "PyPI upload token",
        "false_positive_hints": ["pypi-xxxx", "pypi-your", "pypi-test"],
    },

    # ── Heroku ───────────────────────────────────────────────────────────────
    "heroku_api_key": {
        "regex": r"(?i)heroku[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "severity": "HIGH",
        "description": "Heroku API key (UUID format)",
        "false_positive_hints": ["00000000-0000-0000-0000-000000000000", "xxxx", "example"],
    },

    # ── Vercel ───────────────────────────────────────────────────────────────
    "vercel_token": {
        "regex": r"(?i)VERCEL[_\s]?TOKEN\s*[=:]\s*['\"]?([a-zA-Z0-9]{24})['\"]?",
        "severity": "HIGH",
        "description": "Vercel API token",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── Netlify ───────────────────────────────────────────────────────────────
    "netlify_token": {
        "regex": r"(?i)NETLIFY[_\s]?(?:ACCESS[_\s]?)?TOKEN\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{40,})['\"]?",
        "severity": "HIGH",
        "description": "Netlify personal access token",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── Cloudflare ───────────────────────────────────────────────────────────
    "cloudflare_global_key": {
        "regex": r"(?i)CLOUDFLARE[_\s]?(?:GLOBAL[_\s]?)?(?:API[_\s]?)?KEY\s*[=:]\s*['\"]?([a-f0-9]{37})['\"]?",
        "severity": "CRITICAL",
        "description": "Cloudflare Global API key",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "cloudflare_api_token": {
        "regex": r"(?i)CLOUDFLARE[_\s]?API[_\s]?TOKEN\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{40})['\"]?",
        "severity": "HIGH",
        "description": "Cloudflare API token",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },

    # ── DigitalOcean ─────────────────────────────────────────────────────────
    "digitalocean_token": {
        "regex": r"(?i)(?:DO|DIGITAL_?OCEAN)[_\s]?(?:ACCESS[_\s]?)?TOKEN\s*[=:]\s*['\"]?([a-zA-Z0-9]{64})['\"]?",
        "severity": "HIGH",
        "description": "DigitalOcean personal access token",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },
    "digitalocean_pat": {
        "regex": r"dop_v1_[a-f0-9]{64}",
        "severity": "HIGH",
        "description": "DigitalOcean personal access token (dop_v1_... format)",
        "false_positive_hints": ["dop_v1_xxxx", "dop_v1_example"],
    },

    # ── Azure ─────────────────────────────────────────────────────────────────
    "azure_subscription_key": {
        "regex": r"(?i)(?:AZURE[_\s]?)?(?:SUBSCRIPTION[_\s]?KEY|OCP[_\s]?APIM[_\s]?SUBSCRIPTION[_\s]?KEY)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "HIGH",
        "description": "Azure Cognitive Services / APIM subscription key",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "azure_connection_string": {
        "regex": r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[a-zA-Z0-9+/]{86}==",
        "severity": "CRITICAL",
        "description": "Azure Storage account connection string",
        "false_positive_hints": ["AccountName=devstoreaccount1", "example", "xxxx"],
    },

    # ── Database URLs ─────────────────────────────────────────────────────────
    "postgres_url": {
        "regex": r"postgres(?:ql)?://[a-zA-Z0-9_\-]+:[^@\s\"']{6,}@[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+",
        "severity": "CRITICAL",
        "description": "PostgreSQL connection string with credentials",
        "false_positive_hints": ["localhost", "127.0.0.1", "user:password@", "user:pass@", "postgres:postgres@"],
    },
    "mysql_url": {
        "regex": r"mysql(?:\+[a-z]+)?://[a-zA-Z0-9_\-]+:[^@\s\"']{6,}@[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+",
        "severity": "CRITICAL",
        "description": "MySQL connection string with credentials",
        "false_positive_hints": ["localhost", "127.0.0.1", "user:password@", "root:root@"],
    },
    "mongodb_url": {
        "regex": r"mongodb(?:\+srv)?://[a-zA-Z0-9_\-]+:[^@\s\"']{6,}@[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+",
        "severity": "CRITICAL",
        "description": "MongoDB connection string with credentials",
        "false_positive_hints": ["localhost", "127.0.0.1", "user:password@", "admin:admin@"],
    },
    "redis_url": {
        "regex": r"redis(?:s)?://(?:[a-zA-Z0-9_\-]+:[^@\s\"']{6,}@)?[a-zA-Z0-9._\-]+:[0-9]+(?:/[0-9]+)?",
        "severity": "HIGH",
        "description": "Redis connection URL (may include auth token)",
        "false_positive_hints": ["localhost:6379", "127.0.0.1:6379", "redis://redis:6379"],
    },

    # ── SSH Private Keys ──────────────────────────────────────────────────────
    "ssh_private_key": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "SSH or TLS private key header",
        "false_positive_hints": ["example", "test", "dummy", "placeholder"],
    },

    # ── PGP Private Key ───────────────────────────────────────────────────────
    "pgp_private_key": {
        "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "CRITICAL",
        "description": "PGP private key block",
        "false_positive_hints": ["example", "test"],
    },

    # ── Generic high-entropy .env line ────────────────────────────────────────
    # Handled separately in scan_text() but listed for documentation
    "generic_high_entropy_env": {
        "regex": r"^[A-Z][A-Z0-9_]{3,40}\s*=\s*['\"]?([a-zA-Z0-9/+_\-\.]{30,})['\"]?\s*$",
        "severity": "MEDIUM",
        "description": "High-entropy value in .env-style KEY=VALUE line (entropy > 4.5 bits/char)",
        "false_positive_hints": ["example", "your_", "xxxx", "placeholder", "changeme", "default", "localhost", "http", "true", "false", "none", "null"],
    },

    # ── Sentry DSN ────────────────────────────────────────────────────────────
    "sentry_dsn": {
        "regex": r"https://[a-f0-9]{32}@(?:o[0-9]+\.)?ingest(?:\.us)?\.sentry\.io/[0-9]+",
        "severity": "MEDIUM",
        "description": "Sentry DSN (project key leaks allowed event ingestion)",
        "false_positive_hints": ["example", "your_dsn"],
    },

    # ── Mapbox ────────────────────────────────────────────────────────────────
    "mapbox_token": {
        "regex": r"pk\.eyJ1IjoiW[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]{30,}",
        "severity": "HIGH",
        "description": "Mapbox public access token",
        "false_positive_hints": ["pk.eyJ1IjoixxXX", "example"],
    },
    "mapbox_secret_token": {
        "regex": r"sk\.eyJ1IjoiW[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]{30,}",
        "severity": "CRITICAL",
        "description": "Mapbox secret access token",
        "false_positive_hints": ["sk.eyJ1IjoixxXX", "example"],
    },

    # ── Algolia ───────────────────────────────────────────────────────────────
    "algolia_admin_key": {
        "regex": r"(?i)ALGOLIA[_\s]?(?:ADMIN[_\s]?)?(?:API[_\s]?)?KEY\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "HIGH",
        "description": "Algolia Admin API key",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── Supabase ──────────────────────────────────────────────────────────────
    "supabase_service_key": {
        "regex": r"(?i)SUPABASE[_\s]?(?:SERVICE[_\s]?(?:ROLE[_\s]?)?)?KEY\s*[=:]\s*['\"]?(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)['\"]?",
        "severity": "CRITICAL",
        "description": "Supabase service role key (JWT with full DB access)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── PlanetScale ───────────────────────────────────────────────────────────
    "planetscale_token": {
        "regex": r"pscale_tkn_[a-zA-Z0-9_]{32,64}",
        "severity": "HIGH",
        "description": "PlanetScale service token",
        "false_positive_hints": ["pscale_tkn_xxxx", "pscale_tkn_example"],
    },

    # ── Linear ────────────────────────────────────────────────────────────────
    "linear_api_key": {
        "regex": r"lin_api_[a-zA-Z0-9]{40}",
        "severity": "HIGH",
        "description": "Linear API key",
        "false_positive_hints": ["lin_api_xxxx", "lin_api_example"],
    },

    # ── Notion ────────────────────────────────────────────────────────────────
    "notion_integration_token": {
        "regex": r"secret_[a-zA-Z0-9]{43}",
        "severity": "HIGH",
        "description": "Notion integration token",
        "false_positive_hints": ["secret_xxxx", "secret_example", "secret_your"],
    },

    # ── Airtable ──────────────────────────────────────────────────────────────
    "airtable_key": {
        "regex": r"pat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}",
        "severity": "HIGH",
        "description": "Airtable personal access token",
        "false_positive_hints": ["patxxxx", "example"],
    },

    # ── Docker Hub ───────────────────────────────────────────────────────────
    "docker_pat": {
        "regex": r"dckr_pat_[a-zA-Z0-9_\-]{27}",
        "severity": "HIGH",
        "description": "Docker Hub personal access token",
        "false_positive_hints": ["dckr_pat_xxxx", "dckr_pat_example"],
    },

    # ── Vault (HashiCorp) ─────────────────────────────────────────────────────
    "vault_token": {
        "regex": r"(?:hvs|s)\.[a-zA-Z0-9]{24,128}",
        "severity": "HIGH",
        "description": "HashiCorp Vault token",
        "false_positive_hints": ["hvs.xxxx", "s.xxxx", "example"],
    },

    # ── Pinecone ──────────────────────────────────────────────────────────────
    "pinecone_key": {
        "regex": r"(?i)PINECONE[_\s]?(?:API[_\s]?)?KEY\s*[=:]\s*['\"]?([a-f0-9\-]{36,})['\"]?",
        "severity": "HIGH",
        "description": "Pinecone API key",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── ElevenLabs ───────────────────────────────────────────────────────────
    "elevenlabs_key": {
        "regex": r"(?i)ELEVEN(?:LABS)?[_\s]?(?:API[_\s]?)?KEY\s*[=:]\s*['\"]?([a-zA-Z0-9]{32})['\"]?",
        "severity": "HIGH",
        "description": "ElevenLabs API key",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },

    # ── Resend ────────────────────────────────────────────────────────────────
    "resend_key": {
        "regex": r"re_[a-zA-Z0-9_]{36}",
        "severity": "HIGH",
        "description": "Resend API key",
        "false_positive_hints": ["re_xxxx", "re_example", "re_your"],
    },

    # ── CRYPTO / BLOCKCHAIN ───────────────────────────────────────────────────
    "eth_private_key": {
        "regex": r"0x[0-9a-fA-F]{64}",
        "severity": "CRITICAL",
        "description": "Ethereum private key (raw hex with 0x prefix)",
        "false_positive_hints": ["0x0000000000000000", "0xdeadbeef", "example", "xxxx"],
    },
    "eth_private_key_no0x": {
        "regex": r"(?i)(?:private[_\s]?key|privateKey)\s*[=:]\s*['\"]?([0-9a-fA-F]{64})['\"]?",
        "severity": "CRITICAL",
        "description": "Ethereum private key without 0x prefix (context-matched near private_key/privateKey)",
        "false_positive_hints": ["example", "xxxx", "0000000000000000"],
    },
    "mnemonic_12": {
        "regex": r"(?i)(?:mnemonic|seed[_\s]?phrase|recovery[_\s]?phrase)\s*[=:\"'\s]+(?:\b\w+\b\s+){11}\b\w+\b",
        "severity": "HIGH",
        "description": "12-word BIP39 mnemonic seed phrase (context-matched near mnemonic/seed)",
        "false_positive_hints": ["example", "test", "lorem ipsum"],
    },
    "mnemonic_24": {
        "regex": r"(?i)(?:mnemonic|seed[_\s]?phrase|recovery[_\s]?phrase)\s*[=:\"'\s]+(?:\b\w+\b\s+){23}\b\w+\b",
        "severity": "CRITICAL",
        "description": "24-word BIP39 mnemonic seed phrase (context-matched near mnemonic/seed)",
        "false_positive_hints": ["example", "test", "lorem ipsum"],
    },
    "btc_wif": {
        "regex": r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b",
        "severity": "CRITICAL",
        "description": "Bitcoin WIF (Wallet Import Format) private key",
        "false_positive_hints": ["example", "xxxx", "test"],
    },
    "btc_wif_compressed": {
        "regex": r"\bc[1-9A-HJ-NP-Za-km-z]{51}\b",
        "severity": "CRITICAL",
        "description": "Bitcoin compressed WIF private key",
        "false_positive_hints": ["example", "xxxx", "test"],
    },
    "xprv_key": {
        "regex": r"xprv[0-9A-Za-z]{107}",
        "severity": "CRITICAL",
        "description": "BIP32 extended private key (xprv prefix)",
        "false_positive_hints": ["xprvexample", "xxxx"],
    },
    "solana_private_key": {
        "regex": r"(?i)(?:SOLANA[_\s]?PRIVATE[_\s]?KEY|SOL[_\s]?PRIVATE[_\s]?KEY)\s*[=:]\s*['\"]?([1-9A-HJ-NP-Za-km-z]{87,88})['\"]?",
        "severity": "HIGH",
        "description": "Solana base58 private key (context-matched)",
        "false_positive_hints": ["example", "xxxx", "your_key"],
    },

    # ── CRYPTO EXCHANGE APIs ──────────────────────────────────────────────────
    "binance_api_key": {
        "regex": r"(?i)BINANCE[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{64})['\"]?",
        "severity": "HIGH",
        "description": "Binance API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "coinbase_api_key": {
        "regex": r"(?i)COINBASE[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{32,64})['\"]?",
        "severity": "HIGH",
        "description": "Coinbase API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "kraken_api_key": {
        "regex": r"(?i)KRAKEN[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9/+]{56})['\"]?",
        "severity": "HIGH",
        "description": "Kraken exchange API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "bybit_api_key": {
        "regex": r"(?i)BYBIT[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{18,32})['\"]?",
        "severity": "HIGH",
        "description": "Bybit exchange API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "kucoin_api_key": {
        "regex": r"(?i)KUCOIN[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{24})['\"]?",
        "severity": "HIGH",
        "description": "KuCoin exchange API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "okx_api_key": {
        "regex": r"(?i)OKX[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9\-]{36})['\"]?",
        "severity": "MEDIUM",
        "description": "OKX exchange API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "infura_key": {
        "regex": r"(?i)(?:INFURA[_\s]?(?:PROJECT[_\s]?)?(?:ID|KEY)|infura\.io/v3/)\s*[=:/]?\s*['\"]?([0-9a-f]{32})['\"]?",
        "severity": "HIGH",
        "description": "Infura Ethereum node project ID/key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key", "00000000000000000000000000000000"],
    },
    "alchemy_key": {
        "regex": r"(?i)ALCHEMY[_\s]?(?:API[_\s]?)?KEY\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{32})['\"]?",
        "severity": "HIGH",
        "description": "Alchemy API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "moralis_key": {
        "regex": r"(?i)MORALIS[_\s]?(?:API[_\s]?)?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{40})['\"]?",
        "severity": "HIGH",
        "description": "Moralis Web3 API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "etherscan_key": {
        "regex": r"(?i)ETHERSCAN[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Z0-9]{34})['\"]?",
        "severity": "MEDIUM",
        "description": "Etherscan API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "web3_provider": {
        "regex": r"wss?://[^/\s\"']+infura\.io/v3/[0-9a-f]{32}",
        "severity": "HIGH",
        "description": "Infura WebSocket/HTTP endpoint with embedded project key",
        "false_positive_hints": ["example", "your_key", "xxxx"],
    },

    # ── CLOUD PROVIDERS (extended) ────────────────────────────────────────────
    "azure_subscription": {
        "regex": r"(?i)subscription[_\s]?(?:id)?\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "severity": "MEDIUM",
        "description": "Azure subscription ID (context-matched near 'subscription')",
        "false_positive_hints": ["00000000-0000-0000-0000-000000000000", "example", "xxxx"],
    },
    "azure_client_secret": {
        "regex": r"(?i)AZURE[_\s]?CLIENT[_\s]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9_.\-~]{40,})['\"]?",
        "severity": "HIGH",
        "description": "Azure AD client secret (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_secret"],
    },
    "azure_storage_key": {
        "regex": r"DefaultEndpointsProtocol=https;AccountName=\w+;AccountKey=[A-Za-z0-9+/]{88}==",
        "severity": "CRITICAL",
        "description": "Azure Storage account connection string with full AccountKey",
        "false_positive_hints": ["AccountName=devstoreaccount1", "example", "xxxx"],
    },
    "digitalocean_spaces_key": {
        "regex": r"(?i)DO[_\s]?SPACES[_\s]?(?:KEY|SECRET|ACCESS)\s*[=:]\s*['\"]?([A-Za-z0-9]{20,})['\"]?",
        "severity": "HIGH",
        "description": "DigitalOcean Spaces access/secret key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "linode_token": {
        "regex": r"(?i)LINODE[_\s]?TOKEN\s*[=:]\s*['\"]?([A-Za-z0-9]{64})['\"]?",
        "severity": "HIGH",
        "description": "Linode API token (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },
    "vultr_api_key": {
        "regex": r"(?i)VULTR[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Z0-9]{36})['\"]?",
        "severity": "HIGH",
        "description": "Vultr API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "hetzner_token": {
        "regex": r"(?i)HETZNER[_\s]?(?:API[_\s]?)?TOKEN\s*[=:]\s*['\"]?([A-Za-z0-9]{64})['\"]?",
        "severity": "MEDIUM",
        "description": "Hetzner Cloud API token (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },
    "railway_token": {
        "regex": r"(?i)RAILWAY[_\s]?TOKEN\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{43})['\"]?",
        "severity": "MEDIUM",
        "description": "Railway deployment token (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },
    "render_api_key": {
        "regex": r"(?i)RENDER[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{32})['\"]?",
        "severity": "MEDIUM",
        "description": "Render.com API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "fly_token": {
        "regex": r"fo1_[A-Za-z0-9_\-]{40}",
        "severity": "MEDIUM",
        "description": "Fly.io API token (fo1_ prefix)",
        "false_positive_hints": ["fo1_xxxx", "fo1_example"],
    },
    "firebase_credential": {
        "regex": r"(?i)FIREBASE[_\s]?PRIVATE[_\s]?KEY\s*[=:]\s*['\"]?-----BEGIN[^\n]*PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Firebase service account private key (context-matched)",
        "false_positive_hints": ["example", "xxxx", "test"],
    },

    # ── DATABASE CONNECTION STRINGS (extended) ────────────────────────────────
    "elasticsearch_conn": {
        "regex": r"https?://[a-zA-Z0-9_\-]+:[^@\s\"']{6,}@[a-zA-Z0-9._\-]+:9200",
        "severity": "HIGH",
        "description": "Elasticsearch connection URL with embedded credentials",
        "false_positive_hints": ["localhost:9200", "127.0.0.1:9200", "user:password@"],
    },
    "database_url_generic": {
        "regex": r"(?i)DATABASE_URL\s*=\s*['\"]?\S+://[^:]+:[^@\s\"']{6,}@\S+",
        "severity": "HIGH",
        "description": "Generic DATABASE_URL with embedded credentials",
        "false_positive_hints": ["user:password@", "localhost", "127.0.0.1", "example"],
    },

    # ── PAYMENT / FINANCE ─────────────────────────────────────────────────────
    "paypal_client_secret": {
        "regex": r"(?i)PAYPAL[_\s]?CLIENT[_\s]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{40,})['\"]?",
        "severity": "HIGH",
        "description": "PayPal client secret (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_secret"],
    },
    "square_token": {
        "regex": r"sq0atp-[A-Za-z0-9_\-]{22}",
        "severity": "HIGH",
        "description": "Square access token (sq0atp- prefix)",
        "false_positive_hints": ["sq0atp-xxxx", "sq0atp-example"],
    },
    "braintree_key": {
        "regex": r"(?i)BRAINTREE[_\s]?PRIVATE[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{32})['\"]?",
        "severity": "HIGH",
        "description": "Braintree private key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "paddle_api_key": {
        "regex": r"(?i)PADDLE[_\s]?API[_\s]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{40})['\"]?",
        "severity": "MEDIUM",
        "description": "Paddle API key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "razorpay_key": {
        "regex": r"rzp_(?:live|test)_[A-Za-z0-9]{14}",
        "severity": "HIGH",
        "description": "Razorpay API key (rzp_live_ or rzp_test_ prefix)",
        "false_positive_hints": ["rzp_live_xxxx", "rzp_test_xxxx", "example"],
    },

    # ── SOCIAL / COMMUNICATION (extended) ─────────────────────────────────────
    "twitter_bearer": {
        "regex": r"AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,}",
        "severity": "HIGH",
        "description": "Twitter/X API Bearer Token",
        "false_positive_hints": ["example", "xxxx", "your_token"],
    },
    "twitter_consumer_key": {
        "regex": r"(?i)TWITTER[_\s]?(?:API[_\s]?KEY|CONSUMER[_\s]?KEY)\s*[=:]\s*['\"]?([A-Za-z0-9]{25})['\"]?",
        "severity": "HIGH",
        "description": "Twitter/X consumer key (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "facebook_token": {
        "regex": r"(?i)(?:FACEBOOK|FB)[_\s]?(?:ACCESS[_\s]?)?TOKEN\s*[=:]\s*['\"]?(EAA[A-Za-z0-9]+)['\"]?",
        "severity": "HIGH",
        "description": "Facebook/Meta access token (context-matched EAA prefix)",
        "false_positive_hints": ["EAAxxxx", "example", "your_token"],
    },
    "linkedin_secret": {
        "regex": r"(?i)LINKEDIN[_\s]?CLIENT[_\s]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9]{16})['\"]?",
        "severity": "MEDIUM",
        "description": "LinkedIn OAuth client secret (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_secret"],
    },
    "spotify_secret": {
        "regex": r"(?i)SPOTIFY[_\s]?CLIENT[_\s]?SECRET\s*[=:]\s*['\"]?([0-9a-f]{32})['\"]?",
        "severity": "MEDIUM",
        "description": "Spotify client secret (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_secret"],
    },
    "github_oauth_secret": {
        "regex": r"(?i)GITHUB[_\s]?CLIENT[_\s]?SECRET\s*[=:]\s*['\"]?([0-9a-f]{40})['\"]?",
        "severity": "HIGH",
        "description": "GitHub OAuth application client secret (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_secret"],
    },
    "gitlab_token": {
        "regex": r"glpat-[A-Za-z0-9_\-]{20}",
        "severity": "HIGH",
        "description": "GitLab personal access token (glpat- prefix)",
        "false_positive_hints": ["glpat-xxxx", "glpat-example"],
    },
    "vault_service_token": {
        "regex": r"hvs\.[A-Za-z0-9_\-]{24}",
        "severity": "HIGH",
        "description": "HashiCorp Vault service token (hvs. prefix)",
        "false_positive_hints": ["hvs.xxxx", "hvs.example"],
    },
    "ngrok_token": {
        "regex": r"(?i)NGROK[_\s]?AUTH[_\s]?TOKEN\s*[=:]\s*['\"]?([0-9a-zA-Z_\-]{49})['\"]?",
        "severity": "MEDIUM",
        "description": "ngrok authentication token (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_token"],
    },
    "pusher_secret": {
        "regex": r"(?i)PUSHER[_\s]?APP[_\s]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9]{20})['\"]?",
        "severity": "MEDIUM",
        "description": "Pusher app secret (context-matched)",
        "false_positive_hints": ["xxxx", "example", "your_secret"],
    },
    "algolia_admin_api_key": {
        "regex": r"(?i)ALGOLIA[_\s]?ADMIN[_\s]?(?:API[_\s]?)?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{32})['\"]?",
        "severity": "HIGH",
        "description": "Algolia Admin API key (context-matched, more specific than algolia_admin_key)",
        "false_positive_hints": ["xxxx", "example", "your_key"],
    },
    "mapbox_public_token": {
        "regex": r"pk\.ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "severity": "HIGH",
        "description": "Mapbox public token (pk.ey prefix, broader match)",
        "false_positive_hints": ["pk.eyJ1IjoixxXX", "example"],
    },

    # ── SSH / CERTIFICATES (explicit named variants) ──────────────────────────
    "ssh_rsa_private_key": {
        "regex": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "RSA private key header (PEM format)",
        "false_positive_hints": ["example", "test", "dummy"],
    },
    "ssh_openssh_private_key": {
        "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "OpenSSH private key header",
        "false_positive_hints": ["example", "test", "dummy"],
    },
    "ssh_ec_private_key": {
        "regex": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "EC (elliptic curve) private key header",
        "false_positive_hints": ["example", "test", "dummy"],
    },
    "pgp_private_key_block": {
        "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "CRITICAL",
        "description": "PGP private key block",
        "false_positive_hints": ["example", "test"],
    },
    "ssl_private_key": {
        "regex": r"-----BEGIN PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "PKCS#8 private key header (generic SSL/TLS)",
        "false_positive_hints": ["example", "test", "dummy"],
    },

    # ── MISC HIGH VALUE ───────────────────────────────────────────────────────
    "jwt_secret": {
        "regex": r"(?i)JWT[_\s]?(?:SECRET|KEY)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{32,})['\"]?",
        "severity": "HIGH",
        "description": "JWT signing secret (context-matched near JWT_SECRET/JWT_KEY)",
        "false_positive_hints": ["xxxx", "example", "your_secret", "changeme", "secret"],
    },
    "django_secret_key": {
        "regex": r"(?i)SECRET_KEY\s*=\s*['\"]([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{40,})['\"]",
        "severity": "MEDIUM",
        "description": "Django/Flask SECRET_KEY in Python settings",
        "false_positive_hints": ["xxxx", "example", "your-secret-key", "changeme", "insecure"],
    },
    "encryption_key": {
        "regex": r"(?i)(?:ENCRYPTION[_\s]?KEY|AES[_\s]?KEY)\s*[=:]\s*['\"]?([0-9a-fA-F]{32,64})['\"]?",
        "severity": "HIGH",
        "description": "Encryption key — AES or generic hex (context-matched)",
        "false_positive_hints": ["xxxx", "example", "0000000000000000", "your_key"],
    },
    "twilio_auth_token_bare": {
        "regex": r"(?i)TWILIO[_\s]?AUTH[_\s]?TOKEN\s*[=:]\s*['\"]?([0-9a-f]{32})['\"]?",
        "severity": "HIGH",
        "description": "Twilio Auth Token (context-matched, bare pattern)",
        "false_positive_hints": ["xxxx", "example", "your_token", "00000000000000000000000000000000"],
    },
    "mailgun_api_key": {
        "regex": r"key-[0-9a-z]{32}",
        "severity": "HIGH",
        "description": "Mailgun API key (key- prefix, lowercase hex)",
        "false_positive_hints": ["key-xxxx", "key-your", "key-example"],
    },

    # ── Shopify ───────────────────────────────────────────────────────────────
    "shopify_admin_token": {
        "regex": r"shpat_[a-fA-F0-9]{32}",
        "severity": "CRITICAL",
        "description": "Shopify Admin API token",
        "false_positive_hints": ["shpat_xxxx", "shpat_test"],
    },
    "shopify_private_app": {
        "regex": r"shppa_[a-fA-F0-9]{32}",
        "severity": "CRITICAL",
        "description": "Shopify Private App token",
        "false_positive_hints": [],
    },
    "shopify_shared_secret": {
        "regex": r"shpss_[a-fA-F0-9]{32}",
        "severity": "HIGH",
        "description": "Shopify Shared Secret",
        "false_positive_hints": [],
    },
    "shopify_storefront": {
        "regex": r"shpca_[a-fA-F0-9]{32}",
        "severity": "MEDIUM",
        "description": "Shopify Custom App token",
        "false_positive_hints": [],
    },

    # ── HubSpot ───────────────────────────────────────────────────────────────
    "hubspot_api_key": {
        "regex": r"pat-[a-z]{2}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "HIGH",
        "description": "HubSpot Private App token",
        "false_positive_hints": [],
    },

    # ── Okta ──────────────────────────────────────────────────────────────────
    "okta_token": {
        "regex": r"00[a-zA-Z0-9_-]{40}",
        "severity": "CRITICAL",
        "description": "Okta API token (ssws prefix context)",
        "false_positive_hints": ["00xxxx", "00test"],
    },
    "okta_ssws": {
        "regex": r"ssws\s+[a-zA-Z0-9_-]{42,}",
        "severity": "CRITICAL",
        "description": "Okta SSWS API token with prefix",
        "false_positive_hints": [],
    },

    # ── Databricks ────────────────────────────────────────────────────────────
    "databricks_token": {
        "regex": r"dapi[a-f0-9]{32}",
        "severity": "HIGH",
        "description": "Databricks API token",
        "false_positive_hints": ["dapixxxx", "dapitest"],
    },

    # ── Postman ───────────────────────────────────────────────────────────────
    "postman_api_key": {
        "regex": r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}",
        "severity": "HIGH",
        "description": "Postman API key",
        "false_positive_hints": [],
    },

    # ── New Relic ─────────────────────────────────────────────────────────────
    "new_relic_ingest": {
        "regex": r"NRAK-[A-Z0-9]{27}",
        "severity": "HIGH",
        "description": "New Relic Ingest key",
        "false_positive_hints": [],
    },
    "new_relic_user": {
        "regex": r"NRIQ-[A-Z0-9]{27}",
        "severity": "HIGH",
        "description": "New Relic User API key",
        "false_positive_hints": [],
    },

    # ── Grafana ───────────────────────────────────────────────────────────────
    "grafana_api_key": {
        "regex": r"eyJrIjoi[A-Za-z0-9+/]{40,}",
        "severity": "HIGH",
        "description": "Grafana API key (base64 starting with eyJrIjoi)",
        "false_positive_hints": [],
    },
    "grafana_cloud_token": {
        "regex": r"glc_[A-Za-z0-9+/=]{32,}",
        "severity": "HIGH",
        "description": "Grafana Cloud token",
        "false_positive_hints": [],
    },

    # ── Pulumi ────────────────────────────────────────────────────────────────
    "pulumi_access_token": {
        "regex": r"pul-[a-f0-9]{40}",
        "severity": "HIGH",
        "description": "Pulumi access token",
        "false_positive_hints": [],
    },

    # ── Kubernetes ────────────────────────────────────────────────────────────
    "k8s_secret_yaml": {
        "regex": r"kind:\s*Secret[\s\S]{0,200}data:[\s\S]{0,500}[A-Za-z0-9+/]{40,}={0,2}",
        "severity": "HIGH",
        "description": "Kubernetes Secret manifest with base64 data",
        "false_positive_hints": ["example", "placeholder", "changeme"],
    },

    # ── PagerDuty ─────────────────────────────────────────────────────────────
    "pagerduty_key": {
        "regex": r"(?i)PAGERDUTY[_\s]*(?:API[_\s]*)?KEY\s*=\s*[a-zA-Z0-9+/]{20}",
        "severity": "HIGH",
        "description": "PagerDuty API key",
        "false_positive_hints": [],
    },

    # ── Zendesk ───────────────────────────────────────────────────────────────
    "zendesk_secret": {
        "regex": r"(?i)ZENDESK[_\s]*(?:API[_\s]*)?TOKEN\s*[=:]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",
        "severity": "MEDIUM",
        "description": "Zendesk API token (context-matched)",
        "false_positive_hints": [],
    },

    # ── Jira / Atlassian ──────────────────────────────────────────────────────
    "atlassian_token": {
        "regex": r"(?i)(?:JIRA|ATLASSIAN|CONFLUENCE)[_\s]*TOKEN\s*=\s*[A-Za-z0-9+/]{24,}={0,2}",
        "severity": "HIGH",
        "description": "Atlassian/Jira API token",
        "false_positive_hints": [],
    },

    # ── Notion (additional format) ────────────────────────────────────────────
    "notion_token": {
        "regex": r"ntn_[a-zA-Z0-9]{43}",
        "severity": "HIGH",
        "description": "Notion API token (ntn_ format)",
        "false_positive_hints": [],
    },

    # ── Weaviate ──────────────────────────────────────────────────────────────
    "weaviate_key": {
        "regex": r"(?i)WEAVIATE[_\s]*API[_\s]*KEY\s*[=:]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?",
        "severity": "MEDIUM",
        "description": "Weaviate API key",
        "false_positive_hints": [],
    },

    # ── Supabase anon key ─────────────────────────────────────────────────────
    "supabase_anon_key": {
        "regex": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "severity": "MEDIUM",
        "description": "Supabase JWT anon key (public, but reveals project)",
        "false_positive_hints": [],
    },

    # ── OpenAI service account (2024 format) ──────────────────────────────────
    "openai_service_account": {
        "regex": r"sk-svcacct-[a-zA-Z0-9_-]{100,}",
        "severity": "CRITICAL",
        "description": "OpenAI Service Account key (2024 format)",
        "false_positive_hints": [],
    },

    # ── Anthropic (enhanced full format) ──────────────────────────────────────
    "anthropic_beta_key": {
        "regex": r"sk-ant-[a-zA-Z0-9_-]{95,}",
        "severity": "CRITICAL",
        "description": "Anthropic API key (full format, ≥95 chars after prefix)",
        "false_positive_hints": ["sk-ant-xxxx", "sk-ant-your"],
    },

    # ── Azure OpenAI ──────────────────────────────────────────────────────────
    "azure_openai_key": {
        "regex": r"(?i)AZURE[_\s]*OPENAI[_\s]*(?:API[_\s]*)?KEY\s*=\s*[a-f0-9]{32}",
        "severity": "CRITICAL",
        "description": "Azure OpenAI API key",
        "false_positive_hints": [],
    },

    # ── Perplexity AI ─────────────────────────────────────────────────────────
    "perplexity_key": {
        "regex": r"pplx-[a-f0-9]{48}",
        "severity": "HIGH",
        "description": "Perplexity AI API key",
        "false_positive_hints": [],
    },

    # ── PAYPAL (extended) ─────────────────────────────────────────────────────
    "paypal_client_id": {
        "regex": r"(?i)PAYPAL_CLIENT_ID\s*=\s*[A-Za-z0-9_-]{80}",
        "severity": "HIGH",
        "description": "PayPal Client ID",
        "false_positive_hints": ["sandbox", "test", "example", "your_client"],
    },
    "paypal_access_token": {
        "regex": r"access_token\$[a-z]+\$[a-f0-9]{4}\$[a-f0-9]{4}\$[a-f0-9]{16}",
        "severity": "CRITICAL",
        "description": "PayPal Bearer access token",
        "false_positive_hints": [],
    },

    # ── CREDIT CARDS ──────────────────────────────────────────────────────────
    "credit_card_visa": {
        "regex": r"4[0-9]{12}(?:[0-9]{3})?",
        "severity": "CRITICAL",
        "description": "Visa credit card number",
        "false_positive_hints": ["4111111111111111", "4242424242424242", "test", "example", "dummy", "fake", "4000"],
    },
    "credit_card_mastercard": {
        "regex": r"5[1-5][0-9]{14}",
        "severity": "CRITICAL",
        "description": "Mastercard credit card number",
        "false_positive_hints": ["5500005555555559", "5105105105105100", "test", "dummy"],
    },
    "credit_card_amex": {
        "regex": r"3[47][0-9]{13}",
        "severity": "CRITICAL",
        "description": "American Express credit card number",
        "false_positive_hints": ["378282246310005", "371449635398431", "test"],
    },
    "credit_card_discover": {
        "regex": r"6(?:011|5[0-9]{2})[0-9]{12}",
        "severity": "HIGH",
        "description": "Discover credit card number",
        "false_positive_hints": ["6011111111111117", "test"],
    },
    "credit_card_cvv": {
        "regex": r"(?i)(?:cvv|cvc|cvv2|csc)\s*[=:]\s*[0-9]{3,4}",
        "severity": "CRITICAL",
        "description": "Credit card CVV/CVC code",
        "false_positive_hints": ["123", "000", "test"],
    },

    # ── IBAN / BANK ACCOUNT ───────────────────────────────────────────────────
    "iban": {
        "regex": r"[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}",
        "severity": "HIGH",
        "description": "IBAN bank account number",
        "false_positive_hints": ["GB29NWBK60161331926819", "DE89370400440532013000", "test"],
    },

    # ── BITCOIN / ETHEREUM ADDRESSES ──────────────────────────────────────────
    "bitcoin_address": {
        "regex": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
        "severity": "MEDIUM",
        "description": "Bitcoin wallet address (public — financial target)",
        "false_positive_hints": ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "test"],
    },
    "ethereum_address": {
        "regex": r"0x[a-fA-F0-9]{40}",
        "severity": "MEDIUM",
        "description": "Ethereum wallet address (public — financial target)",
        "false_positive_hints": ["0x0000000000000000000000000000000000000000"],
    },

    # ── PAYONEER ──────────────────────────────────────────────────────────────
    "payoneer_token": {
        "regex": r"(?i)PAYONEER[_\s]*(?:API[_\s]*)?(?:KEY|TOKEN|SECRET)\s*=\s*[a-zA-Z0-9]{32,}",
        "severity": "HIGH",
        "description": "Payoneer API credentials",
        "false_positive_hints": [],
    },

    # ── WISE (TransferWise) ───────────────────────────────────────────────────
    "wise_api_key": {
        "regex": r"(?i)WISE[_\s]*(?:API[_\s]*)?(?:KEY|TOKEN)\s*=\s*[a-zA-Z0-9_-]{36,}",
        "severity": "HIGH",
        "description": "Wise (TransferWise) API key",
        "false_positive_hints": [],
    },

    # ── REVOLUT ───────────────────────────────────────────────────────────────
    "revolut_api_key": {
        "regex": r"(?i)REVOLUT[_\s]*(?:API[_\s]*)?(?:KEY|TOKEN)\s*=\s*[a-zA-Z0-9_-]{32,}",
        "severity": "HIGH",
        "description": "Revolut Business API key",
        "false_positive_hints": [],
    },

    # ── COINPAYMENTS ──────────────────────────────────────────────────────────
    "coinpayments_secret": {
        "regex": r"(?i)COINPAYMENTS[_\s]*(?:PRIVATE|SECRET)[_\s]*KEY\s*=\s*[a-f0-9]{64}",
        "severity": "CRITICAL",
        "description": "CoinPayments private key",
        "false_positive_hints": [],
    },

    # ── ADYEN ─────────────────────────────────────────────────────────────────
    "adyen_api_key": {
        "regex": r"AQE[a-zA-Z0-9+/]{98}={0,2}",
        "severity": "CRITICAL",
        "description": "Adyen API key",
        "false_positive_hints": [],
    },

    # ── MERGED FROM missing_patterns.py (Gitleaks+TruffleHog+detect-secrets) ──
    'shopify_access_token': {
        'regex': 'shpat_[a-fA-F0-9]{32}',
        'severity': 'CRITICAL',
        'description': 'Shopify merchant access token (shpat_ prefix)',
        'keywords': ['shpat_'],
        'false_positive_hints': ['shpat_xxxx', 'shpat_example', 'shpat_test'],
    },
    'shopify_custom_access_token': {
        'regex': 'shpca_[a-fA-F0-9]{32}',
        'severity': 'CRITICAL',
        'description': 'Shopify custom app access token (shpca_ prefix)',
        'keywords': ['shpca_'],
        'false_positive_hints': ['shpca_xxxx', 'shpca_example'],
    },
    'shopify_private_app_token': {
        'regex': 'shppa_[a-fA-F0-9]{32}',
        'severity': 'CRITICAL',
        'description': 'Shopify private app access token (shppa_ prefix)',
        'keywords': ['shppa_'],
        'false_positive_hints': ['shppa_xxxx', 'shppa_example'],
    },
    'databricks_api_token': {
        'regex': '\\bdapi[a-f0-9]{32}(?:-\\d)?\\b',
        'severity': 'CRITICAL',
        'description': 'Databricks personal access token (dapi prefix)',
        'keywords': ['dapi'],
        'entropy_min': 3.0,
        'false_positive_hints': ['dapi0000000000000000000000000000', 'example', 'xxxx'],
    },
    'anthropic_admin_key': {
        'regex': '\\bsk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA\\b',
        'severity': 'CRITICAL',
        'description': 'Anthropic Admin API key (sk-ant-admin01- prefix, full account access)',
        'keywords': ['sk-ant-admin01-'],
        'false_positive_hints': ['sk-ant-admin01-xxxx', 'example'],
    },
    'atlassian_api_token': {
        'regex': '\\bATATT3[A-Za-z0-9_\\-=]{186}\\b',
        'severity': 'CRITICAL',
        'description': 'Atlassian API token (ATATT3 prefix — Jira/Confluence access)',
        'keywords': ['atatt3'],
        'entropy_min': 3.5,
        'false_positive_hints': ['ATATT3xxxx', 'example'],
    },
    'new_relic_browser_api_token': {
        'regex': '\\bNRJS-[a-f0-9]{19}\\b',
        'severity': 'HIGH',
        'description': 'New Relic browser ingest API token (NRJS- prefix)',
        'keywords': ['nrjs-'],
        'false_positive_hints': ['NRJS-xxxx', 'NRJS-example'],
    },
    'new_relic_insert_key': {
        'regex': '\\bNRII-[a-zA-Z0-9\\-]{32}\\b',
        'severity': 'HIGH',
        'description': 'New Relic Insights insert key (NRII- prefix)',
        'keywords': ['nrii-'],
        'false_positive_hints': ['NRII-xxxx', 'NRII-example'],
    },
    'new_relic_user_api_key': {
        'regex': '\\bNRAK-[a-zA-Z0-9]{27}\\b',
        'severity': 'HIGH',
        'description': 'New Relic user API key (NRAK- prefix)',
        'keywords': ['nrak-'],
        'false_positive_hints': ['NRAK-xxxx', 'NRAK-example'],
    },
    'grafana_cloud_api_token': {
        'regex': '\\bglc_[A-Za-z0-9+/]{32,400}={0,3}',
        'severity': 'HIGH',
        'description': 'Grafana Cloud API token (glc_ prefix)',
        'keywords': ['glc_'],
        'entropy_min': 3.0,
        'false_positive_hints': ['glc_xxxx', 'glc_example'],
    },
    'grafana_service_account_token': {
        'regex': '\\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\\b',
        'severity': 'HIGH',
        'description': 'Grafana service account token (glsa_ prefix)',
        'keywords': ['glsa_'],
        'false_positive_hints': ['glsa_xxxx_00000000', 'example'],
    },
    'doppler_api_token': {
        'regex': '\\bdp\\.pt\\.[a-zA-Z0-9]{43}\\b',
        'severity': 'HIGH',
        'description': 'Doppler secrets manager API token (dp.pt. prefix)',
        'keywords': ['dp.pt.'],
        'entropy_min': 2.0,
        'false_positive_hints': ['dp.pt.xxxx', 'dp.pt.example'],
    },
    'postman_api_token': {
        'regex': '\\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\\b',
        'severity': 'HIGH',
        'description': 'Postman API token (PMAK- prefix)',
        'keywords': ['pmak-'],
        'false_positive_hints': ['PMAK-xxxx', 'PMAK-example'],
    },
    'perplexity_api_key': {
        'regex': '\\bpplx-[a-zA-Z0-9]{48}\\b',
        'severity': 'CRITICAL',
        'description': 'Perplexity AI API key (pplx- prefix)',
        'keywords': ['pplx-'],
        'entropy_min': 4.0,
        'false_positive_hints': ['pplx-xxxx', 'pplx-example'],
    },
    'pulumi_api_token': {
        'regex': '\\bpul-[a-f0-9]{40}\\b',
        'severity': 'HIGH',
        'description': 'Pulumi Infrastructure-as-Code API token (pul- prefix)',
        'keywords': ['pul-'],
        'entropy_min': 2.0,
        'false_positive_hints': ['pul-xxxx', 'pul-example'],
    },
    'snyk_api_token': {
        'regex': '(?i)(?:snyk[_.\\-]?(?:(?:api|oauth)[_.\\-]?)?(?:key|token))\\s*[=:]\\s*[\'\\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\'\\"]?',
        'severity': 'HIGH',
        'description': 'Snyk security scanning API token (UUID format, context-matched near snyk)',
        'keywords': ['snyk'],
        'false_positive_hints': ['00000000-0000-0000-0000-000000000000', 'example', 'xxxx'],
    },
    'dynatrace_api_token': {
        'regex': '\\bdt0c01\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{64}\\b',
        'severity': 'HIGH',
        'description': 'Dynatrace API token (dt0c01. prefix)',
        'keywords': ['dt0c01.'],
        'entropy_min': 4.0,
        'false_positive_hints': ['dt0c01.xxxx', 'example'],
    },
    'notion_api_token_v2': {
        'regex': '\\bntn_[0-9]{11}[A-Za-z0-9]{35}\\b',
        'severity': 'HIGH',
        'description': 'Notion integration token (new ntn_ format, 2024+)',
        'keywords': ['ntn_'],
        'entropy_min': 4.0,
        'false_positive_hints': ['ntn_00000000000xxxx', 'example'],
    },
    'sendinblue_api_token': {
        'regex': '\\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\\b',
        'severity': 'HIGH',
        'description': 'Brevo/Sendinblue email API token (xkeysib- prefix)',
        'keywords': ['xkeysib-'],
        'entropy_min': 2.0,
        'false_positive_hints': ['xkeysib-xxxx', 'example'],
    },
    'sentry_user_token': {
        'regex': '\\bsntryu_[a-f0-9]{64}\\b',
        'severity': 'HIGH',
        'description': 'Sentry.io user auth token (sntryu_ prefix)',
        'keywords': ['sntryu_'],
        'entropy_min': 3.5,
        'false_positive_hints': ['sntryu_xxxx', 'example'],
    },
    'sentry_org_token': {
        'regex': '\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}',
        'severity': 'CRITICAL',
        'description': 'Sentry.io organization auth token (sntrys_ prefix)',
        'keywords': ['sntrys_'],
        'entropy_min': 4.5,
        'false_positive_hints': ['sntrys_xxxx', 'example'],
    },
    'typeform_api_token': {
        'regex': '(?i)(?:typeform)(?:[\\s\\w.-]{0,20})[\\s=:\\"\']{1,5}(tfp_[a-zA-Z0-9\\-_\\.=]{59})',
        'severity': 'MEDIUM',
        'description': 'Typeform survey API token (tfp_ prefix, context-matched)',
        'keywords': ['typeform', 'tfp_'],
        'false_positive_hints': ['tfp_xxxx', 'example'],
    },
    'frameio_api_token': {
        'regex': '\\bfio-u-[a-zA-Z0-9\\-_=]{64}\\b',
        'severity': 'HIGH',
        'description': 'Frame.io video collaboration API token (fio-u- prefix)',
        'keywords': ['fio-u-'],
        'false_positive_hints': ['fio-u-xxxx', 'example'],
    },
    'onepassword_service_account': {
        'regex': '\\bops_eyJ[a-zA-Z0-9+/]{250,}={0,3}',
        'severity': 'CRITICAL',
        'description': '1Password service account token (ops_eyJ prefix)',
        'keywords': ['ops_eyj'],
        'entropy_min': 4.0,
        'false_positive_hints': ['ops_eyJxxxx', 'example'],
    },
    'onepassword_secret_key': {
        'regex': '\\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b',
        'severity': 'CRITICAL',
        'description': '1Password account secret key (A3- prefix with structured format)',
        'keywords': ['a3-'],
        'false_positive_hints': ['A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX', 'example'],
    },
    'harness_api_key': {
        'regex': '\\b(?:pat|sat)\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}\\b',
        'severity': 'HIGH',
        'description': 'Harness CI/CD platform API token (pat./sat. structured prefix)',
        'keywords': ['pat.', 'sat.'],
        'false_positive_hints': ['pat.xxxx', 'sat.xxxx', 'example'],
    },
    'okta_access_token': {
        'regex': '(?i)(?:okta)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}(00[\\w=\\-]{40})',
        'severity': 'HIGH',
        'description': 'Okta API access token (00 prefix, 42 chars, context-matched near okta)',
        'keywords': ['okta'],
        'entropy_min': 4.0,
        'false_positive_hints': ['00xxxx', 'example', 'your_token'],
    },
    'openshift_user_token': {
        'regex': '\\bsha256~[\\w\\-]{43}\\b',
        'severity': 'HIGH',
        'description': 'OpenShift/Kubernetes user auth token (sha256~ prefix)',
        'keywords': ['sha256~'],
        'entropy_min': 3.5,
        'false_positive_hints': ['sha256~xxxx', 'example'],
    },
    'rubygems_api_token': {
        'regex': '\\brubygems_[a-f0-9]{48}\\b',
        'severity': 'HIGH',
        'description': 'RubyGems.org API token (rubygems_ prefix)',
        'keywords': ['rubygems_'],
        'false_positive_hints': ['rubygems_xxxx', 'example'],
    },
    'shippo_api_token': {
        'regex': '\\bshippo_(?:live|test)_[a-fA-F0-9]{40}\\b',
        'severity': 'HIGH',
        'description': 'Shippo shipping API token (shippo_live_ or shippo_test_ prefix)',
        'keywords': ['shippo_live_', 'shippo_test_'],
        'false_positive_hints': ['shippo_live_xxxx', 'shippo_test_xxxx', 'example'],
    },
    'easypost_api_token': {
        'regex': '\\bEZAK[a-zA-Z0-9]{54}\\b',
        'severity': 'HIGH',
        'description': 'EasyPost shipping API token (EZAK prefix)',
        'keywords': ['ezak'],
        'false_positive_hints': ['EZAKxxxx', 'example'],
    },
    'easypost_test_token': {
        'regex': '\\bEZTK[a-zA-Z0-9]{54}\\b',
        'severity': 'MEDIUM',
        'description': 'EasyPost test API token (EZTK prefix)',
        'keywords': ['eztk'],
        'false_positive_hints': ['EZTKxxxx', 'example'],
    },
    'artifactory_api_key': {
        'regex': '\\bAKCp[A-Za-z0-9]{69}\\b',
        'severity': 'HIGH',
        'description': 'JFrog Artifactory API key (AKCp prefix)',
        'keywords': ['akcp'],
        'entropy_min': 4.5,
        'false_positive_hints': ['AKCpxxxx', 'example'],
    },
    'jfrog_identity_token': {
        'regex': '(?i)(?:jfrog|artifactory|bintray|xray)(?:[\\s\\w.-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{73})',
        'severity': 'HIGH',
        'description': 'JFrog identity/reference token (context-matched near jfrog/artifactory)',
        'keywords': ['jfrog', 'artifactory', 'xray'],
        'entropy_min': 4.5,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'scalingo_api_token': {
        'regex': '\\btk-us-[\\w\\-]{48}\\b',
        'severity': 'HIGH',
        'description': 'Scalingo PaaS API token (tk-us- prefix)',
        'keywords': ['tk-us-'],
        'entropy_min': 2.0,
        'false_positive_hints': ['tk-us-xxxx', 'example'],
    },
    'prefect_api_token': {
        'regex': '\\bpnu_[a-zA-Z0-9]{36}\\b',
        'severity': 'HIGH',
        'description': 'Prefect workflow orchestration API token (pnu_ prefix)',
        'keywords': ['pnu_'],
        'entropy_min': 2.0,
        'false_positive_hints': ['pnu_xxxx', 'example'],
    },
    'readme_api_token': {
        'regex': '\\brdme_[a-zA-Z0-9]{70}\\b',
        'severity': 'MEDIUM',
        'description': 'ReadMe.io documentation API token (rdme_ prefix)',
        'keywords': ['rdme_'],
        'entropy_min': 2.0,
        'false_positive_hints': ['rdme_xxxx', 'example'],
    },
    'vault_batch_token': {
        'regex': '\\bhvb\\.[\\w\\-]{138,300}\\b',
        'severity': 'HIGH',
        'description': 'HashiCorp Vault batch token (hvb. prefix — longer than service tokens)',
        'keywords': ['hvb.'],
        'entropy_min': 4.0,
        'false_positive_hints': ['hvb.xxxx', 'example'],
    },
    'planetscale_oauth_token': {
        'regex': '\\bpscale_oauth_[\\w=.\\-]{32,64}\\b',
        'severity': 'HIGH',
        'description': 'PlanetScale OAuth token (pscale_oauth_ prefix)',
        'keywords': ['pscale_oauth_'],
        'entropy_min': 3.0,
        'false_positive_hints': ['pscale_oauth_xxxx', 'example'],
    },
    'planetscale_password': {
        'regex': '\\bpscale_pw_[\\w=.\\-]{32,64}\\b',
        'severity': 'HIGH',
        'description': 'PlanetScale database password (pscale_pw_ prefix)',
        'keywords': ['pscale_pw_'],
        'entropy_min': 3.0,
        'false_positive_hints': ['pscale_pw_xxxx', 'example'],
    },
    'age_secret_key': {
        'regex': '\\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\\b',
        'severity': 'CRITICAL',
        'description': 'Age encryption tool secret key (AGE-SECRET-KEY-1 bech32 prefix)',
        'keywords': ['age-secret-key-1'],
        'false_positive_hints': ['AGE-SECRET-KEY-1xxxx', 'example'],
    },
    'alibaba_access_key_id': {
        'regex': '\\bLTAI[a-zA-Z0-9]{20}\\b',
        'severity': 'HIGH',
        'description': 'Alibaba Cloud AccessKey ID (LTAI prefix)',
        'keywords': ['ltai'],
        'entropy_min': 2.0,
        'false_positive_hints': ['LTAIxxxx', 'LTAIexample'],
    },
    'alibaba_secret_key': {
        'regex': '(?i)(?:alibaba)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-z0-9]{30})',
        'severity': 'HIGH',
        'description': 'Alibaba Cloud secret key (context-matched near alibaba, 30-char lowercase hex)',
        'keywords': ['alibaba'],
        'entropy_min': 2.0,
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'clojars_api_token': {
        'regex': '(?i)\\bCLOJARS_[a-zA-Z0-9]{60}\\b',
        'severity': 'HIGH',
        'description': 'Clojars Clojure package registry API token (CLOJARS_ prefix)',
        'keywords': ['clojars_'],
        'entropy_min': 2.0,
        'false_positive_hints': ['CLOJARS_xxxx', 'example'],
    },
    'maxmind_license_key': {
        'regex': '\\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\\b',
        'severity': 'MEDIUM',
        'description': 'MaxMind GeoIP database license key (_mmk suffix)',
        'keywords': ['_mmk'],
        'entropy_min': 4.0,
        'false_positive_hints': ['xxxxxx_xxxx_mmk', 'example'],
    },
    'yandex_access_token': {
        'regex': '(?i)(?:yandex)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}(t1\\.[A-Z0-9a-z_\\-]+={0,2}\\.[A-Z0-9a-z_\\-]{86}={0,2})',
        'severity': 'HIGH',
        'description': 'Yandex OAuth access token (t1. prefix, context-matched)',
        'keywords': ['yandex'],
        'false_positive_hints': ['t1.xxxx', 'example'],
    },
    'yandex_api_key': {
        'regex': '\\bAQVN[A-Za-z0-9_\\-]{35,38}\\b',
        'severity': 'HIGH',
        'description': 'Yandex Cloud API key (AQVN prefix)',
        'keywords': ['aqvn'],
        'false_positive_hints': ['AQVNxxxx', 'example'],
    },
    'yandex_aws_access_token': {
        'regex': '\\bYC[a-zA-Z0-9_\\-]{38}\\b',
        'severity': 'HIGH',
        'description': 'Yandex AWS-compatible access token (YC prefix)',
        'keywords': ['yc'],
        'false_positive_hints': ['YCxxxx', 'example'],
    },
    'microsoft_teams_webhook': {
        'regex': 'https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}',
        'severity': 'HIGH',
        'description': 'Microsoft Teams incoming webhook URL (contains org/tenant identifiers)',
        'keywords': ['webhook.office.com'],
        'false_positive_hints': ['example', 'your_webhook'],
    },
    'hashicorp_tf_api_token': {
        'regex': '(?i)[a-z0-9]{14}\\.atlasv1\\.[a-zA-Z0-9\\-_=]{60,70}',
        'severity': 'HIGH',
        'description': 'HashiCorp Terraform Cloud user/team API token (atlasv1. prefix segment)',
        'keywords': ['atlasv1'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx.atlasv1.xxxx', 'example'],
    },
    'heroku_api_key_v2': {
        'regex': '\\bHRKU-AA[0-9a-zA-Z_\\-]{58}\\b',
        'severity': 'HIGH',
        'description': 'Heroku API key v2 format (HRKU-AA prefix)',
        'keywords': ['hrku-aa'],
        'entropy_min': 4.0,
        'false_positive_hints': ['HRKU-AAxxxx', 'example'],
    },
    'launchdarkly_access_token': {
        'regex': '(?i)(?:launchdarkly)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_\\-=]{40})',
        'severity': 'HIGH',
        'description': 'LaunchDarkly feature flag access token (context-matched near launchdarkly)',
        'keywords': ['launchdarkly'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'twitch_api_token': {
        'regex': '(?i)(?:twitch)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-z0-9]{30})',
        'severity': 'HIGH',
        'description': 'Twitch streaming platform API token (context-matched near twitch)',
        'keywords': ['twitch'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'twitter_access_token': {
        'regex': '(?i)(?:twitter)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})',
        'severity': 'HIGH',
        'description': 'Twitter/X OAuth access token (numeric_id-alphanumeric format, context-matched)',
        'keywords': ['twitter'],
        'false_positive_hints': ['xxxx', 'example', 'your_token', '123456789012345-xxxx'],
    },
    'twitter_access_secret': {
        'regex': '(?i)(?:twitter)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-z0-9]{45})',
        'severity': 'HIGH',
        'description': 'Twitter/X OAuth access secret (45-char, context-matched near twitter)',
        'keywords': ['twitter'],
        'false_positive_hints': ['xxxx', 'example'],
    },
    'twitter_api_secret': {
        'regex': '(?i)(?:twitter[_\\s]?(?:api[_\\s]?)?secret|twitter[_\\s]?consumer[_\\s]?secret)[\\s=:\\"\']{1,5}([a-z0-9]{50})',
        'severity': 'HIGH',
        'description': 'Twitter/X API consumer secret (50-char, context-matched)',
        'keywords': ['twitter'],
        'false_positive_hints': ['xxxx', 'example'],
    },
    'sonarqube_api_token': {
        'regex': '(?i)(?:sonar[_.\\-]?(?:login|token))(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}((?:squ_|sqp_|sqa_)[a-zA-Z0-9_\\-=]{40}|[a-zA-Z0-9_\\-=]{40})',
        'severity': 'HIGH',
        'description': 'SonarQube/SonarCloud API token (squ_/sqp_/sqa_ prefix or context-matched near sonar)',
        'keywords': ['sonar'],
        'entropy_min': 3.5,
        'false_positive_hints': ['squ_xxxx', 'sqp_xxxx', 'example'],
    },
    'sourcegraph_access_token': {
        'regex': '\\bsgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}\\b',
        'severity': 'HIGH',
        'description': 'Sourcegraph code search access token (sgp_ prefix)',
        'keywords': ['sgp_'],
        'entropy_min': 3.0,
        'false_positive_hints': ['sgp_xxxx_xxxx', 'example'],
    },
    'cisco_meraki_api_key': {
        'regex': '(?i)(?:meraki)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([0-9a-f]{40})',
        'severity': 'HIGH',
        'description': 'Cisco Meraki network management API key (40-char hex, context-matched near meraki)',
        'keywords': ['meraki'],
        'entropy_min': 3.0,
        'false_positive_hints': ['xxxx', 'example', '0000000000000000000000000000000000000000'],
    },
    'travisci_access_token': {
        'regex': '(?i)(?:travis)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_\\-]{22})',
        'severity': 'MEDIUM',
        'description': 'Travis CI access token (22-char, context-matched near travis)',
        'keywords': ['travis'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'zendesk_api_token': {
        'regex': '(?i)(?:zendesk)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{40})',
        'severity': 'HIGH',
        'description': 'Zendesk support platform API token (context-matched near zendesk)',
        'keywords': ['zendesk'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'ibm_cloud_api_key': {
        'regex': '(?i)(?:ibm[_\\s]?(?:cloud[_\\s]?)?api[_\\s]?key|IBMCLOUD_API_KEY)[\\s=:\\"\']{1,5}([A-Za-z0-9_\\-]{44})',
        'severity': 'CRITICAL',
        'description': 'IBM Cloud API key (context-matched near ibm_cloud_api_key or IBMCLOUD_API_KEY)',
        'keywords': ['ibm'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'square_oauth_token': {
        'regex': '\\bsq0csp-[A-Za-z0-9\\-_]{43}\\b',
        'severity': 'CRITICAL',
        'description': 'Square OAuth application secret (sq0csp- prefix, differs from access token sq0atp-)',
        'keywords': ['sq0csp-'],
        'false_positive_hints': ['sq0csp-xxxx', 'example'],
    },
    'basic_auth_url': {
        'regex': 'https?://[^:\\s/\\"\']+:[^@\\s\\"\']{6,}@[a-zA-Z0-9._\\-]+(?::[0-9]+)?',
        'severity': 'HIGH',
        'description': 'HTTP Basic Auth credentials embedded in URL (user:pass@host)',
        'false_positive_hints': ['user:password@', 'admin:admin@', 'root:root@', 'localhost', 'example.com', 'xxxx'],
    },
    'doppler_token_short': {
        'regex': '(?i)(?:DOPPLER[_\\s]?TOKEN|DOPPLER[_\\s]?(?:API[_\\s]?)?KEY)[\\s=:\\"\']{1,5}([a-zA-Z0-9.]{43,})',
        'severity': 'HIGH',
        'description': 'Doppler API token (context-matched near DOPPLER_TOKEN)',
        'keywords': ['doppler'],
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'duffel_api_token': {
        'regex': '\\bduffel_(?:test|live)_[a-zA-Z0-9_\\-=]{43}\\b',
        'severity': 'HIGH',
        'description': 'Duffel travel API token (duffel_test_ or duffel_live_ prefix)',
        'keywords': ['duffel_test_', 'duffel_live_'],
        'entropy_min': 2.0,
        'false_positive_hints': ['duffel_test_xxxx', 'duffel_live_xxxx', 'example'],
    },
    'contentful_delivery_api_token': {
        'regex': '(?i)(?:contentful)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_\\-=]{43})',
        'severity': 'HIGH',
        'description': 'Contentful CMS delivery API token (context-matched near contentful)',
        'keywords': ['contentful'],
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'confluent_access_token': {
        'regex': '(?i)(?:confluent)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{16})',
        'severity': 'HIGH',
        'description': 'Confluent Kafka Cloud API key (context-matched near confluent)',
        'keywords': ['confluent'],
        'entropy_min': 3.0,
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'confluent_secret_key': {
        'regex': '(?i)(?:CONFLUENT[_\\s]?SECRET|CONFLUENT[_\\s]?API[_\\s]?SECRET)[\\s=:\\"\']{1,5}([a-zA-Z0-9+/]{64})',
        'severity': 'CRITICAL',
        'description': 'Confluent Kafka Cloud API secret (context-matched near CONFLUENT_SECRET)',
        'keywords': ['confluent'],
        'entropy_min': 4.0,
        'false_positive_hints': ['xxxx', 'example', 'your_secret'],
    },
    'lark_app_token': {
        'regex': '(?i)(?:LARK[_\\s]?(?:APP[_\\s]?)?(?:SECRET|TOKEN)|FEISHU[_\\s]?(?:APP[_\\s]?)?SECRET)[\\s=:\\"\']{1,5}([a-zA-Z0-9]{32,50})',
        'severity': 'HIGH',
        'description': 'Lark/Feishu (ByteDance) app token or secret (context-matched)',
        'keywords': ['lark', 'feishu'],
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'azure_devops_pat': {
        'regex': '(?i)(?:AZURE[_\\s]?DEVOPS[_\\s]?(?:PERSONAL[_\\s]?ACCESS[_\\s]?)?TOKEN|AZDO[_\\s]?TOKEN)[\\s=:\\"\']{1,5}([a-zA-Z0-9+/]{52}={0,2})',
        'severity': 'CRITICAL',
        'description': 'Azure DevOps personal access token (context-matched, base64 format)',
        'keywords': ['azure devops', 'azdo'],
        'entropy_min': 4.0,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'azure_sas_token': {
        'regex': '(?:sig=[a-zA-Z0-9%+/]{43,}(?:%3D|=){0,2}(?:&|$))',
        'severity': 'HIGH',
        'description': 'Azure Storage SAS token signature (sig= parameter in SAS URL)',
        'keywords': ['sig='],
        'false_positive_hints': ['sig=xxxx', 'sig=example'],
    },
    'azure_function_key': {
        'regex': '(?i)(?:AZURE[_\\s]?FUNCTION[_\\s]?(?:APP[_\\s]?)?(?:KEY|CODE)|FUNCTIONS[_\\s]?KEY)[\\s=:\\"\']{1,5}([a-zA-Z0-9+/\\-_]{40,88}={0,2})',
        'severity': 'HIGH',
        'description': 'Azure Function App key (context-matched near AZURE_FUNCTION_KEY)',
        'keywords': ['azure function'],
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'azure_search_admin_key': {
        'regex': '(?i)(?:AZURE[_\\s]?SEARCH[_\\s]?(?:ADMIN[_\\s]?)?(?:KEY|API[_\\s]?KEY))[\\s=:\\"\']{1,5}([A-Z0-9]{32})',
        'severity': 'HIGH',
        'description': 'Azure AI Search (Cognitive Search) admin key (context-matched)',
        'keywords': ['azure search'],
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'auth0_management_api_token': {
        'regex': '(?i)(?:AUTH0[_\\s]?(?:MANAGEMENT[_\\s]?)?(?:API[_\\s]?)?TOKEN)[\\s=:\\"\']{1,5}(eyJ[a-zA-Z0-9_\\-]{20,}\\.[a-zA-Z0-9_\\-]{20,}\\.[a-zA-Z0-9_\\-]{20,})',
        'severity': 'CRITICAL',
        'description': 'Auth0 Management API token (JWT format, context-matched near AUTH0_TOKEN)',
        'keywords': ['auth0'],
        'entropy_min': 3.0,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'figma_personal_access_token': {
        'regex': '\\bfigd_[a-zA-Z0-9_\\-]{42}\\b',
        'severity': 'HIGH',
        'description': 'Figma personal access token (figd_ prefix)',
        'keywords': ['figd_'],
        'false_positive_hints': ['figd_xxxx', 'example'],
    },
    'figma_oauth_token': {
        'regex': '(?i)(?:FIGMA[_\\s]?(?:ACCESS[_\\s]?)?TOKEN|FIGMA[_\\s]?API[_\\s]?KEY)[\\s=:\\"\']{1,5}([a-zA-Z0-9_\\-]{43,})',
        'severity': 'HIGH',
        'description': 'Figma OAuth access token (context-matched near FIGMA_TOKEN)',
        'keywords': ['figma'],
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'gocardless_api_token': {
        'regex': '(?i)(?:gocardless)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}(live_[a-zA-Z0-9_\\-=]{40})',
        'severity': 'HIGH',
        'description': 'GoCardless payment API token (live_ prefix, context-matched near gocardless)',
        'keywords': ['gocardless'],
        'false_positive_hints': ['live_xxxx', 'example'],
    },
    'intercom_api_key': {
        'regex': '(?i)(?:intercom)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_\\-=]{60})',
        'severity': 'HIGH',
        'description': 'Intercom customer messaging API key (context-matched near intercom)',
        'keywords': ['intercom'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'sumologic_access_id': {
        'regex': '(?i)(?:sumo)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}(su[a-zA-Z0-9]{12})',
        'severity': 'HIGH',
        'description': 'Sumo Logic SIEM access ID (su prefix, context-matched near sumo)',
        'keywords': ['sumo'],
        'entropy_min': 3.0,
        'false_positive_hints': ['suxxxx', 'example'],
    },
    'sumologic_access_token': {
        'regex': '(?i)(?:sumo)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{64})',
        'severity': 'HIGH',
        'description': 'Sumo Logic SIEM access token (64-char, context-matched near sumo)',
        'keywords': ['sumo'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'mattermost_access_token': {
        'regex': '(?i)(?:mattermost)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{26})',
        'severity': 'HIGH',
        'description': 'Mattermost team communication access token (context-matched near mattermost)',
        'keywords': ['mattermost'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'messagebird_api_token': {
        'regex': '(?i)(?:message[_\\-]?bird)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{25})',
        'severity': 'HIGH',
        'description': 'MessageBird SMS/voice API token (context-matched near messagebird)',
        'keywords': ['messagebird'],
        'false_positive_hints': ['xxxx', 'example'],
    },
    'sendbird_access_token': {
        'regex': '(?i)(?:sendbird)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-f0-9]{40})',
        'severity': 'HIGH',
        'description': 'Sendbird in-app chat API token (40-char hex, context-matched near sendbird)',
        'keywords': ['sendbird'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'plaid_api_token': {
        'regex': '(?i)(?:plaid)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        'severity': 'CRITICAL',
        'description': 'Plaid fintech access token (access-{env}-UUID format, context-matched)',
        'keywords': ['plaid'],
        'false_positive_hints': ['access-sandbox-00000000-0000-0000-0000-000000000000', 'example'],
    },
    'lob_api_key': {
        'regex': '(?i)(?:lob)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}((?:live|test)_[a-f0-9]{35})',
        'severity': 'HIGH',
        'description': 'Lob direct mail API key (live_/test_ prefix, context-matched near lob)',
        'keywords': ['lob'],
        'false_positive_hints': ['live_xxxx', 'test_xxxx', 'example'],
    },
    'openrouter_api_key': {
        'regex': '\\bsk-or-v1-[a-zA-Z0-9]{64}\\b',
        'severity': 'CRITICAL',
        'description': 'OpenRouter LLM proxy API key (sk-or-v1- prefix)',
        'keywords': ['sk-or-v1-'],
        'false_positive_hints': ['sk-or-v1-xxxx', 'example'],
    },
    'gitlab_cicd_job_token': {
        'regex': '\\bglcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_\\-]{20}\\b',
        'severity': 'HIGH',
        'description': 'GitLab CI/CD job token (glcbt- prefix)',
        'keywords': ['glcbt-'],
        'false_positive_hints': ['glcbt-xxxx', 'example'],
    },
    'gitlab_deploy_token': {
        'regex': '\\bgldt-[0-9a-zA-Z_\\-]{20}\\b',
        'severity': 'HIGH',
        'description': 'GitLab deploy token (gldt- prefix)',
        'keywords': ['gldt-'],
        'false_positive_hints': ['gldt-xxxx', 'example'],
    },
    'gitlab_runner_token': {
        'regex': '\\bglrt-[0-9a-zA-Z_\\-]{20}\\b',
        'severity': 'HIGH',
        'description': 'GitLab runner authentication token (glrt- prefix)',
        'keywords': ['glrt-'],
        'false_positive_hints': ['glrt-xxxx', 'example'],
    },
    'gitlab_pipeline_trigger': {
        'regex': '\\bglptt-[0-9a-zA-Z_\\-]{20}\\b',
        'severity': 'HIGH',
        'description': 'GitLab pipeline trigger token (glptt- prefix)',
        'keywords': ['glptt-'],
        'false_positive_hints': ['glptt-xxxx', 'example'],
    },
    'gitlab_feed_token': {
        'regex': '\\bglft-[0-9a-zA-Z_\\-]{20}\\b',
        'severity': 'MEDIUM',
        'description': 'GitLab feed token (glft- prefix)',
        'keywords': ['glft-'],
        'false_positive_hints': ['glft-xxxx', 'example'],
    },
    'beamer_api_token': {
        'regex': '(?i)(?:beamer)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}(b_[a-zA-Z0-9_\\-=]{44})',
        'severity': 'MEDIUM',
        'description': 'Beamer product changelog API token (b_ prefix, context-matched near beamer)',
        'keywords': ['beamer'],
        'false_positive_hints': ['b_xxxx', 'example'],
    },
    'infracost_api_token': {
        'regex': '\\bico-[a-zA-Z0-9]{32}\\b',
        'severity': 'MEDIUM',
        'description': 'Infracost cloud cost API token (ico- prefix)',
        'keywords': ['ico-'],
        'false_positive_hints': ['ico-xxxx', 'example'],
    },
    'settlemint_access_token': {
        'regex': '\\bsm_(?:aat|pat|sat)_[a-zA-Z0-9]{16}\\b',
        'severity': 'HIGH',
        'description': 'SettleMint blockchain platform access token (sm_aat/pat/sat_ prefix)',
        'keywords': ['sm_aat_', 'sm_pat_', 'sm_sat_'],
        'false_positive_hints': ['sm_aat_xxxx', 'example'],
    },
    'sidekiq_secret': {
        'regex': '(?i)(?:BUNDLE_(?:ENTERPRISE|GEMS)__CONTRIBSYS__COM)[\\s=:\\"\']{1,5}([a-f0-9]{8}:[a-f0-9]{8})',
        'severity': 'HIGH',
        'description': 'Sidekiq Pro/Enterprise gem server credentials (BUNDLE_CONTRIBSYS format)',
        'keywords': ['contribsys'],
        'false_positive_hints': ['00000000:00000000', 'example'],
    },
    'slack_config_access_token': {
        'regex': '(?i)\\bxoxe\\.xox[bp]-\\d-[A-Z0-9]{163,166}\\b',
        'severity': 'HIGH',
        'description': 'Slack configuration access token (xoxe.xoxb- or xoxe.xoxp- prefix)',
        'keywords': ['xoxe.'],
        'false_positive_hints': ['xoxe.xoxb-xxxx', 'example'],
    },
    'slack_legacy_token': {
        'regex': '\\bxox[os]-\\d+-\\d+-\\d+-[a-fA-F0-9]+\\b',
        'severity': 'HIGH',
        'description': 'Slack legacy user/workspace token (xoxo- or xoxs- prefix)',
        'keywords': ['xoxo-', 'xoxs-'],
        'false_positive_hints': ['xoxo-xxxx', 'xoxs-xxxx', 'example'],
    },
    'codecov_access_token': {
        'regex': '(?i)(?:codecov)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{32})',
        'severity': 'HIGH',
        'description': 'Codecov code coverage upload token (context-matched near codecov)',
        'keywords': ['codecov'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_token'],
    },
    'gitter_access_token': {
        'regex': '(?i)(?:gitter)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_]{40})',
        'severity': 'MEDIUM',
        'description': 'Gitter chat access token (context-matched near gitter)',
        'keywords': ['gitter'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'nytimes_api_key': {
        'regex': '(?i)(?:nytimes|new-york-times|newyorktimes)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_\\-=]{32})',
        'severity': 'LOW',
        'description': 'NY Times API key (context-matched, low severity — public API)',
        'keywords': ['nytimes'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'finnhub_access_token': {
        'regex': '(?i)(?:finnhub)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_]{20})',
        'severity': 'MEDIUM',
        'description': 'Finnhub stock market data API token (context-matched near finnhub)',
        'keywords': ['finnhub'],
        'entropy_min': 3.0,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'freshbooks_access_token': {
        'regex': '(?i)(?:freshbooks)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{64})',
        'severity': 'HIGH',
        'description': 'FreshBooks invoicing OAuth access token (64-char, context-matched)',
        'keywords': ['freshbooks'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'etsy_access_token': {
        'regex': '(?i)(?:etsy)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{24})',
        'severity': 'HIGH',
        'description': 'Etsy marketplace OAuth access token (context-matched near etsy)',
        'keywords': ['etsy'],
        'entropy_min': 3.0,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'flickr_access_token': {
        'regex': '(?i)(?:flickr)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{32})',
        'severity': 'MEDIUM',
        'description': 'Flickr photo sharing OAuth access token (context-matched near flickr)',
        'keywords': ['flickr'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'fastly_api_token': {
        'regex': '(?i)(?:fastly)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9_\\-=]{32})',
        'severity': 'HIGH',
        'description': 'Fastly CDN API token (context-matched near fastly)',
        'keywords': ['fastly'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'finicity_api_token': {
        'regex': '(?i)(?:finicity)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-f0-9]{32})',
        'severity': 'HIGH',
        'description': 'Finicity financial data API token (context-matched near finicity)',
        'keywords': ['finicity'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'droneci_access_token': {
        'regex': '(?i)(?:droneci|drone[_\\-]ci)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{32})',
        'severity': 'HIGH',
        'description': 'Drone CI/CD access token (context-matched near droneci)',
        'keywords': ['droneci', 'drone_ci'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'dropbox_access_token': {
        'regex': '(?i)(?:dropbox)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{15})',
        'severity': 'HIGH',
        'description': 'Dropbox file storage OAuth access token (context-matched near dropbox)',
        'keywords': ['dropbox'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'mailgun_signing_key': {
        'regex': '(?i)(?:mailgun)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})',
        'severity': 'HIGH',
        'description': 'Mailgun webhook signing key (structured hex-hex-hex format, context-matched)',
        'keywords': ['mailgun'],
        'false_positive_hints': ['00000000000000000000000000000000-00000000-00000000', 'example'],
    },
    'kubernetes_secret_yaml': {
        'regex': '(?:kind:\\s*Secret[\\s\\S]{0,200}data:\\s*\\n(?:[ \\t]+[a-zA-Z0-9_\\-]+:\\s*[a-zA-Z0-9+/]{20,}={0,2}\\n)+)',
        'severity': 'HIGH',
        'description': 'Kubernetes Secret manifest with base64-encoded data values',
        'keywords': ['kind: secret', 'kind:secret'],
        'false_positive_hints': ['example', 'test', 'placeholder'],
    },
    'looker_client_id': {
        'regex': '(?i)(?:looker)(?:[\\s\\w.\\-]{0,20})[\\s=:\\"\']{1,5}([a-zA-Z0-9]{20})',
        'severity': 'HIGH',
        'description': 'Looker Business Intelligence client ID/secret (context-matched near looker)',
        'keywords': ['looker'],
        'entropy_min': 3.0,
        'false_positive_hints': ['xxxx', 'example'],
    },
    'tailscale_api_key': {
        'regex': '\\btskey-(?:api|client|user)-[a-zA-Z0-9_\\-]{25,50}\\b',
        'severity': 'HIGH',
        'description': 'Tailscale VPN mesh network API key (tskey- prefix)',
        'keywords': ['tskey-'],
        'false_positive_hints': ['tskey-api-xxxx', 'example'],
    },
    'segment_write_key': {
        'regex': '(?i)(?:SEGMENT[_\\s]?(?:WRITE[_\\s]?)?KEY|ANALYTICS[_\\s]?WRITE[_\\s]?KEY)[\\s=:\\"\']{1,5}([a-zA-Z0-9]{32,50})',
        'severity': 'HIGH',
        'description': 'Segment analytics write key (context-matched near SEGMENT_WRITE_KEY)',
        'keywords': ['segment'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'runpod_api_key': {
        'regex': '(?i)(?:RUNPOD[_\\s]?API[_\\s]?KEY)[\\s=:\\"\']{1,5}([a-zA-Z0-9]{32,48})',
        'severity': 'HIGH',
        'description': 'RunPod GPU cloud API key (context-matched near RUNPOD_API_KEY)',
        'keywords': ['runpod'],
        'entropy_min': 3.5,
        'false_positive_hints': ['xxxx', 'example', 'your_key'],
    },
    'workato_api_token': {
        'regex': '(?i)(?:WORKATO[_\\s]?(?:API[_\\s]?)?TOKEN)[\\s=:\\"\']{1,5}([a-zA-Z0-9]{32,64})',
        'severity': 'HIGH',
        'description': 'Workato iPaaS automation API token (context-matched)',
        'keywords': ['workato'],
        'false_positive_hints': ['xxxx', 'example'],
    },
    'generic_high_entropy_hex': {
        'regex': '(?i)(?:api[_\\s]?key|access[_\\s]?key|secret|password|token|passwd|private[_\\s]?key|credential)\\s*[=:]\\s*[\'\\"]?([0-9a-f]{32,64})[\'\\"]?',
        'severity': 'MEDIUM',
        'description': 'High-entropy hex secret near key/password/token keyword (entropy >= 3.0)',
        'entropy_min': 3.0,
        'false_positive_hints': ['0000000000000000', 'ffffffffffffffff', 'deadbeef', 'example', 'xxxx', 'test'],
    },

    # ── CAPTCHA solvers ───────────────────────────────────────────────────────
    "capmonster_key": {
        "regex": r"(?i)(?:capmonster|cap_monster)(?:[\s\-_]*(?:api|key|token|secret|client))?[\s]*[=:\"'`]+\s*([a-f0-9]{32})",
        "severity": "HIGH",
        "description": "CapMonster cloud API key (32-char hex)",
        "false_positive_hints": ["example", "test", "00000000", "ffffffff", "aaaaaa"],
    },
    "anticaptcha_key": {
        "regex": r"(?i)(?:anti.?captcha|anticaptcha)(?:[\s\-_]*(?:api|key|token))?[\s]*[=:\"'`]+\s*([a-f0-9]{32})",
        "severity": "HIGH",
        "description": "Anti-Captcha API key (32-char hex)",
        "false_positive_hints": ["example", "test", "0000000000"],
    },
    "twocaptcha_key": {
        "regex": r"(?i)(?:2captcha|two_?captcha|rucaptcha)(?:[\s\-_]*(?:api|key|token))?[\s]*[=:\"'`]+\s*([a-f0-9]{32})",
        "severity": "HIGH",
        "description": "2Captcha / RuCaptcha API key",
        "false_positive_hints": ["example", "test"],
    },
    "capsolver_key": {
        "regex": r"(?i)(?:capsolver|cap_solver)(?:[\s\-_]*(?:api|key|token))?[\s]*[=:\"'`]+\s*(CAP-[a-zA-Z0-9]{32,})",
        "severity": "HIGH",
        "description": "CapSolver API key (CAP- prefix)",
        "false_positive_hints": ["example"],
    },
    "deathbycaptcha_key": {
        "regex": r"(?i)(?:deathbycaptcha|dbc)(?:[\s\-_]*(?:api|key|pass|password|username))?[\s]*[=:\"'`]+\s*([a-zA-Z0-9]{8,40})",
        "severity": "MEDIUM",
        "description": "DeathByCaptcha credentials",
        "false_positive_hints": ["example", "test"],
    },
    # VPS / SSH / Infrastructure
    "hetzner_token": {
        "regex": r"(?i)hetzner[_\-](?:api[_\-])?token[\s]*[=:\"'`]+\s*([A-Za-z0-9]{64})",
        "severity": "CRITICAL",
        "description": "Hetzner Cloud API token (64 chars)",
        "false_positive_hints": ["example", "test", "xxx"],
    },
    "vultr_api_key": {
        "regex": r"(?i)vultr[_\-](?:api[_\-])?key[\s]*[=:\"'`]+\s*([A-Z0-9]{36})",
        "severity": "CRITICAL",
        "description": "Vultr API key (36 uppercase chars)",
        "false_positive_hints": ["example"],
    },
    "linode_token": {
        "regex": r"(?i)(?:linode|akamai)[_\-](?:api[_\-])?token[\s]*[=:\"'`]+\s*([a-f0-9]{64})",
        "severity": "CRITICAL",
        "description": "Linode/Akamai Cloud API token",
        "false_positive_hints": ["example", "test"],
    },
    "scaleway_secret": {
        "regex": r"(?i)scw[_\-]secret[_\-]key[\s]*[=:\"'`]+\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
        "severity": "CRITICAL",
        "description": "Scaleway secret key (UUID format)",
        "false_positive_hints": [],
    },
    "wireguard_private_key": {
        "regex": r"PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)",
        "severity": "CRITICAL",
        "description": "WireGuard VPN private key (base64 44 chars)",
        "false_positive_hints": ["example", "placeholder", "AAAA"],
    },
    "ovh_app_secret": {
        "regex": r"(?i)OVH_APPLICATION_SECRET[\s]*[=:\"'`]+\s*([A-Za-z0-9]{32})",
        "severity": "HIGH",
        "description": "OVH cloud application secret",
        "false_positive_hints": ["example"],
    },
    "ssh_password_env": {
        "regex": r"(?i)(?:SSH_PASS(?:WORD)?|ROOT_PASSWORD|SSHPASS)[\s]*[=:\"'`]+\s*([^\s\"'`]{8,40})",
        "severity": "HIGH",
        "description": "SSH/root password in env file",
        "false_positive_hints": ["password", "changeme", "example", "your_", "xxxx", "1234", "passwd"],
    },
    "ansible_vault_pass": {
        "regex": r"(?i)(?:ANSIBLE_VAULT_PASSWORD|vault[_\-]pass(?:word)?)[\s]*[=:\"'`]+\s*([^\s\"'`]{6,50})",
        "severity": "HIGH",
        "description": "Ansible vault password",
        "false_positive_hints": ["example", "changeme"],
    },
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# Pre-compile all regexes once at import time
_COMPILED: dict[str, re.Pattern] = {
    name: re.compile(pat["regex"], re.MULTILINE)
    for name, pat in PATTERNS.items()
}

# For the generic high-entropy pattern, compile separately
_ENV_LINE_RE = re.compile(
    r"^([A-Z][A-Z0-9_]{3,40})\s*=\s*['\"]?([a-zA-Z0-9/+_\-\.]{30,})['\"]?\s*$",
    re.MULTILINE,
)

_GENERIC_FP_HINTS = PATTERNS["generic_high_entropy_env"]["false_positive_hints"]

# Extensions that should trigger .env-style generic scanning
_ENV_EXTENSIONS = {".env", ".env.local", ".env.production", ".env.development", ".env.staging", ".envrc"}


def _is_fp(matched_text: str, hints: list[str]) -> bool:
    lower = matched_text.lower()
    return any(h.lower() in lower for h in hints)


def scan_text(text: str, filename: str = "") -> list[dict]:
    """
    Scan text for leaked secrets.

    Returns a list of dicts:
      {
        "pattern_name": str,
        "matched": str,          # the full matched string
        "severity": str,         # CRITICAL / HIGH / MEDIUM
        "line_no": int,
        "description": str,
        "is_fp_hint": bool,      # True if likely a false positive
      }
    """
    results: list[dict] = []
    lines = text.splitlines()

    for name, compiled in _COMPILED.items():
        pat = PATTERNS[name]
        for m in compiled.finditer(text):
            matched = m.group(0)
            # Compute line number (1-indexed)
            line_no = text[:m.start()].count("\n") + 1
            fp = _is_fp(matched, pat["false_positive_hints"])
            results.append({
                "pattern_name": name,
                "matched": matched,
                "severity": pat["severity"],
                "line_no": line_no,
                "description": pat["description"],
                "is_fp_hint": fp,
            })

    # Generic high-entropy .env-style scan
    ext = ""
    if filename:
        import os
        _, ext = os.path.splitext(filename.lower())

    is_env_file = ext in _ENV_EXTENSIONS or filename.lower().endswith(".env")

    for m in _ENV_LINE_RE.finditer(text):
        key_name = m.group(1)
        value = m.group(2)
        if entropy(value) < 4.5:
            continue
        if len(value) < 30:
            continue
        matched = m.group(0).strip()
        fp = _is_fp(value, _GENERIC_FP_HINTS)
        line_no = text[:m.start()].count("\n") + 1
        results.append({
            "pattern_name": "generic_high_entropy_env",
            "matched": matched,
            "severity": "MEDIUM",
            "line_no": line_no,
            "description": f"High-entropy value (entropy={entropy(value):.2f}) for key '{key_name}'",
            "is_fp_hint": fp,
        })

    # Deduplicate: if both a specific pattern and generic_high_entropy_env matched
    # the same line, prefer the specific one.
    seen_line_specific: set[int] = set()
    for r in results:
        if r["pattern_name"] != "generic_high_entropy_env":
            seen_line_specific.add(r["line_no"])

    filtered = [
        r for r in results
        if not (r["pattern_name"] == "generic_high_entropy_env" and r["line_no"] in seen_line_specific)
    ]

    # Sort by line number
    filtered.sort(key=lambda x: x["line_no"])
    return filtered


# ---------------------------------------------------------------------------
# GitHub dork queries (≥40)
# ---------------------------------------------------------------------------

GITHUB_DORK_QUERIES: list[dict] = [
    # ── OpenAI ──────────────────────────────────────────────────────────────
    {
        "q": "sk-proj- filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "openai",
        "description": "OpenAI project-scoped API keys in .env files",
    },
    {
        "q": "OPENAI_API_KEY= filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "openai",
        "description": "OpenAI API key assignment in .env files",
    },
    {
        "q": "OPENAI_API_KEY in:file filename:.env.local",
        "kind": "code",
        "qualifiers": {},
        "category": "openai",
        "description": "OpenAI API key in .env.local",
    },
    {
        "q": '"sk-proj-" in:file extension:py',
        "kind": "code",
        "qualifiers": {},
        "category": "openai",
        "description": "OpenAI project key hardcoded in Python source",
    },
    {
        "q": 'OPENAI_API_KEY filename:config.py',
        "kind": "code",
        "qualifiers": {},
        "category": "openai",
        "description": "OpenAI key in Python config module",
    },
    {
        "q": 'OPENAI_API_KEY filename:settings.py',
        "kind": "code",
        "qualifiers": {},
        "category": "openai",
        "description": "OpenAI key in Django/Flask settings",
    },
    # ── Anthropic ────────────────────────────────────────────────────────────
    {
        "q": "ANTHROPIC_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "anthropic",
        "description": "Anthropic API key in .env files",
    },
    {
        "q": '"sk-ant-" in:file extension:py',
        "kind": "code",
        "qualifiers": {},
        "category": "anthropic",
        "description": "Anthropic key prefix hardcoded in Python",
    },
    {
        "q": "ANTHROPIC_API_KEY filename:config.py",
        "kind": "code",
        "qualifiers": {},
        "category": "anthropic",
        "description": "Anthropic key in Python config",
    },
    # ── HuggingFace ──────────────────────────────────────────────────────────
    {
        "q": '"hf_" in:file filename:config',
        "kind": "code",
        "qualifiers": {},
        "category": "huggingface",
        "description": "HuggingFace token prefix in config files",
    },
    {
        "q": "HUGGING_FACE_HUB_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "huggingface",
        "description": "HuggingFace hub token in .env",
    },
    {
        "q": "HF_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "huggingface",
        "description": "HuggingFace short-form token in .env",
    },
    # ── GitHub ───────────────────────────────────────────────────────────────
    {
        "q": "GITHUB_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "github",
        "description": "GitHub personal access token in .env",
    },
    {
        "q": '"ghp_" in:file extension:env',
        "kind": "code",
        "qualifiers": {},
        "category": "github",
        "description": "GitHub classic PAT prefix in .env files",
    },
    {
        "q": "github_pat_ in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "github",
        "description": "GitHub fine-grained PAT in .env",
    },
    # ── AWS ──────────────────────────────────────────────────────────────────
    {
        "q": "AWS_ACCESS_KEY_ID in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "aws",
        "description": "AWS Access Key ID in .env",
    },
    {
        "q": "AWS_SECRET_ACCESS_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "aws",
        "description": "AWS Secret Key in .env",
    },
    {
        "q": '"AKIA" in:file extension:json path:config',
        "kind": "code",
        "qualifiers": {},
        "category": "aws",
        "description": "AWS Access Key ID prefix in JSON config",
    },
    {
        "q": "AWS_ACCESS_KEY_ID filename:credentials",
        "kind": "code",
        "qualifiers": {},
        "category": "aws",
        "description": "AWS credentials file with access key",
    },
    # ── Google ───────────────────────────────────────────────────────────────
    {
        "q": "GOOGLE_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "google",
        "description": "Google API key in .env",
    },
    {
        "q": '"AIza" in:file extension:py',
        "kind": "code",
        "qualifiers": {},
        "category": "google",
        "description": "Google/Gemini API key hardcoded in Python",
    },
    {
        "q": "GEMINI_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "google",
        "description": "Gemini API key in .env files",
    },
    {
        "q": "GOOGLE_APPLICATION_CREDENTIALS in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "google",
        "description": "Google service account credentials path in .env",
    },
    # ── Stripe ───────────────────────────────────────────────────────────────
    {
        "q": "STRIPE_SECRET_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "stripe",
        "description": "Stripe secret key in .env",
    },
    {
        "q": '"sk_live_" in:file extension:py',
        "kind": "code",
        "qualifiers": {},
        "category": "stripe",
        "description": "Stripe live secret key hardcoded in Python",
    },
    # ── Groq ─────────────────────────────────────────────────────────────────
    {
        "q": "GROQ_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "groq",
        "description": "Groq API key in .env files",
    },
    {
        "q": '"gsk_" in:file extension:py',
        "kind": "code",
        "qualifiers": {},
        "category": "groq",
        "description": "Groq API key prefix hardcoded in Python",
    },
    # ── Mistral ───────────────────────────────────────────────────────────────
    {
        "q": "MISTRAL_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "mistral",
        "description": "Mistral API key in .env files",
    },
    # ── Slack ─────────────────────────────────────────────────────────────────
    {
        "q": "SLACK_BOT_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "slack",
        "description": "Slack bot token in .env",
    },
    {
        "q": '"xoxb-" in:file extension:py',
        "kind": "code",
        "qualifiers": {},
        "category": "slack",
        "description": "Slack bot token prefix hardcoded in Python",
    },
    {
        "q": "hooks.slack.com/services in:file",
        "kind": "code",
        "qualifiers": {},
        "category": "slack",
        "description": "Slack incoming webhook URL in code",
    },
    # ── Discord ───────────────────────────────────────────────────────────────
    {
        "q": "DISCORD_BOT_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "discord",
        "description": "Discord bot token in .env",
    },
    {
        "q": "discord.com/api/webhooks in:file",
        "kind": "code",
        "qualifiers": {},
        "category": "discord",
        "description": "Discord webhook URL exposed in code",
    },
    # ── Telegram ──────────────────────────────────────────────────────────────
    {
        "q": "TELEGRAM_BOT_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "telegram",
        "description": "Telegram bot token in .env",
    },
    # ── Twilio ────────────────────────────────────────────────────────────────
    {
        "q": "TWILIO_AUTH_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "twilio",
        "description": "Twilio auth token in .env",
    },
    # ── SendGrid ──────────────────────────────────────────────────────────────
    {
        "q": "SENDGRID_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "sendgrid",
        "description": "SendGrid API key in .env",
    },
    {
        "q": '"SG." in:file extension:py',
        "kind": "code",
        "qualifiers": {},
        "category": "sendgrid",
        "description": "SendGrid API key hardcoded in Python",
    },
    # ── Database URLs ─────────────────────────────────────────────────────────
    {
        "q": 'DATABASE_URL postgresql:// in:file filename:.env',
        "kind": "code",
        "qualifiers": {},
        "category": "database",
        "description": "PostgreSQL DATABASE_URL with credentials in .env",
    },
    {
        "q": 'mongodb+srv:// in:file filename:.env',
        "kind": "code",
        "qualifiers": {},
        "category": "database",
        "description": "MongoDB Atlas connection string in .env",
    },
    {
        "q": 'REDIS_URL redis:// in:file filename:.env',
        "kind": "code",
        "qualifiers": {},
        "category": "database",
        "description": "Redis URL with auth in .env",
    },
    # ── Replicate ─────────────────────────────────────────────────────────────
    {
        "q": "REPLICATE_API_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "replicate",
        "description": "Replicate API token in .env",
    },
    # ── xAI ───────────────────────────────────────────────────────────────────
    {
        "q": "XAI_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "xai",
        "description": "xAI (Grok) API key in .env files",
    },
    # ── Secrets YAML ──────────────────────────────────────────────────────────
    {
        "q": "api_key filename:secrets.yaml",
        "kind": "code",
        "qualifiers": {},
        "category": "generic",
        "description": "API key field in secrets.yaml",
    },
    {
        "q": "api_key filename:secrets.yml",
        "kind": "code",
        "qualifiers": {},
        "category": "generic",
        "description": "API key field in secrets.yml",
    },
    # ── Generic .env catches ──────────────────────────────────────────────────
    {
        "q": "SECRET_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "generic",
        "description": "Generic SECRET_KEY in .env",
    },
    {
        "q": "API_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "generic",
        "description": "Generic API_SECRET in .env",
    },
    {
        "q": "PRIVATE_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "generic",
        "description": "Generic PRIVATE_KEY in .env",
    },
    {
        "q": "BEGIN RSA PRIVATE KEY in:file",
        "kind": "code",
        "qualifiers": {},
        "category": "ssh",
        "description": "RSA private key committed to repository",
    },
    {
        "q": "BEGIN OPENSSH PRIVATE KEY in:file",
        "kind": "code",
        "qualifiers": {},
        "category": "ssh",
        "description": "OpenSSH private key committed to repository",
    },
    # ── Supabase ──────────────────────────────────────────────────────────────
    {
        "q": "SUPABASE_SERVICE_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "supabase",
        "description": "Supabase service role key in .env",
    },
    # ── Vercel / Netlify ──────────────────────────────────────────────────────
    {
        "q": "VERCEL_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "vercel",
        "description": "Vercel API token in .env",
    },
    {
        "q": "NETLIFY_ACCESS_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "netlify",
        "description": "Netlify access token in .env",
    },
    # ── Cloudflare ────────────────────────────────────────────────────────────
    {
        "q": "CLOUDFLARE_API_TOKEN in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "cloudflare",
        "description": "Cloudflare API token in .env",
    },
    # ── Notion ────────────────────────────────────────────────────────────────
    {
        "q": "NOTION_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "notion",
        "description": "Notion integration token in .env",
    },
    # ── Cohere / Together ─────────────────────────────────────────────────────
    {
        "q": "COHERE_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "cohere",
        "description": "Cohere API key in .env",
    },
    {
        "q": "TOGETHER_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "together",
        "description": "Together AI API key in .env",
    },
    # ── ElevenLabs ────────────────────────────────────────────────────────────
    {
        "q": "ELEVENLABS_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "elevenlabs",
        "description": "ElevenLabs API key in .env",
    },
    # ── Pinecone ──────────────────────────────────────────────────────────────
    {
        "q": "PINECONE_API_KEY in:file filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "pinecone",
        "description": "Pinecone API key in .env",
    },

    # ── CRYPTO / BLOCKCHAIN dorks ─────────────────────────────────────────────
    {
        "q": "ETH_PRIVATE_KEY= filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "eth_private_key",
        "description": "Ethereum private key in .env",
    },
    {
        "q": "MNEMONIC= filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "mnemonic",
        "description": "BIP39 mnemonic seed phrase in .env",
    },
    {
        "q": "seed phrase filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "mnemonic",
        "description": "Seed phrase literal in .env",
    },
    {
        "q": "INFURA_PROJECT_ID filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "infura",
        "description": "Infura project ID in .env",
    },
    {
        "q": "ALCHEMY_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "alchemy",
        "description": "Alchemy API key in .env",
    },
    {
        "q": "BINANCE_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "binance",
        "description": "Binance API key in .env",
    },
    {
        "q": "COINBASE_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "coinbase",
        "description": "Coinbase API key in .env",
    },
    {
        "q": "web3 private_key 0x filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "eth_private_key",
        "description": "Web3 private key with 0x prefix in .env",
    },
    {
        "q": "wallet privateKey mnemonic filename:config.js",
        "kind": "code",
        "qualifiers": {},
        "category": "mnemonic",
        "description": "Wallet mnemonic in config.js",
    },
    {
        "q": "xprv filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "xprv_key",
        "description": "BIP32 extended private key in .env",
    },
    {
        "q": "KRAKEN_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "kraken",
        "description": "Kraken API key in .env",
    },

    # ── CLOUD dorks ───────────────────────────────────────────────────────────
    {
        "q": "AZURE_CLIENT_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "azure",
        "description": "Azure AD client secret in .env",
    },
    {
        "q": "DefaultEndpointsProtocol AccountKey filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "azure_storage",
        "description": "Azure Storage connection string in .env",
    },
    {
        "q": "DIGITALOCEAN_TOKEN dop_v1 filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "digitalocean",
        "description": "DigitalOcean personal access token (dop_v1_) in .env",
    },
    {
        "q": "CLOUDFLARE_API_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "cloudflare",
        "description": "Cloudflare API token in .env",
    },
    {
        "q": "FIREBASE_PRIVATE_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "firebase",
        "description": "Firebase service account private key in .env",
    },
    {
        "q": "DATABASE_URL postgres:// filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "postgres",
        "description": "PostgreSQL DATABASE_URL with postgres:// scheme in .env",
    },
    {
        "q": "mongodb+srv:// password filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "mongodb",
        "description": "MongoDB Atlas SRV connection string with password in .env",
    },
    {
        "q": "SUPABASE_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "supabase",
        "description": "Supabase API key in .env",
    },

    # ── SSH / CERTIFICATE dorks ───────────────────────────────────────────────
    {
        "q": "BEGIN RSA PRIVATE KEY filename:.pem",
        "kind": "code",
        "qualifiers": {},
        "category": "ssh_rsa",
        "description": "RSA private key committed in .pem file",
    },
    {
        "q": "BEGIN OPENSSH PRIVATE KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "ssh_openssh",
        "description": "OpenSSH private key stored in .env file",
    },
    {
        "q": "BEGIN EC PRIVATE KEY",
        "kind": "code",
        "qualifiers": {"extension": "pem"},
        "category": "ssl_private",
        "description": "EC private key in .pem files",
    },

    # ── SOCIAL / PAYMENT dorks ────────────────────────────────────────────────
    {
        "q": "TWITTER_BEARER_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "twitter",
        "description": "Twitter/X Bearer Token in .env",
    },
    {
        "q": "FACEBOOK_ACCESS_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "facebook",
        "description": "Facebook access token in .env",
    },
    {
        "q": "STRIPE_SECRET_KEY sk_live filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "stripe",
        "description": "Stripe live secret key in .env",
    },
    {
        "q": "SENDGRID_API_KEY SG. filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "sendgrid",
        "description": "SendGrid API key with SG. prefix in .env",
    },
    {
        "q": "npm_token filename:.npmrc",
        "kind": "code",
        "qualifiers": {},
        "category": "npm",
        "description": "NPM token stored in .npmrc",
    },
    {
        "q": "PYPI_TOKEN pypi- filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "pypi",
        "description": "PyPI upload token in .env",
    },
    {
        "q": "glpat- GITLAB_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "gitlab",
        "description": "GitLab personal access token in .env",
    },
    {
        "q": "VAULT_TOKEN hvs. filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "vault",
        "description": "HashiCorp Vault service token in .env",
    },
    {
        "q": "JWT_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "jwt_secret",
        "description": "JWT signing secret in .env",
    },
    {
        "q": "SECRET_KEY django settings.py",
        "kind": "code",
        "qualifiers": {},
        "category": "django_secret",
        "description": "Django SECRET_KEY in settings.py",
    },
    {
        "q": "TWILIO_AUTH_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "twilio",
        "description": "Twilio Auth Token in .env (extended dork)",
    },
    {
        "q": "BYBIT_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "bybit",
        "description": "Bybit exchange API key in .env",
    },
    {
        "q": "KUCOIN_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "kucoin",
        "description": "KuCoin exchange API key in .env",
    },
    {
        "q": "OKX_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "okx",
        "description": "OKX exchange API key in .env",
    },
    {
        "q": "MORALIS_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "moralis",
        "description": "Moralis Web3 API key in .env",
    },
    {
        "q": "ETHERSCAN_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "etherscan",
        "description": "Etherscan API key in .env",
    },
    {
        "q": "SOLANA_PRIVATE_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "solana",
        "description": "Solana private key in .env",
    },
    {
        "q": "rzp_live_ filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "razorpay",
        "description": "Razorpay live API key in .env",
    },
    {
        "q": "sq0atp- filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "square",
        "description": "Square access token in .env",
    },
    {
        "q": "PAYPAL_CLIENT_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "paypal",
        "description": "PayPal client secret in .env",
    },
    {
        "q": "BRAINTREE_PRIVATE_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "braintree",
        "description": "Braintree private key in .env",
    },
    {
        "q": "LINODE_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "linode",
        "description": "Linode API token in .env",
    },
    {
        "q": "VULTR_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "vultr",
        "description": "Vultr API key in .env",
    },
    {
        "q": "HETZNER_API_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "hetzner",
        "description": "Hetzner Cloud API token in .env",
    },
    {
        "q": "FLY_API_TOKEN fo1_ filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "fly",
        "description": "Fly.io API token in .env",
    },
    {
        "q": "RENDER_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "render",
        "description": "Render.com API key in .env",
    },
    {
        "q": "RAILWAY_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "railway",
        "description": "Railway deployment token in .env",
    },
    {
        "q": "SPOTIFY_CLIENT_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "spotify",
        "description": "Spotify OAuth client secret in .env",
    },
    {
        "q": "LINKEDIN_CLIENT_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "linkedin",
        "description": "LinkedIn OAuth client secret in .env",
    },
    {
        "q": "glpat- in:file extension:env",
        "kind": "code",
        "qualifiers": {},
        "category": "gitlab",
        "description": "GitLab PAT prefix in .env extension files",
    },
    {
        "q": "hvs. VAULT_TOKEN in:file",
        "kind": "code",
        "qualifiers": {},
        "category": "vault",
        "description": "HashiCorp Vault service token in code",
    },
    {
        "q": "NGROK_AUTH_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "ngrok",
        "description": "ngrok authentication token in .env",
    },
    {
        "q": "PUSHER_APP_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "pusher",
        "description": "Pusher app secret in .env",
    },
    {
        "q": "MAPBOX_TOKEN filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "mapbox",
        "description": "Mapbox access token in .env",
    },
    {
        "q": "ENCRYPTION_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "encryption",
        "description": "Generic encryption key in .env",
    },
    {
        "q": "AES_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "encryption",
        "description": "AES encryption key in .env",
    },
    {
        "q": "MAILGUN_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "mailgun",
        "description": "Mailgun API key in .env (extended dork)",
    },
    {
        "q": "PADDLE_API_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "paddle",
        "description": "Paddle billing API key in .env",
    },
    {
        "q": "wss://mainnet.infura.io/v3/ filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "infura",
        "description": "Infura WebSocket endpoint with key embedded in .env",
    },
    {
        "q": "BEGIN PGP PRIVATE KEY BLOCK in:file",
        "kind": "code",
        "qualifiers": {},
        "category": "pgp",
        "description": "PGP private key block committed to repository",
    },
    {
        "q": "DO_SPACES_KEY filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "digitalocean_spaces",
        "description": "DigitalOcean Spaces access key in .env",
    },
    {
        "q": "AZURE_CLIENT_ID AZURE_CLIENT_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "azure",
        "description": "Azure service principal credentials pair in .env",
    },
    {
        "q": "GITHUB_CLIENT_SECRET filename:.env",
        "kind": "code",
        "qualifiers": {},
        "category": "github_oauth",
        "description": "GitHub OAuth app client secret in .env",
    },

    # ── Shopify dorks ─────────────────────────────────────────────────────────
    {"q": "shpat_ filename:.env", "kind": "code", "category": "shopify", "qualifiers": {}},
    {"q": "SHOPIFY_ADMIN_ACCESS_TOKEN filename:.env", "kind": "code", "category": "shopify", "qualifiers": {}},
    {"q": "shppa_ filename:.env", "kind": "code", "category": "shopify", "qualifiers": {}},
    {"q": "SHOPIFY_API_SECRET_KEY filename:.env", "kind": "code", "category": "shopify", "qualifiers": {}},

    # ── HubSpot dorks ─────────────────────────────────────────────────────────
    {"q": "HUBSPOT_API_KEY pat- filename:.env", "kind": "code", "category": "hubspot", "qualifiers": {}},
    {"q": "HUBSPOT_PRIVATE_APP_TOKEN filename:.env", "kind": "code", "category": "hubspot", "qualifiers": {}},

    # ── Okta dorks ────────────────────────────────────────────────────────────
    {"q": "OKTA_API_TOKEN ssws filename:.env", "kind": "code", "category": "okta", "qualifiers": {}},
    {"q": "OKTA_TOKEN filename:.env", "kind": "code", "category": "okta", "qualifiers": {}},

    # ── Databricks dorks ──────────────────────────────────────────────────────
    {"q": "DATABRICKS_TOKEN dapi filename:.env", "kind": "code", "category": "databricks", "qualifiers": {}},
    {"q": "DATABRICKS_HOST DATABRICKS_TOKEN filename:.env", "kind": "code", "category": "databricks", "qualifiers": {}},

    # ── Postman dorks ─────────────────────────────────────────────────────────
    {"q": "POSTMAN_API_KEY PMAK- filename:.env", "kind": "code", "category": "postman", "qualifiers": {}},

    # ── New Relic dorks ───────────────────────────────────────────────────────
    {"q": "NEW_RELIC_API_KEY NRAK- filename:.env", "kind": "code", "category": "new_relic", "qualifiers": {}},
    {"q": "NEW_RELIC_LICENSE_KEY filename:.env", "kind": "code", "category": "new_relic", "qualifiers": {}},

    # ── Grafana dorks ─────────────────────────────────────────────────────────
    {"q": "GRAFANA_API_KEY filename:.env", "kind": "code", "category": "grafana", "qualifiers": {}},
    {"q": "GRAFANA_CLOUD_TOKEN glc_ filename:.env", "kind": "code", "category": "grafana", "qualifiers": {}},

    # ── Datadog dorks ─────────────────────────────────────────────────────────
    {"q": "DD_API_KEY filename:.env", "kind": "code", "category": "datadog", "qualifiers": {}},
    {"q": "DATADOG_API_KEY filename:.env.example", "kind": "code", "category": "datadog", "qualifiers": {}},

    # ── Linear dorks ──────────────────────────────────────────────────────────
    {"q": "LINEAR_API_KEY lin_api_ filename:.env", "kind": "code", "category": "linear", "qualifiers": {}},

    # ── Notion dorks ──────────────────────────────────────────────────────────
    {"q": "NOTION_TOKEN secret_ filename:.env", "kind": "code", "category": "notion", "qualifiers": {}},
    {"q": "NOTION_API_KEY ntn_ filename:.env", "kind": "code", "category": "notion", "qualifiers": {}},

    # ── Airtable dorks ────────────────────────────────────────────────────────
    {"q": "AIRTABLE_API_KEY filename:.env", "kind": "code", "category": "airtable", "qualifiers": {}},

    # ── ElevenLabs dorks ──────────────────────────────────────────────────────
    {"q": "ELEVENLABS_API_KEY filename:.env", "kind": "code", "category": "elevenlabs", "qualifiers": {}},

    # ── Pinecone dorks ────────────────────────────────────────────────────────
    {"q": "PINECONE_API_KEY filename:.env", "kind": "code", "category": "pinecone", "qualifiers": {}},

    # ── Azure OpenAI dorks ────────────────────────────────────────────────────
    {"q": "AZURE_OPENAI_API_KEY filename:.env", "kind": "code", "category": "azure_openai", "qualifiers": {}},
    {"q": "AZURE_OPENAI_ENDPOINT AZURE_OPENAI_API_KEY filename:.env", "kind": "code", "category": "azure_openai", "qualifiers": {}},

    # ── Perplexity dorks ──────────────────────────────────────────────────────
    {"q": "pplx- PERPLEXITY filename:.env", "kind": "code", "category": "perplexity", "qualifiers": {}},
    {"q": "PERPLEXITY_API_KEY filename:.env", "kind": "code", "category": "perplexity", "qualifiers": {}},

    # ── Kubernetes secret dorks ───────────────────────────────────────────────
    {"q": "kind: Secret data: filename:secret.yaml", "kind": "code", "category": "kubernetes", "qualifiers": {}},
    {"q": "kind: Secret stringData filename:secret.yml", "kind": "code", "category": "kubernetes", "qualifiers": {}},

    # ── Pulumi dorks ──────────────────────────────────────────────────────────
    {"q": "PULUMI_ACCESS_TOKEN pul- filename:.env", "kind": "code", "category": "pulumi", "qualifiers": {}},

    # ── Supabase anon/service-role dorks ──────────────────────────────────────
    {"q": "SUPABASE_SERVICE_ROLE_KEY filename:.env", "kind": "code", "category": "supabase", "qualifiers": {}},
    {"q": "SUPABASE_ANON_KEY filename:.env", "kind": "code", "category": "supabase", "qualifiers": {}},

    # ── OpenAI service account dorks ──────────────────────────────────────────
    {"q": "sk-svcacct- filename:.env", "kind": "code", "category": "openai_svcacct", "qualifiers": {}},

    # ── PagerDuty / Zendesk / Atlassian dorks ─────────────────────────────────
    {"q": "PAGERDUTY_API_KEY filename:.env", "kind": "code", "category": "pagerduty", "qualifiers": {}},
    {"q": "ZENDESK_API_TOKEN filename:.env", "kind": "code", "category": "zendesk", "qualifiers": {}},
    {"q": "JIRA_API_TOKEN filename:.env", "kind": "code", "category": "atlassian", "qualifiers": {}},
    {"q": "ATLASSIAN_API_TOKEN filename:.env", "kind": "code", "category": "atlassian", "qualifiers": {}},

    # ── Weaviate dorks ────────────────────────────────────────────────────────
    {"q": "WEAVIATE_API_KEY filename:.env", "kind": "code", "category": "weaviate", "qualifiers": {}},

    # ── Financial / Payment dorks ─────────────────────────────────────────────
    {"q": "PAYPAL_SECRET sandbox filename:.env.example", "kind": "code", "category": "paypal", "qualifiers": {}},
    {"q": "credit_card number cvv filename:config", "kind": "code", "category": "credit_card", "qualifiers": {}},
    {"q": "STRIPE_SECRET_KEY sk_live filename:.env", "kind": "code", "category": "stripe", "qualifiers": {}},
    {"q": "payment gateway secret key filename:.env", "kind": "code", "category": "payment", "qualifiers": {}},
    {"q": "ADYEN_API_KEY AQE filename:.env", "kind": "code", "category": "adyen", "qualifiers": {}},
    {"q": "WISE_API_TOKEN filename:.env", "kind": "code", "category": "wise", "qualifiers": {}},
    {"q": "card_number cvv expiry filename:config.php", "kind": "code", "category": "credit_card", "qualifiers": {}},
    {"q": "paypal client_id client_secret filename:.env", "kind": "code", "category": "paypal", "qualifiers": {}},

    # ── CAPTCHA solver dorks ──────────────────────────────────────────────────
    {"q": "CAPMONSTER_API_KEY filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "capmonster.cloud apiKey filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "CAPMONSTER_KEY= filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "ANTI_CAPTCHA_KEY filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "TWOCAPTCHA_API_KEY filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "2captcha apikey filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "capmonster_cloud_key extension:py", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "capsolver API_KEY CAP- filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "rucaptcha key filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    {"q": "deathbycaptcha username password filename:.env", "kind": "code", "category": "hunt_captcha", "qualifiers": {}},
    # VPS / SSH / Infrastructure
    {"q": "BEGIN RSA PRIVATE KEY filename:id_rsa", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "BEGIN OPENSSH PRIVATE KEY filename:id_ed25519", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "HETZNER_API_TOKEN filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "VULTR_API_KEY= filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "LINODE_TOKEN= extension:env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "SCW_SECRET_KEY filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "PrivateKey= filename:*.conf", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "SSH_PASSWORD= filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "ROOT_PASSWORD= extension:env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "ANSIBLE_VAULT_PASSWORD filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "ghp_ filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "DO_API_TOKEN filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "CONTABO_CLIENT_SECRET filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "OVH_APPLICATION_SECRET filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "id_rsa path:.ssh", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "DIGITALOCEAN_TOKEN dop_v1_ filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},
    {"q": "SCALEWAY_SECRET_KEY filename:.env", "kind": "code", "category": "hunt_vps", "qualifiers": {}},

    # hunt_gmail — Gmail OAuth / SendGrid / SMTP / email provider secrets
    {"q": "GOOGLE_CLIENT_SECRET GOCSPX- filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "private_key_id client_email filename:*.json service_account", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "SENDGRID_API_KEY SG. filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "MAILGUN_API_KEY key- filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "MAILCHIMP_API_KEY us filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "GMAIL_APP_PASSWORD filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "SMTP_PASSWORD= SMTP_HOST= filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "POSTMARK_SERVER_TOKEN filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "EMAIL_PASSWORD SMTP_PASS filename:.env", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
    {"q": "client_secret GOCSPX extension:json", "kind": "code", "category": "hunt_gmail", "qualifiers": {}},
]


# ---------------------------------------------------------------------------
# Quick self-test (python -c "import patterns; ...")
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample = "OPENAI_API_KEY=sk-abc123XYZabc123XYZabc123XYZabc123XYZabc"
    hits = scan_text(sample, ".env")
    import json
    print(json.dumps(hits, indent=2))
