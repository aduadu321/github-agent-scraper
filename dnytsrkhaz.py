"""
_gmail_hunt.py — Gmail OAuth / SendGrid / SMTP / email provider secrets hunt
"""
import re, json, time, requests, os
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent
from collections import Counter

def load_token():
    env = open(r'C:\Users\aduad\tools\llm-rotate\.env', encoding='utf-8').read()
    m = re.search(r'^GITHUB_TOKEN=([^\r\n]+)', env, re.M)
    return m.group(1).strip() if m else os.environ.get('GITHUB_TOKEN','')

GITHUB_TOKEN = load_token()
HEADERS = {
    'Authorization': f'Bearer {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
    'X-GitHub-Api-Version': '2022-11-28',
}

DORKS = [
    "GOOGLE_CLIENT_SECRET GOCSPX- filename:.env",
    "private_key_id client_email filename:*.json service_account",
    "SENDGRID_API_KEY SG. filename:.env",
    "MAILGUN_API_KEY key- filename:.env",
    "MAILCHIMP_API_KEY us filename:.env",
    "GMAIL_APP_PASSWORD filename:.env",
    "SMTP_PASSWORD= SMTP_HOST= filename:.env",
    "POSTMARK_SERVER_TOKEN filename:.env",
    "EMAIL_PASSWORD SMTP_PASS filename:.env",
    "client_secret GOCSPX extension:json",
]

PATTERNS = {
    'sendgrid_key':           re.compile(r'(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})'),
    'google_oauth_secret':    re.compile(r'(GOCSPX-[A-Za-z0-9_\-]{28})'),
    'google_service_account': re.compile(r'"private_key":\s*"-----BEGIN RSA PRIVATE KEY-----'),
    'mailgun_key':            re.compile(r'(key-[a-f0-9]{32})'),
    'mailchimp_key':          re.compile(r'([a-f0-9]{32}-us\d{1,2})'),
    'gmail_app_password':     re.compile(r'(?i)GMAIL_APP_PASSWORD[\s]*[=:\"\'`]+\s*([a-z]{4}\s[a-z]{4}\s[a-z]{4}\s[a-z]{4}|[a-z]{16})'),
    'smtp_password':          re.compile(r'(?i)(?:SMTP_PASSWORD|SMTP_PASS|EMAIL_PASSWORD|MAIL_PASSWORD)[\s]*[=:\"\'`]+\s*([^\s\"\'`]{8,60})'),
    'postmark_token':         re.compile(r'(?i)POSTMARK_(?:SERVER_)?TOKEN[\s]*[=:\"\'`]+\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'),
    'google_client_id':       re.compile(r'(\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)'),
    'zoho_oauth':             re.compile(r'(?i)ZOHO_(?:CLIENT_SECRET|REFRESH_TOKEN)[\s]*[=:\"\'`]+\s*([A-Za-z0-9._\-]{20,80})'),
}

FP_HINTS = ['example', 'test', 'changeme', 'your_', 'xxxx', 'placeholder', 'dummy',
            'SG.XXXX', 'key-xxxx', 'smtp_pass', 'password']

def mask(s):
    if not s: return '***'
    return s[:10] + '...' + s[-6:] if len(s) > 16 else s[:8] + '***'

def is_fp(text):
    tl = (text or '').lower()
    return any(h in tl for h in FP_HINTS)

def fetch_raw(html_url):
    raw = html_url.replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/')
    try:
        r = requests.get(raw, headers=HEADERS, timeout=10)
        if r.status_code == 200 and len(r.text) < 300_000:
            return r.text
    except: pass
    return ''

findings = []
print(f"[{datetime.now():%H:%M:%S}] Gmail/email provider hunt — {len(DORKS)} dorks")

for i, dork in enumerate(DORKS, 1):
    print(f"\n[{i}/{len(DORKS)}] {dork[:70]}")
    try:
        r = requests.get(
            'https://api.github.com/search/code',
            params={'q': dork, 'per_page': 20},
            headers=HEADERS, timeout=15
        )
        remaining = int(r.headers.get('X-RateLimit-Remaining', 10))
        if r.status_code == 403 or remaining < 2:
            wait = int(r.headers.get('X-RateLimit-Reset', time.time() + 70)) - int(time.time()) + 5
            print(f"  Rate limited — sleeping {wait}s")
            time.sleep(max(wait, 70))
            continue
        items = r.json().get('items', [])
        print(f"  {len(items)} results")
        for item in items:
            html_url = item.get('html_url', '')
            repo = item.get('repository', {}).get('full_name', '')
            path = item.get('path', '')
            content = fetch_raw(html_url)
            if not content:
                continue
            for pat_name, pat in PATTERNS.items():
                for m in pat.finditer(content):
                    mt = m.group(1) if m.lastindex else m.group(0)
                    fp = is_fp(mt)
                    sev = 'CRITICAL' if pat_name in ('sendgrid_key','google_service_account','google_oauth_secret') else 'HIGH'
                    findings.append({
                        'pattern_name': pat_name,
                        'repo': repo,
                        'path': path,
                        'html_url': html_url,
                        'matched_masked': mask(mt),
                        'is_fp_hint': fp,
                        'severity': sev,
                    })
                    print(f"  {'[CRIT]' if sev=='CRITICAL' else '[HIGH]'} {pat_name} | {repo} | {mask(mt)} | fp={fp}")
            time.sleep(0.4)
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(6)

out = ROOT / 'output' / 'hunt_gmail.json'
out.parent.mkdir(exist_ok=True)
json.dump(findings, out.open('w', encoding='utf-8'), indent=2, ensure_ascii=False)

real = [f for f in findings if not f['is_fp_hint']]
crit = [f for f in real if f['severity'] == 'CRITICAL']
print(f"\n{'='*60}")
print(f"TOTAL: {len(findings)} | Non-FP: {len(real)} | CRITICAL: {len(crit)}")
for p, n in Counter(f['pattern_name'] for f in findings).most_common():
    print(f"  {n:4d}  {p}")
print(f"\nSaved -> {out}")
