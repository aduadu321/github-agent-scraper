"""
_vps_hunt.py - VPS/SSH/WireGuard/GitHub token hunt
Targets: Hetzner, Vultr, Linode, Scaleway, OVH, DigitalOcean, WireGuard, SSH keys
"""
import re, json, time, requests, os
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent

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
    "BEGIN RSA PRIVATE KEY filename:id_rsa",
    "BEGIN OPENSSH PRIVATE KEY filename:id_ed25519",
    "HETZNER_API_TOKEN filename:.env",
    "VULTR_API_KEY= filename:.env",
    "LINODE_TOKEN extension:env",
    "SCW_SECRET_KEY filename:.env",
    "PrivateKey= filename:wg0.conf",
    "SSH_PASSWORD= filename:.env",
    "ROOT_PASSWORD= extension:env",
    "ghp_ filename:.env",
    "DO_API_TOKEN dop_v1_ filename:.env",
    "OVH_APPLICATION_SECRET filename:.env",
    "SCALEWAY_SECRET_KEY filename:.env",
    "CONTABO_CLIENT_SECRET filename:.env",
    "ANSIBLE_VAULT_PASSWORD filename:.env",
    "id_rsa path:.ssh",
    "wireguard PrivateKey extension:conf",
]

PATTERNS = {
    'hetzner_token':     re.compile(r'(?i)hetzner[_\-](?:api[_\-])?token[\s]*[=:\"\'`]+\s*([A-Za-z0-9]{64})'),
    'vultr_api_key':     re.compile(r'(?i)vultr[_\-](?:api[_\-])?key[\s]*[=:\"\'`]+\s*([A-Z0-9]{36})'),
    'linode_token':      re.compile(r'(?i)(?:linode|akamai)[_\-](?:api[_\-])?token[\s]*[=:\"\'`]+\s*([a-f0-9]{64})'),
    'scaleway_secret':   re.compile(r'(?i)scw[_\-]secret[_\-]key[\s]*[=:\"\'`]+\s*([a-f0-9-]{36})'),
    'wireguard_privkey': re.compile(r'PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)'),
    'ovh_app_secret':    re.compile(r'(?i)OVH_APPLICATION_SECRET[\s]*[=:\"\'`]+\s*([A-Za-z0-9]{32})'),
    'ssh_password':      re.compile(r'(?i)(?:SSH_PASS(?:WORD)?|ROOT_PASSWORD|SSHPASS)[\s]*[=:\"\'`]+\s*([^\s\"\'`]{8,40})'),
    'ansible_vault':     re.compile(r'(?i)(?:ANSIBLE_VAULT_PASSWORD|vault[_\-]pass(?:word)?)[\s]*[=:\"\'`]+\s*([^\s\"\'`]{6,50})'),
    'github_pat':        re.compile(r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})'),
    'do_token':          re.compile(r'(dop_v1_[a-f0-9]{64})'),
    'ssh_rsa_block':     re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----'),
    'contabo_secret':    re.compile(r'(?i)CONTABO_CLIENT_SECRET[\s]*[=:\"\'`]+\s*([^\s\"\'`]{20,60})'),
}

FP_HINTS = ['example', 'test', 'changeme', 'your_', 'xxxx', 'placeholder', '0000', '1234', 'aaaa', 'dummy']

def mask(s):
    if not s or len(s) < 16:
        return s[:8] + '***' if s else '***'
    return s[:12] + '...' + s[-6:]

def is_fp(text):
    tl = text.lower()
    return any(h in tl for h in FP_HINTS)

def fetch_raw(url):
    raw_url = url.replace('https://github.com/', 'https://raw.githubusercontent.com/') \
                 .replace('/blob/', '/')
    try:
        r = requests.get(raw_url, headers=HEADERS, timeout=10)
        if r.status_code == 200 and len(r.text) < 500_000:
            return r.text
    except:
        pass
    return ''

findings = []

print(f"[{datetime.now():%H:%M:%S}] VPS/SSH hunt started - {len(DORKS)} dorks")

for i, dork in enumerate(DORKS, 1):
    print(f"\n[{i}/{len(DORKS)}] {dork[:60]}")
    try:
        r = requests.get(
            'https://api.github.com/search/code',
            params={'q': dork, 'per_page': 20},
            headers=HEADERS, timeout=15
        )
        remaining = int(r.headers.get('X-RateLimit-Remaining', 10))
        if r.status_code == 403 or remaining < 2:
            print("  Rate limited - sleeping 70s")
            time.sleep(70)
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
                    mt = m.group(0) if pat_name == 'ssh_rsa_block' else (m.group(1) if m.lastindex else m.group(0))
                    fp = is_fp(mt)
                    findings.append({
                        'pattern_name': pat_name,
                        'repo': repo,
                        'path': path,
                        'html_url': html_url,
                        'matched_masked': mask(mt),
                        'is_fp_hint': fp,
                        'severity': 'CRITICAL' if pat_name in ('wireguard_privkey','ssh_rsa_block','hetzner_token','vultr_api_key','linode_token','do_token','github_pat') else 'HIGH',
                    })
                    print(f"  [OK] {pat_name} | {repo} | {mask(mt)} | fp={fp}")
            time.sleep(0.4)
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(6)

# Save
out_path = ROOT / 'output' / 'hunt_vps.json'
out_path.parent.mkdir(exist_ok=True)
json.dump(findings, out_path.open('w', encoding='utf-8'), indent=2, ensure_ascii=False)

# Summary
from collections import Counter
pat_counts = Counter(f['pattern_name'] for f in findings)
real = [f for f in findings if not f['is_fp_hint']]
crit = [f for f in real if f['severity'] == 'CRITICAL']

print(f"\n{'='*60}")
print(f"TOTAL findings: {len(findings)} | Non-FP: {len(real)} | CRITICAL: {len(crit)}")
print("\nBy pattern:")
for p, n in pat_counts.most_common():
    print(f"  {n:4d}  {p}")
print(f"\nSaved to {out_path}")
