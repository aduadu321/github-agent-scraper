"""
_multi_source_hunt.py - Hunt secrets in ALTE LOCURI decat GitHub code search.

Surse noi:
1. GitHub GISTS (publice, rotite frecvent, ignorat de scanere standard)
2. GitHub COMMITS (mesaje commit cu credentiale)
3. Sourcegraph (index public universal - GitLab, Bitbucket, self-hosted)
4. PyPI packages (setup.py, pyproject.toml cu chei hardcodate)
5. npm packages (index npm pentru .env hardcodate)
6. Pastebin/paste-uri publice via Google dork (Ahmia pentru .onion)
7. Docker Hub (image layers cu env vars)
8. HuggingFace Hub (model cards, scripts)
"""
import re, json, time, requests, os
from pathlib import Path
from datetime import datetime
from collections import Counter

ROOT = Path(__file__).resolve().parent

def load_token():
    env = open(r'C:\Users\aduad\tools\llm-rotate\.env', encoding='utf-8').read()
    m = re.search(r'^GITHUB_TOKEN=([^\r\n]+)', env, re.M)
    return m.group(1).strip() if m else ''

GITHUB_TOKEN = load_token()
GH_HEADERS = {
    'Authorization': f'Bearer {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
    'X-GitHub-Api-Version': '2022-11-28',
}

# Patterns to scan
PATTERNS = {
    'openai_key':     re.compile(r'(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{40,})'),
    'anthropic_key':  re.compile(r'(sk-ant-[A-Za-z0-9_\-]{90,})'),
    'groq_key':       re.compile(r'(gsk_[A-Za-z0-9]{52})'),
    'github_pat':     re.compile(r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})'),
    'aws_access':     re.compile(r'(AKIA[0-9A-Z]{16})'),
    'hetzner_token':  re.compile(r'(?i)hetzner[_\-](?:api[_\-])?token[\s]*[=:\"\'`]+\s*([A-Za-z0-9]{64})'),
    'do_token':       re.compile(r'(dop_v1_[a-f0-9]{64})'),
    'sendgrid_key':   re.compile(r'(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})'),
    'stripe_live':    re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    'ssh_private':    re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----'),
    'wireguard':      re.compile(r'PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)'),
    'telegram_bot':   re.compile(r'(\d{8,10}:[A-Za-z0-9_\-]{35})'),
    'huggingface':    re.compile(r'(hf_[A-Za-z0-9]{34,})'),
    'together_key':   re.compile(r'(tgp_v\d_[A-Za-z0-9]{48,})'),
}

FP_HINTS = ['example', 'test', 'changeme', 'your_', 'xxxx', 'placeholder', 'dummy', 'sample']

def mask(s): return s[:12]+'...'+s[-6:] if len(s or '')>18 else (s[:8]+'***' if s else '***')
def is_fp(t): return any(h in (t or '').lower() for h in FP_HINTS)

def scan(text, source, url, repo=''):
    hits = []
    for name, pat in PATTERNS.items():
        for m in pat.finditer(text or ''):
            mt = m.group(1) if m.lastindex else m.group(0)
            if not is_fp(mt):
                hits.append({'pattern_name': name, 'source': source, 'repo': repo,
                             'url': url, 'matched_masked': mask(mt),
                             'severity': 'CRITICAL' if name in ('openai_key','aws_access','ssh_private','stripe_live','wireguard') else 'HIGH'})
    return hits

all_findings = []

# ============================================================
# SOURCE 1: GitHub Gists (publice, recente)
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 1: GitHub Gists publice")
print('='*60)

GIST_DORKS = [
    "OPENAI_API_KEY", "sk-proj-", "AWS_SECRET_ACCESS_KEY",
    "private_key BEGIN RSA", "PrivateKey wireguard",
    "STRIPE_SECRET_KEY sk_live", "GITHUB_TOKEN ghp_",
    "hetzner token api", "DO_API_TOKEN dop_v1",
]

try:
    r = requests.get('https://api.github.com/gists/public',
                     params={'per_page': 100}, headers=GH_HEADERS, timeout=15)
    gists = r.json() if isinstance(r.json(), list) else []
    print(f"  Got {len(gists)} recent public gists")
    for gist in gists[:50]:
        for fname, fdata in (gist.get('files') or {}).items():
            raw_url = fdata.get('raw_url', '')
            if raw_url:
                try:
                    content = requests.get(raw_url, headers=GH_HEADERS, timeout=8).text
                    hits = scan(content, 'gist', gist.get('html_url',''), gist.get('id',''))
                    if hits:
                        print(f"  [HIT] {len(hits)} hits in gist {gist['id']}/{fname}")
                        all_findings.extend(hits)
                except: pass
                time.sleep(0.3)
    time.sleep(3)
except Exception as e:
    print(f"  Gist error: {e}")

# ============================================================
# SOURCE 2: GitHub COMMIT messages + diffs
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 2: GitHub Commits con credentiale")
print('='*60)

COMMIT_QUERIES = [
    "sk-proj- accidentally",
    "removed api key",
    "deleted secret key",
    "oops api key",
    "OPENAI_API_KEY commit",
    "AWS_SECRET accidentally pushed",
]

for q in COMMIT_QUERIES[:4]:
    try:
        r = requests.get('https://api.github.com/search/commits',
                         params={'q': q, 'per_page': 10},
                         headers={**GH_HEADERS, 'Accept': 'application/vnd.github.cloak-preview+json'},
                         timeout=12)
        items = r.json().get('items', [])
        print(f"  [{q[:40]}] -> {len(items)} commits")
        for item in items[:5]:
            msg = item.get('commit', {}).get('message', '')
            hits = scan(msg, 'commit_message', item.get('html_url',''),
                       item.get('repository', {}).get('full_name',''))
            if hits:
                print(f"  [OK] Hit in commit message: {hits[0]['pattern_name']}")
                all_findings.extend(hits)
        time.sleep(6)
    except Exception as e:
        print(f"  Error: {e}")
        time.sleep(6)

# ============================================================
# SOURCE 3: HuggingFace Hub - model cards si scripts
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 3: HuggingFace Hub - scripts cu chei")
print('='*60)

HF_SEARCHES = [
    "OPENAI_API_KEY",
    "sk-proj-",
    "AWS_ACCESS_KEY_ID AKIA",
    "ANTHROPIC_API_KEY sk-ant-",
]

for q in HF_SEARCHES[:3]:
    try:
        # HF search API
        r = requests.get(f'https://huggingface.co/api/models',
                        params={'search': q, 'limit': 5}, timeout=10)
        models = r.json() if isinstance(r.json(), list) else []
        print(f"  [{q[:40]}] -> {len(models)} models")
        for model in models[:3]:
            mid = model.get('id','')
            # Try README
            readme_url = f'https://huggingface.co/{mid}/resolve/main/README.md'
            try:
                readme = requests.get(readme_url, timeout=8).text
                hits = scan(readme, 'huggingface_readme', readme_url, mid)
                if hits:
                    print(f"  [HIT] {len(hits)} hits in {mid}/README.md")
                    all_findings.extend(hits)
            except: pass
            time.sleep(0.5)
        time.sleep(3)
    except Exception as e:
        print(f"  HF error: {e}")

# ============================================================
# SOURCE 4: Docker Hub - image descriptions
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 4: Docker Hub - image descriptions")
print('='*60)

DH_QUERIES = ["api_key", "secret_key", "OPENAI", "private_key"]

for q in DH_QUERIES[:2]:
    try:
        r = requests.get(f'https://hub.docker.com/v2/search/repositories/',
                        params={'query': q, 'page_size': 10}, timeout=10)
        results = r.json().get('results', [])
        print(f"  [{q}] -> {len(results)} images")
        for img in results[:5]:
            desc = img.get('description','') + ' ' + img.get('full_description','')
            hits = scan(desc, 'dockerhub', f"https://hub.docker.com/r/{img.get('repo_name','')}", img.get('repo_name',''))
            if hits:
                print(f"  [HIT] {len(hits)} hits in {img.get('repo_name')}")
                all_findings.extend(hits)
        time.sleep(2)
    except Exception as e:
        print(f"  Docker Hub error: {e}")

# ============================================================
# SOURCE 5: PyPI - package files via PyPI JSON API
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 5: PyPI - recent packages cu chei hardcodate")
print('='*60)

# Check recent uploads via PyPI RSS
try:
    r = requests.get('https://pypi.org/rss/updates.xml', timeout=10)
    # Parse package names from RSS
    pkg_names = re.findall(r'<title>([a-zA-Z0-9_\-]+) \d', r.text)[:20]
    print(f"  Recent packages: {len(pkg_names)}")
    for pkg in pkg_names[:10]:
        try:
            info = requests.get(f'https://pypi.org/pypi/{pkg}/json', timeout=8).json()
            desc = info.get('info', {}).get('description', '')
            hits = scan(desc, 'pypi', f'https://pypi.org/project/{pkg}/', pkg)
            if hits:
                print(f"  [HIT] {len(hits)} hits in PyPI/{pkg}")
                all_findings.extend(hits)
        except: pass
        time.sleep(0.5)
except Exception as e:
    print(f"  PyPI error: {e}")

# ============================================================
# SAVE & REPORT
# ============================================================
out = ROOT / 'output' / 'hunt_multi_source.json'
out.parent.mkdir(exist_ok=True)
json.dump(all_findings, out.open('w', encoding='utf-8'), indent=2, ensure_ascii=False)

real = [f for f in all_findings if not f.get('is_fp_hint')]
crit = [f for f in all_findings if f.get('severity') == 'CRITICAL']

print(f"\n{'='*60}")
print(f"MULTI-SOURCE HUNT COMPLETE")
print(f"Total findings: {len(all_findings)} | CRITICAL: {len(crit)}")
print(f"\nBy source:")
for src, n in Counter(f['source'] for f in all_findings).most_common():
    print(f"  {n:4d}  {src}")
print(f"\nBy pattern:")
for p, n in Counter(f['pattern_name'] for f in all_findings).most_common():
    print(f"  {n:4d}  {p}")
print(f"\nSaved -> {out}")
