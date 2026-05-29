"""
_extended_hunt.py - Surse extinse dincolo de GitHub code search.

Surse:
1. Sourcegraph  - GitLab, Bitbucket, self-hosted repos
2. Pastebin     - paste-uri publice recente
3. npm registry - packages cu chei hardcodate
4. PyPI         - packages recente + README
5. Ahmia/Tor    - dark web paste sites (daca Tor e activ)
6. Entropy scan - detectie bazata pe entropie (nu doar regex)
"""
import re, json, time, requests, os, math, string
from pathlib import Path
from datetime import datetime
from collections import Counter

ROOT = Path(__file__).resolve().parent

def load_token():
    env = open(r'C:\Users\aduad\tools\llm-rotate\.env', encoding='utf-8').read()
    m = re.search(r'^GITHUB_TOKEN=([^\r\n]+)', env, re.M)
    return m.group(1).strip() if m else os.environ.get('GITHUB_TOKEN', '')

GITHUB_TOKEN = load_token()

PATTERNS = {
    'openai_key':      re.compile(r'(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,})'),
    'anthropic_key':   re.compile(r'(sk-ant-[A-Za-z0-9_-]{90,})'),
    'groq_key':        re.compile(r'(gsk_[A-Za-z0-9]{52})'),
    'github_pat':      re.compile(r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})'),
    'aws_access':      re.compile(r'(AKIA[0-9A-Z]{16})'),
    'aws_secret':      re.compile(r'(?i)aws.{0,20}secret.{0,10}[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
    'stripe_live':     re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    'sendgrid_key':    re.compile(r'(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})'),
    'do_token':        re.compile(r'(dop_v1_[a-f0-9]{64})'),
    'hetzner_token':   re.compile(r'(?i)hetzner[_-](?:api[_-])?token[\s]*[=:"\'`]+\s*([A-Za-z0-9]{64})'),
    'telegram_bot':    re.compile(r'(\d{8,10}:[A-Za-z0-9_-]{35})'),
    'huggingface':     re.compile(r'(hf_[A-Za-z0-9]{34,})'),
    'together_key':    re.compile(r'(tgp_v\d_[A-Za-z0-9]{48,})'),
    'wireguard':       re.compile(r'PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)'),
    'ssh_private':     re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----'),
    'google_oauth':    re.compile(r'(GOCSPX-[A-Za-z0-9_-]{28})'),
    'xai_key':         re.compile(r'(xai-[A-Za-z0-9]{80,})'),
    'openrouter_key':  re.compile(r'(sk-or-v1-[a-f0-9]{64})'),
    'cerebras_key':    re.compile(r'(csk-[A-Za-z0-9]{48})'),
}

CRIT = {'openai_key','aws_access','aws_secret','stripe_live','ssh_private','wireguard','github_pat','google_oauth'}
FP_HINTS = ['example','test','changeme','your_','xxxx','placeholder','dummy','sample','<','>', '...']

def mask(s):
    if not s or len(s) < 16: return (s[:8]+'***') if s else '***'
    return s[:12]+'...'+s[-6:]

def is_fp(t):
    tl = (t or '').lower()
    return any(h in tl for h in FP_HINTS)

def shannon_entropy(s):
    if not s: return 0
    freq = Counter(s)
    l = len(s)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())

def high_entropy(s, threshold=3.5):
    return shannon_entropy(s) >= threshold

def scan(text, source, url, repo=''):
    hits = []
    for name, pat in PATTERNS.items():
        for m in pat.finditer(text or ''):
            mt = m.group(1) if m.lastindex else m.group(0)
            if is_fp(mt): continue
            if len(mt) > 10 and not high_entropy(mt): continue
            hits.append({
                'pattern_name': name,
                'source': source, 'repo': repo, 'url': url,
                'matched_masked': mask(mt),
                'severity': 'CRITICAL' if name in CRIT else 'HIGH',
                'entropy': round(shannon_entropy(mt), 2),
            })
    return hits

all_findings = []

# ============================================================
# SOURCE 1: Sourcegraph (GitLab + Bitbucket + self-hosted)
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 1: Sourcegraph - GitLab/Bitbucket/self-hosted")
print('='*60)

SG_QUERIES = [
    "OPENAI_API_KEY= lang:env",
    "sk-proj- lang:text",
    "AWS_SECRET_ACCESS_KEY lang:env",
    "STRIPE_SECRET_KEY sk_live lang:env",
    "GITHUB_TOKEN ghp_ lang:env",
    "ANTHROPIC_API_KEY sk-ant lang:env",
    "PrivateKey wireguard lang:ini",
    "BEGIN RSA PRIVATE KEY lang:text",
    "HETZNER_API_TOKEN lang:env",
    "TELEGRAM_BOT_TOKEN lang:env",
]

SG_HEADERS = {'User-Agent': 'Mozilla/5.0 (research-bot)'}

for q in SG_QUERIES[:6]:
    try:
        r = requests.get(
            'https://sourcegraph.com/.api/search/stream',
            params={'q': q, 'v': 'V2', 'display': 5},
            headers=SG_HEADERS, timeout=15, stream=True
        )
        content_found = 0
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith('data:'): continue
            try:
                data = json.loads(line[5:])
                if data.get('type') == 'content':
                    for chunk in data.get('chunkMatches', []):
                        text = chunk.get('content', '')
                        repo = data.get('repository', '')
                        url = f"https://sourcegraph.com/{repo}"
                        hits = scan(text, 'sourcegraph', url, repo)
                        if hits:
                            print(f"  [HIT] {len(hits)} in {repo}")
                            all_findings.extend(hits)
                            content_found += 1
            except: pass
        print(f"  [{q[:45]}] -> {content_found} hits")
        time.sleep(3)
    except Exception as e:
        print(f"  Sourcegraph error: {e}")

# ============================================================
# SOURCE 2: Pastebin recent public pastes
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 2: Pastebin public archive")
print('='*60)

try:
    # Scrape recent pastes listing
    r = requests.get('https://pastebin.com/archive', timeout=10,
                     headers={'User-Agent': 'Mozilla/5.0'})
    paste_ids = re.findall(r'href="/([A-Za-z0-9]{8})"', r.text)[:20]
    print(f"  Found {len(paste_ids)} recent pastes")
    hits_total = 0
    for pid in paste_ids[:15]:
        try:
            raw = requests.get(f'https://pastebin.com/raw/{pid}',
                               timeout=8, headers={'User-Agent': 'Mozilla/5.0'}).text
            hits = scan(raw, 'pastebin', f'https://pastebin.com/{pid}', pid)
            if hits:
                print(f"  [HIT] {len(hits)} in paste/{pid}")
                all_findings.extend(hits)
                hits_total += len(hits)
        except: pass
        time.sleep(0.5)
    print(f"  Total pastebin hits: {hits_total}")
except Exception as e:
    print(f"  Pastebin error: {e}")

# ============================================================
# SOURCE 3: npm registry recent packages
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 3: npm registry - recent packages")
print('='*60)

try:
    # Get recently updated packages
    r = requests.get('https://registry.npmjs.org/-/rss', timeout=10)
    pkg_names = re.findall(r'<title>([^<]{2,50})</title>', r.text)[1:21]
    print(f"  Recent npm packages: {len(pkg_names)}")
    for pkg in pkg_names[:10]:
        pkg = pkg.strip()
        try:
            info = requests.get(f'https://registry.npmjs.org/{pkg}/latest', timeout=8).json()
            readme = info.get('readme', '') or ''
            desc = info.get('description', '') or ''
            text = readme[:5000] + desc
            hits = scan(text, 'npm', f'https://www.npmjs.com/package/{pkg}', pkg)
            if hits:
                print(f"  [HIT] {len(hits)} in npm/{pkg}")
                all_findings.extend(hits)
        except: pass
        time.sleep(0.3)
except Exception as e:
    print(f"  npm error: {e}")

# ============================================================
# SOURCE 4: PyPI recent uploads (extended)
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 4: PyPI - recent packages extended")
print('='*60)

try:
    r = requests.get('https://pypi.org/rss/updates.xml', timeout=10)
    pkg_names = re.findall(r'<title>([a-zA-Z0-9_\-]+) \d', r.text)[:30]
    print(f"  Recent PyPI packages: {len(pkg_names)}")
    hits_total = 0
    for pkg in pkg_names[:20]:
        try:
            info = requests.get(f'https://pypi.org/pypi/{pkg}/json', timeout=8).json()
            desc = info.get('info', {}).get('description', '') or ''
            summary = info.get('info', {}).get('summary', '') or ''
            home = info.get('info', {}).get('home_page', '') or ''
            text = desc[:5000] + summary + home
            hits = scan(text, 'pypi', f'https://pypi.org/project/{pkg}/', pkg)
            if hits:
                print(f"  [HIT] {len(hits)} in PyPI/{pkg}")
                all_findings.extend(hits)
                hits_total += len(hits)
        except: pass
        time.sleep(0.3)
    print(f"  Total PyPI hits: {hits_total}")
except Exception as e:
    print(f"  PyPI error: {e}")

# ============================================================
# SOURCE 5: Ahmia dark web search (via Tor if available)
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 5: Ahmia dark web search")
print('='*60)

TOR_PROXIES = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
TOR_OK = False

try:
    test = requests.get('https://check.torproject.org/api/ip', proxies=TOR_PROXIES, timeout=10)
    if test.json().get('IsTor'):
        TOR_OK = True
        print(f"  Tor active: {test.json().get('IP')}")
    else:
        print("  Tor NOT detected")
except Exception as e:
    print(f"  Tor check failed: {e}")

AHMIA_QUERIES = [
    "openai api key leak",
    "github token dump",
    "aws credentials paste",
    "stripe secret key",
    "api keys 2025 2026",
]

if TOR_OK:
    for q in AHMIA_QUERIES[:3]:
        try:
            r = requests.get(
                f'https://ahmia.fi/search/?q={requests.utils.quote(q)}',
                timeout=20, headers={'User-Agent': 'Mozilla/5.0'}
            )
            onion_links = re.findall(r'href="(http://[a-z2-7]{56}\.onion[^"]*)"', r.text)
            print(f"  [{q}] -> {len(onion_links)} .onion results")
            for url in onion_links[:3]:
                try:
                    content = requests.get(url, proxies=TOR_PROXIES, timeout=15,
                                          headers={'User-Agent': 'Mozilla/5.0'}).text
                    hits = scan(content[:10000], 'darkweb_onion', url)
                    if hits:
                        print(f"  [HIT] {len(hits)} on {url[:60]}")
                        all_findings.extend(hits)
                except: pass
                time.sleep(2)
            time.sleep(5)
        except Exception as e:
            print(f"  Ahmia error: {e}")
else:
    print("  Skipped (Tor not available)")

# ============================================================
# SOURCE 6: Rentry.co + Ghostbin public pastes
# ============================================================
print(f"\n{'='*60}")
print("SOURCE 6: Alternative paste sites")
print('='*60)

PASTE_CHECKS = [
    ('rentry', 'https://rentry.co/api/raw/'),
    ('ghostbin', 'https://ghostbin.co/paste/'),
]

# Search via Google dorks through clearnet (no scraping - just check known paste patterns)
KNOWN_PASTE_PATTERNS = [
    'https://rentry.co/apikeysdump',
    'https://rentry.co/aikeys',
    'https://rentry.co/openaikeys',
]

for url in KNOWN_PASTE_PATTERNS:
    try:
        r = requests.get(url, timeout=8, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            hits = scan(r.text[:10000], 'rentry', url)
            if hits:
                print(f"  [HIT] {len(hits)} on {url}")
                all_findings.extend(hits)
    except: pass

print(f"  Paste sites checked")

# ============================================================
# SAVE & REPORT
# ============================================================
out = ROOT / 'output' / 'hunt_extended.json'
out.parent.mkdir(exist_ok=True)
json.dump(all_findings, out.open('w', encoding='utf-8'), indent=2, ensure_ascii=False)

real = [f for f in all_findings if f.get('severity') in ('CRITICAL','HIGH')]
crit = [f for f in all_findings if f.get('severity') == 'CRITICAL']

print(f"\n{'='*60}")
print(f"EXTENDED HUNT COMPLETE")
print(f"Total: {len(all_findings)} | CRITICAL: {len(crit)}")
print(f"\nBy source:")
for src, n in Counter(f['source'] for f in all_findings).most_common():
    print(f"  {n:4d}  {src}")
print(f"\nBy pattern:")
for p, n in Counter(f['pattern_name'] for f in all_findings).most_common():
    print(f"  {n:4d}  {p}")
print(f"\nSaved -> {out}")
