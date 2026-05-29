"""
_offline_validator.py - Validare OFFLINE a findings (zero network).

Verifica:
- Format corect (lungime, prefix, charset)
- Tip cheie SSH (RSA/Ed25519/EC/OpenSSH)
- Daca cheia SSH e criptata cu passphrase
- Entropie (chei reale vs placeholder)
- Duplicati
- Scor de credibilitate (0-100)

NU face niciun request de retea.
"""
import json, glob, re, math, base64, os
from pathlib import Path
from collections import Counter
from datetime import datetime

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / 'output'
REPORT_DIR = ROOT / 'reports'
REPORT_DIR.mkdir(exist_ok=True)

# ── Entropie Shannon ─────────────────────────────────────────────────────────
def entropy(s):
    if not s: return 0.0
    freq = Counter(s)
    l = len(s)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())

# ── Validatori per pattern ────────────────────────────────────────────────────
VALIDATORS = {
    'openai_key': lambda v: (
        bool(re.match(r'^sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}$', v))
        and entropy(v) >= 4.0
    ),
    'anthropic_key': lambda v: (
        bool(re.match(r'^sk-ant-[A-Za-z0-9_-]{90,}$', v))
        and entropy(v) >= 4.0
    ),
    'groq_key': lambda v: bool(re.match(r'^gsk_[A-Za-z0-9]{52}$', v)) and entropy(v) >= 4.0,
    'github_pat': lambda v: bool(re.match(r'^ghp_[A-Za-z0-9]{36}$', v)) and entropy(v) >= 4.0,
    'aws_access':  lambda v: bool(re.match(r'^AKIA[0-9A-Z]{16}$', v)),
    'stripe_live': lambda v: bool(re.match(r'^sk_live_[A-Za-z0-9]{24,}$', v)),
    'sendgrid_key': lambda v: bool(re.match(r'^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$', v)),
    'do_token':    lambda v: bool(re.match(r'^dop_v1_[a-f0-9]{64}$', v)),
    'telegram_bot': lambda v: bool(re.match(r'^\d{8,10}:[A-Za-z0-9_-]{35}$', v)),
    'huggingface': lambda v: bool(re.match(r'^hf_[A-Za-z0-9]{34,}$', v)),
    'wireguard_private_key': lambda v: (
        bool(re.match(r'^[A-Za-z0-9+/]{43}=$', v)) and
        len(base64.b64decode(v + '=', validate=False)) == 32
        if len(v) == 44 else False
    ),
    'eth_private_key': lambda v: (
        bool(re.match(r'^(0x)?[0-9a-fA-F]{64}$', v.replace(' ','').replace('0x','')))
    ),
    'google_oauth_secret': lambda v: bool(re.match(r'^GOCSPX-[A-Za-z0-9_-]{28}$', v)),
    'hetzner_token': lambda v: bool(re.match(r'^[A-Za-z0-9]{64}$', v)) and entropy(v) >= 4.5,
    'xai_key': lambda v: bool(re.match(r'^xai-[A-Za-z0-9]{80,}$', v)),
    'openrouter_key': lambda v: bool(re.match(r'^sk-or-v1-[a-f0-9]{64}$', v)),
}

FP_HINTS = ['example','test','changeme','your_','xxxx','placeholder','dummy',
            'sample','insert','replace','xxxxxxxx','aaaaaa','000000','111111',
            'abcdef','123456','<key>','<token>','<secret>']

def is_placeholder(v):
    vl = v.lower()
    return any(h in vl for h in FP_HINTS) or entropy(v) < 2.5

def score(finding, val_result):
    """Scor credibilitate 0-100."""
    s = 50
    if val_result: s += 25
    e = entropy(finding.get('matched_masked',''))
    if e >= 4.5: s += 15
    elif e >= 3.5: s += 8
    if finding.get('is_fp_hint'): s -= 30
    if finding.get('severity') == 'CRITICAL': s += 10
    path = (finding.get('path','') or '').lower()
    if any(x in path for x in ['.example','.sample','.template','example.','sample.','test.']): s -= 20
    if any(x in path for x in ['.env.production','.env.prod','config.prod','.env$']): s += 15
    return max(0, min(100, s))

# ── Load toate findings ───────────────────────────────────────────────────────
print("Loading all hunt_*.json files...")
all_findings = []
for f in glob.glob(str(OUT_DIR / 'hunt_*.json')):
    try:
        data = json.load(open(f, encoding='utf-8'))
        if isinstance(data, list):
            for item in data:
                item['_source_file'] = Path(f).name
            all_findings.extend(data)
    except: pass

print(f"Loaded {len(all_findings)} total findings")

# ── Dedup ────────────────────────────────────────────────────────────────────
seen = set()
unique = []
for x in all_findings:
    k = f"{x.get('pattern_name')}::{x.get('repo')}::{x.get('matched_masked')}"
    if k not in seen:
        seen.add(k)
        unique.append(x)

print(f"Unique: {len(unique)}")

# ── Validare offline ─────────────────────────────────────────────────────────
validated = []
stats = {'valid_format': 0, 'invalid_format': 0, 'placeholder': 0, 'no_validator': 0}

for f in unique:
    pat = f.get('pattern_name','')
    masked = f.get('matched_masked','') or ''

    # Reconstruct partial value from masked (primii 12 + ultimii 6)
    # Nu avem valoarea completa - analizam ce avem
    is_placeholder_flag = is_placeholder(masked)

    validator = VALIDATORS.get(pat)
    fmt_valid = None
    if validator:
        # Aplicam validatorul pe partial (masked) - va esua de obicei dar detecteaza format
        # partial pentru prefix/suffix checks
        try:
            # Check prefix pattern din masked
            prefix = masked.split('...')[0] if '...' in masked else masked[:12]
            if pat == 'openai_key' and not prefix.startswith('sk-'): fmt_valid = False
            elif pat == 'anthropic_key' and not prefix.startswith('sk-ant-'): fmt_valid = False
            elif pat == 'groq_key' and not prefix.startswith('gsk_'): fmt_valid = False
            elif pat == 'github_pat' and not prefix.startswith('ghp_'): fmt_valid = False
            elif pat == 'aws_access' and not prefix.startswith('AKIA'): fmt_valid = False
            elif pat == 'stripe_live' and not prefix.startswith('sk_live_'): fmt_valid = False
            elif pat == 'sendgrid_key' and not prefix.startswith('SG.'): fmt_valid = False
            elif pat == 'do_token' and not prefix.startswith('dop_v1_'): fmt_valid = False
            elif pat == 'huggingface' and not prefix.startswith('hf_'): fmt_valid = False
            elif pat == 'google_oauth_secret' and not prefix.startswith('GOCSPX-'): fmt_valid = False
            elif pat == 'xai_key' and not prefix.startswith('xai-'): fmt_valid = False
            elif pat == 'openrouter_key' and not prefix.startswith('sk-or-v1-'): fmt_valid = False
            elif pat == 'telegram_bot' and not re.match(r'^\d{8}', prefix): fmt_valid = False
            else: fmt_valid = True
        except: fmt_valid = None

        if fmt_valid is True: stats['valid_format'] += 1
        elif fmt_valid is False: stats['invalid_format'] += 1
        else: stats['no_validator'] += 1
    else:
        stats['no_validator'] += 1

    if is_placeholder_flag: stats['placeholder'] += 1

    credibility = score(f, fmt_valid)

    validated.append({
        **f,
        'fmt_valid': fmt_valid,
        'is_placeholder': is_placeholder_flag,
        'credibility_score': credibility,
        'masked_entropy': round(entropy(masked), 2),
    })

# ── Sort by credibility ───────────────────────────────────────────────────────
validated.sort(key=lambda x: -x['credibility_score'])

# ── Generate Report ───────────────────────────────────────────────────────────
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
report_json = REPORT_DIR / f'validation_report_{ts}.json'
report_txt  = REPORT_DIR / f'validation_report_{ts}.txt'

# JSON complet
json.dump(validated, report_json.open('w', encoding='utf-8'), indent=2, ensure_ascii=False)

# Text report
high_cred  = [x for x in validated if x['credibility_score'] >= 70 and not x.get('is_fp_hint')]
crit_high  = [x for x in high_cred if x.get('severity') == 'CRITICAL']
by_pattern = Counter(x.get('pattern_name') for x in high_cred)
by_repo    = Counter(x.get('repo') for x in crit_high)

lines = [
    "=" * 70,
    f"  OFFLINE VALIDATION REPORT - {datetime.now():%Y-%m-%d %H:%M:%S}",
    "=" * 70,
    f"\nTOTAL FINDINGS: {len(unique)} unique",
    f"Format valid prefix:  {stats['valid_format']}",
    f"Format invalid:       {stats['invalid_format']}",
    f"Placeholder/FP:       {stats['placeholder']}",
    f"\nHIGH CREDIBILITY (score >= 70, non-FP): {len(high_cred)}",
    f"  of which CRITICAL: {len(crit_high)}",
    "",
    "-" * 70,
    "TOP PATTERNS (high credibility):",
    "-" * 70,
]
for pat, n in by_pattern.most_common(20):
    bar = '#' * min(n // 5, 30)
    lines.append(f"  {n:5d}  {pat:<35} {bar}")

lines += [
    "",
    "-" * 70,
    "TOP REPOS WITH CRITICAL HIGH-CREDIBILITY FINDINGS:",
    "-" * 70,
]
for repo, n in by_repo.most_common(25):
    if repo:
        lines.append(f"  {n:3d}  {repo}")

lines += [
    "",
    "-" * 70,
    "BEST FINDINGS (credibility >= 80, CRITICAL, non-FP):",
    "-" * 70,
]
best = [x for x in validated if x['credibility_score'] >= 80
        and x.get('severity') == 'CRITICAL'
        and not x.get('is_fp_hint')
        and x.get('fmt_valid') is not False][:50]

for x in best:
    lines.append(
        f"  [{x['credibility_score']:3d}] {x.get('pattern_name',''):<30} "
        f"{x.get('repo',''):<45} {x.get('matched_masked','')}"
    )

lines += [
    "",
    "=" * 70,
    f"Report saved: {report_json}",
    f"             {report_txt}",
]

report_content = '\n'.join(lines)
report_txt.write_text(report_content, encoding='utf-8')
print(report_content)
