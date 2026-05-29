"""
ETH balance checker for leaked private keys found in GitHub public repos.
Academic security research — reads balances only, never moves funds.
"""
import json, time, re, os, requests
from pathlib import Path

OUTPUT_DIR = 'output'

# ─── Load GitHub token ────────────────────────────────────────────────────────
def load_gh_token():
    env_path = r'C:\Users\aduad\tools\llm-rotate\.env'
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith(('GITHUB_TOKEN=', 'GH_TOKEN=')):
                    return line.split('=', 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return os.environ.get('GITHUB_TOKEN', '')

GH_TOKEN = load_gh_token()
GH_HEADERS = {'Authorization': f'token {GH_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'} if GH_TOKEN else {}
print(f"GitHub token: {'loaded' if GH_TOKEN else 'NOT found'}")

# ─── Load hunt data ───────────────────────────────────────────────────────────
data = json.load(open(f'{OUTPUT_DIR}/hunt_crypto.json', encoding='utf-8'))
print(f"Loaded {len(data)} hunt_crypto records")

# ─── Regex patterns for extracting keys from raw file content ─────────────────
# ETH private key: 64 hex chars, optionally prefixed with 0x
ETH_RE = re.compile(r'(?:0x)?([0-9a-fA-F]{64})')
# xprv key pattern
XPRV_RE = re.compile(r'(xprv[A-Za-z0-9]{100,})')

SKIP_PATHS = ['test', 'spec', 'example', 'mock', 'fixture', 'sample',
              'doc', 'readme', 'dummy', 'fake', 'learning']

# Well-known test/dummy private keys to exclude
SKIP_KEYS = {
    '0' * 64,
    '1' * 64,
    'a' * 64,
    'f' * 64,
    # Hardhat default account 0
    'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    # Ganache default
    '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d',
    '6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1',
    '6370fd033278c143179d81c5526140625662b8daa446c22ee2d73db3707e620c',
    '646f1ce2fdad0e6deeeb5c7e8e5543bdde65e86029e2fd9fc169899c440a7913',
    'add53f9a7e588d003326d1cbf9e4a43c061aadd9bc938c843a79e7b4fd2ad743',
    '395df67f0c2d2d9fe1ad08d1bc8b6627011959b79c53d7dd6a3536a33ab8a4fd',
    'e485d098507f54e7733a205420dfddbe58db035fa577fc294ebd14db90767a52',
    'a453611d9419d0e56f499079478fd72c37b251a94bfde4d19872c44cf65386e3',
    '829e924fdf021ba3dbbc4225edfece9aca04b929d6e75613329ca6f1d31c0bb4',
    'b0057716d5917badaf911b193b12b910811c1497b5bada8d7711f758981c3773',
    # Known Truffle default accounts
    'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
    'ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f',
    '0dbbe8e4ae425a6d2687f1a7e3ba17bc98c673636790f1b8ad91193c05875ef1',
    '659cbb0e2411a44db63778987b1e22153c086a95eb6b18bdf89de078917abc63',
    '82d052c865f5763aad42add438569276c00d3d88a2d062d36b2bae914d58b8c8',
    '44532a4bb18f9594e45e09ac0018e5e79c7fe48db7c27ab4c67c56b3fcf94b6a',
    '9b2055d370f73ec7d8a03e965129118dc8f5bf83ef96067bc16197ef9c3a927f',
    '1cbd53d0d3cbe96de39c0c7d5b8001b9d8bf7bb40e6ae53fb49c0fe4ee6bc0bf',
    # All-ones, incremental
    '0000000000000000000000000000000000000000000000000000000000000001',
    '0000000000000000000000000000000000000000000000000000000000000002',
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
}

# ─── Fetch raw file content from GitHub ──────────────────────────────────────
_raw_cache = {}

def fetch_raw(raw_url, line_no=None):
    """Fetch raw file content, return lines around line_no if given."""
    if raw_url in _raw_cache:
        return _raw_cache[raw_url]
    try:
        r = requests.get(raw_url, headers=GH_HEADERS, timeout=10)
        if r.status_code == 200:
            _raw_cache[raw_url] = r.text
            return r.text
    except Exception:
        pass
    return None

def extract_eth_key_from_content(content, line_no):
    """Extract ETH private key near the given line number."""
    lines = content.splitlines()
    # Check ±3 lines around line_no
    start = max(0, line_no - 4)
    end   = min(len(lines), line_no + 3)
    for line in lines[start:end]:
        for m in ETH_RE.finditer(line):
            candidate = m.group(1).lower()
            if candidate not in SKIP_KEYS and len(candidate) == 64:
                return candidate
    return None

def extract_xprv_from_content(content, line_no):
    """Extract xprv key near the given line number."""
    lines = content.splitlines()
    start = max(0, line_no - 4)
    end   = min(len(lines), line_no + 3)
    for line in lines[start:end]:
        m = XPRV_RE.search(line)
        if m:
            return m.group(1)
    return None

# ─── Phase 1: Collect ETH private key candidates ─────────────────────────────
print("\n=== Phase 1: Collecting ETH private key candidates ===")
eth_records = [x for x in data if 'eth_private' in x.get('pattern_name', '').lower()]
print(f"ETH private key records: {len(eth_records)}")

eth_candidates = []
for x in eth_records:
    path = (x.get('path', '') or '').lower()
    # Less aggressive path filter: only skip if path strongly suggests template/docs
    # Keep .env files that are not explicitly marked as examples
    if any(t in path for t in SKIP_PATHS):
        continue
    raw_url = x.get('raw_url', '')
    line_no = x.get('line_no', 1) or 1
    if not raw_url:
        continue
    eth_candidates.append({'raw_url': raw_url, 'line_no': line_no,
                           'repo': x.get('repo'), 'path': x.get('path'),
                           'pattern': x.get('pattern_name')})

print(f"After path filter: {len(eth_candidates)} candidates to fetch")

# Fetch and extract keys
seen_keys = set()
valid_eth = []
for i, c in enumerate(eth_candidates):
    content = fetch_raw(c['raw_url'], c['line_no'])
    if content is None:
        print(f"  [{i+1}] FETCH FAILED: {c['repo']} / {c['path']}")
        time.sleep(0.5)
        continue
    key_hex = extract_eth_key_from_content(content, c['line_no'])
    if key_hex and key_hex not in seen_keys:
        seen_keys.add(key_hex)
        masked = '0x' + key_hex[:8] + '...' + key_hex[-6:]
        valid_eth.append({'key_hex': key_hex, 'repo': c['repo'],
                          'path': c['path'], 'key_masked': masked})
        print(f"  [{i+1}] KEY: {masked}  [{c['repo']}]")
    elif key_hex:
        print(f"  [{i+1}] duplicate key")
    else:
        print(f"  [{i+1}] no key extracted: {c['repo']} / {c['path']}")
    time.sleep(0.3)

print(f"\nUnique real ETH private keys found: {len(valid_eth)}")

# ─── Phase 2: xprv keys ──────────────────────────────────────────────────────
print("\n=== Phase 2: xprv key candidates ===")
xprv_records = [x for x in data if 'xprv' in x.get('pattern_name', '').lower()]
print(f"xprv records: {len(xprv_records)}")

xprv_candidates = []
for x in xprv_records:
    path = (x.get('path', '') or '').lower()
    if any(t in path for t in SKIP_PATHS):
        continue
    raw_url = x.get('raw_url', '')
    line_no = x.get('line_no', 1) or 1
    if not raw_url:
        continue
    xprv_candidates.append({'raw_url': raw_url, 'line_no': line_no,
                             'repo': x.get('repo'), 'path': x.get('path')})

seen_xprv = set()
valid_xprv = []
for i, c in enumerate(xprv_candidates):
    content = fetch_raw(c['raw_url'], c['line_no'])
    if content is None:
        print(f"  [{i+1}] FETCH FAILED: {c['repo']}")
        continue
    xprv_key = extract_xprv_from_content(content, c['line_no'])
    if xprv_key and xprv_key not in seen_xprv:
        seen_xprv.add(xprv_key)
        masked = xprv_key[:12] + '...' + xprv_key[-6:]
        valid_xprv.append({'key': xprv_key, 'repo': c['repo'],
                           'path': c['path'], 'key_masked': masked})
        print(f"  [{i+1}] XPRV: {masked}  [{c['repo']}]")
    elif xprv_key:
        print(f"  [{i+1}] duplicate xprv")
    else:
        print(f"  [{i+1}] no xprv extracted: {c['repo']}")
    time.sleep(0.3)

print(f"\nUnique xprv keys found: {len(valid_xprv)}")

# ─── Phase 3: Derive Ethereum addresses ──────────────────────────────────────
print("\n=== Phase 3: Deriving Ethereum addresses ===")
from eth_account import Account
Account.enable_unaudited_hdwallet_features()

addresses = []

# From raw private keys
for c in valid_eth:
    try:
        acct = Account.from_key('0x' + c['key_hex'])
        addresses.append({'address': acct.address, 'repo': c['repo'],
                          'path': c['path'], 'key_masked': c['key_masked'],
                          'source': 'eth_private'})
    except Exception as e:
        print(f"  Key derivation failed: {e}")

print(f"ETH private key addresses: {len(addresses)}")

# From xprv — derive m/44'/60'/0'/0/0 through /2
try:
    import bip32utils
    xprv_count = 0
    for c in valid_xprv:
        try:
            root = bip32utils.BIP32Key.fromExtendedKey(c['key'])
            child = root.ChildKey(44 + bip32utils.BIP32_HARDEN)
            child = child.ChildKey(60 + bip32utils.BIP32_HARDEN)
            child = child.ChildKey(0  + bip32utils.BIP32_HARDEN)
            child = child.ChildKey(0)
            for i in range(3):
                leaf = child.ChildKey(i)
                acct = Account.from_key(leaf.PrivateKey())
                addresses.append({'address': acct.address, 'repo': c['repo'],
                                  'path': c['path'], 'key_masked': c['key_masked'],
                                  'source': f'xprv/m/44h/60h/0h/0/{i}'})
                xprv_count += 1
        except Exception as e:
            print(f"  xprv derivation error: {e}")
    print(f"xprv-derived addresses: {xprv_count}")
except ImportError:
    print("bip32utils not installed — skipping xprv derivation")

print(f"Total addresses to check: {len(addresses)}")

# ─── ETH price ───────────────────────────────────────────────────────────────
print("\n=== Fetching ETH price ===")
try:
    r = requests.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd,ron',
        timeout=10
    )
    prices = r.json().get('ethereum', {})
    eth_usd = prices.get('usd', 0) or 0
    eth_ron = prices.get('ron', 0) or 0
    if not eth_ron and eth_usd:
        eth_ron = eth_usd * 4.55
    print(f"ETH: ${eth_usd} USD / {eth_ron:.0f} RON")
except Exception as e:
    print(f"Price fetch failed: {e} — using fallback")
    eth_usd = 2500
    eth_ron = 11375

# ─── Balance check ───────────────────────────────────────────────────────────
CLOUDFLARE_ETH = "https://cloudflare-eth.com"
ETHERSCAN      = "https://api.etherscan.io/api"

def get_balance_wei(address):
    # Try Cloudflare public JSON-RPC
    try:
        payload = {"jsonrpc": "2.0", "method": "eth_getBalance",
                   "params": [address, "latest"], "id": 1}
        r = requests.post(CLOUDFLARE_ETH, json=payload, timeout=8)
        result = r.json().get('result', '0x0')
        return int(result, 16)
    except Exception:
        pass
    # Fallback: Etherscan (no key required for balance)
    try:
        r = requests.get(
            f"{ETHERSCAN}?module=account&action=balance&address={address}&tag=latest",
            timeout=8
        )
        j = r.json()
        if j.get('status') == '1':
            return int(j['result'])
    except Exception:
        pass
    return None

if addresses:
    print(f"\n=== Checking {len(addresses)} addresses for balance ===")
else:
    print("\nNo addresses to check — all keys were in test/example paths.")

total_eth = 0.0
nonzero   = []
errors    = 0

for i, addr_info in enumerate(addresses):
    addr = addr_info['address']
    bal_wei = get_balance_wei(addr)
    if bal_wei is None:
        print(f"  [{i+1}/{len(addresses)}] {addr[:10]}... ERROR")
        errors += 1
        time.sleep(1)
        continue
    bal_eth = bal_wei / 1e18
    if bal_eth > 0.0001:
        total_eth += bal_eth
        bal_usd = bal_eth * eth_usd
        bal_ron = bal_eth * eth_ron
        nonzero.append({**addr_info,
                        'balance_eth': bal_eth,
                        'balance_usd': bal_usd,
                        'balance_ron': bal_ron})
        print(f"  [{i+1}] *** {addr} = {bal_eth:.6f} ETH "
              f"({bal_ron:.0f} RON / ${bal_usd:.0f}) | {addr_info['repo']}")
    else:
        print(f"  [{i+1}/{len(addresses)}] {addr[:10]}... 0 ETH")
    time.sleep(0.3)

# ─── Final summary ───────────────────────────────────────────────────────────
print(f"\n{'='*65}")
print(f"=== CRYPTO VALUE FOUND ON GITHUB (public repos, academic research) ===")
print(f"ETH price:         ${eth_usd} USD / {eth_ron:.0f} RON")
print(f"Addresses checked: {len(addresses)}")
print(f"Errors:            {errors}")
print(f"Non-zero wallets:  {len(nonzero)}")
print(f"Total ETH:         {total_eth:.6f}")
print(f"Total value:       {total_eth * eth_ron:.0f} RON / ${total_eth * eth_usd:.0f} USD")
print(f"{'='*65}")

# ─── Save results ────────────────────────────────────────────────────────────
output_data = {
    'eth_price_usd':     eth_usd,
    'eth_price_ron':     eth_ron,
    'addresses_checked': len(addresses),
    'errors':            errors,
    'nonzero_wallets':   nonzero,
    'total_eth':         total_eth,
    'total_ron':         total_eth * eth_ron,
    'total_usd':         total_eth * eth_usd,
}
json.dump(output_data,
          open(f'{OUTPUT_DIR}/eth_balances.json', 'w', encoding='utf-8'),
          indent=2)
print(f"\nSaved to {OUTPUT_DIR}/eth_balances.json")
