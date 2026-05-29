import json
d = json.load(open('output/hunt_openai.json', encoding='utf-8'))
ssh = [x for x in d if 'ssh' in x.get('pattern_name','').lower() or 'private' in x.get('pattern_name','').lower()]
crypto = [x for x in d if any(t in x.get('pattern_name','').lower() for t in ['eth','btc','mnemonic','xprv','solana','binance','coinbase','infura','alchemy'])]
print(f"SSH/private key findings: {len(ssh)}")
for x in ssh:
    mt = x.get('matched_text','') or ''
    masked = mt[:12] + '...' + mt[-8:] if len(mt) > 20 else mt[:20]
    fp = x.get('is_fp_hint', False)
    print(f"  repo={x['repo']} path={x['path']} pattern={x['pattern_name']} FP={fp}")
    print(f"  matched={masked}")
    print(f"  url={x.get('html_url','')}")
print(f"\nCrypto findings: {len(crypto)}")
if crypto:
    for x in crypto:
        print(f"  {x['pattern_name']} in {x['repo']}/{x['path']}")
else:
    print("  None found (crypto hunt not run yet — need dedicated crypto dorks)")
