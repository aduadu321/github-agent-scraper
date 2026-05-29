import json, glob
from collections import Counter

all_findings = []
for f in glob.glob('output/hunt_*.json'):
    try:
        data = json.load(open(f, encoding='utf-8'))
        if isinstance(data, list):
            all_findings.extend(data)
    except: pass

seen = set()
unique = []
for x in all_findings:
    k = str(x.get('repo','')) + '::' + str(x.get('path','')) + '::' + str(x.get('pattern_name',''))
    if k not in seen:
        seen.add(k)
        unique.append(x)

print(f'Total unice: {len(unique)} din {len(all_findings)} total\n')

cats = {
    'DB connections (postgres/redis/mongo)': ['postgres_url','redis_url','mongodb_url','database_url_generic','mysql_url'],
    'SSH / TLS private keys':               ['ssh_private_key','ssh_rsa_private_key','ssh_openssh_private_key','ssh_ec_private_key','ssl_private_key'],
    'JWT secrets':                           ['jwt_secret','jwt_token'],
    'OpenAI keys':                           ['openai_key','openai_project_key','openai_service_account'],
    'GitHub PAT':                            ['github_pat','github_pat_classic'],
    'Google API':                            ['google_api_key','google_oauth_secret','google_service_account'],
    'AWS keys':                              ['aws_access_key','aws_secret_key'],
    'Okta tokens':                           ['okta_token'],
    'GitLab tokens':                         ['gitlab_token'],
    'Slack tokens':                          ['slack_bot_token','slack_token'],
    'Supabase':                              ['supabase_service_key','supabase_key'],
    'Stripe':                                ['stripe_live_key','stripe_key'],
    'Groq':                                  ['groq_key'],
    'Crypto ETH private key':               ['eth_private_key','eth_private_key_no0x','eth_private_key_hex'],
    'Mnemonic BIP39':                        ['mnemonic_12','mnemonic_24','mnemonic_12words'],
    'Anthropic':                             ['anthropic_key','anthropic_beta_key'],
    'HuggingFace':                           ['huggingface_token'],
    'Telegram bot':                          ['telegram_bot_token'],
    'SendGrid':                              ['sendgrid_key'],
    'Infura/Alchemy (ETH RPC)':             ['infura_key','alchemy_key'],
    'Credit card numbers':                   ['credit_card_visa','credit_card_mastercard','credit_card_amex','credit_card_discover'],
    'PayPal':                                ['paypal_client_secret','paypal_client_id'],
    'WireGuard VPN':                         ['wireguard_private_key'],
    'VPS tokens (Hetzner/DO/Vultr)':        ['hetzner_token','vultr_api_key','linode_token','scaleway_secret','do_token'],
}

pats = Counter(x.get('pattern_name','') for x in unique)
rows = []
for cat, patterns in cats.items():
    total = sum(pats.get(p,0) for p in patterns)
    rows.append((cat, total))
rows.sort(key=lambda r: -r[1])

print(f"{'#':<3} {'Categorie':<38} {'Found':>7}")
print('-' * 52)
for i, (cat, n) in enumerate(rows, 1):
    if n > 0:
        bar = '█' * min(n // 30, 20)
        print(f"{i:<3} {cat:<38} {n:>7}  {bar}")
