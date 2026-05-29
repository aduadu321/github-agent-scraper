import re
env_path = r'C:\Users\aduad\tools\llm-rotate\.env'
gh_token = None
with open(env_path) as f:
    for line in f:
        line = line.strip()
        if line.startswith('GITHUB_TOKEN=') or line.startswith('GH_TOKEN='):
            gh_token = line.split('=', 1)[1].strip().strip('"').strip("'")
            break
print('Token found:', bool(gh_token), len(gh_token) if gh_token else 0)
if gh_token:
    print('Prefix:', gh_token[:8])
