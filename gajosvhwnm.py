import urllib.request, json
from pathlib import Path

env_file = Path(r"C:\Users\aduad\tools\llm-rotate\.env")
token = ""
if env_file.exists():
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == "GITHUB_TOKEN":
            token = v.strip().strip('"').strip("'")
            break
print(f"Token found: {bool(token)}, length={len(token)}")
req = urllib.request.Request(
    "https://api.github.com/rate_limit",
    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
)
with urllib.request.urlopen(req, timeout=10) as r:
    data = json.loads(r.read())
print("search remaining:", data["resources"]["search"]["remaining"])
print("core remaining:", data["resources"]["core"]["remaining"])
print("reset search at (unix):", data["resources"]["search"]["reset"])
