"""Scan hunt_financial.json results with patterns and save findings."""
import sys, json
sys.path.insert(0, r"C:\Users\aduad\tools\github-scraper")
from patterns import scan_text, PATTERNS

with open(r"C:\Users\aduad\tools\github-scraper\output\hunt_financial.json", encoding="utf-8") as f:
    results = json.load(f)

findings = []
SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}

for item in results:
    # scan snippet / text_matches if available
    text = item.get("snippet") or item.get("content") or ""
    if not text:
        # try text_matches
        tms = item.get("text_matches", [])
        if tms:
            text = " ".join(tm.get("fragment", "") for tm in tms)
    if not text:
        continue
    filename = item.get("path", "") or item.get("name", "")
    hits = scan_text(text, filename)
    for h in hits:
        if SEVERITY_ORDER.get(h["severity"], 0) < 2:  # HIGH+
            continue
        findings.append({
            "repo": item.get("repo") or item.get("repository", {}).get("full_name", "?"),
            "path": filename,
            "html_url": item.get("html_url", ""),
            "pattern_name": h["pattern_name"],
            "severity": h["severity"],
            "matched": h["matched"][:60] + "..." if len(h["matched"]) > 60 else h["matched"],
            "is_fp_hint": h["is_fp_hint"],
            "line_no": h["line_no"],
        })

print(f"Scanned {len(results)} result snippets")
print(f"Findings (HIGH+): {len(findings)}")
print()

# Group by severity
for sev in ["CRITICAL", "HIGH"]:
    sev_hits = [f for f in findings if f["severity"] == sev]
    real_hits = [f for f in sev_hits if not f["is_fp_hint"]]
    print(f"  {sev}: {len(sev_hits)} total, {len(real_hits)} non-FP")
    for f in real_hits[:5]:
        masked = f["matched"]
        if len(masked) > 20:
            masked = masked[:8] + "***" + masked[-4:]
        print(f"    [{f['severity']}] {f['pattern_name']} in {f['repo']} | {masked}")

out_path = r"C:\Users\aduad\tools\github-scraper\output\hunt_financial_secrets.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(findings, f, ensure_ascii=False, indent=2)
print(f"\nSaved to {out_path}")
