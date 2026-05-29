import json
from pathlib import Path
from collections import Counter

merged = json.loads(Path("output/hunt_MERGED.json").read_text(encoding="utf-8"))
validated = json.loads(Path("output/hunt_VALIDATED.json").read_text(encoding="utf-8"))

# Files scanned (unique repo+path combos)
files_scanned = len(set((f.get("repo",""), f.get("path","")) for f in merged))
total_findings = len(merged)
not_fp = [f for f in merged if not f.get("is_fp_hint", False)]
print("Total files scanned (unique repo+path):", files_scanned)
print("Total findings (all):", total_findings)
print("Findings excluding FP hints:", len(not_fp))

val_status = Counter(f.get("validation_status","") for f in validated)
print("Validation summary:", dict(val_status))

valid_keys = [f for f in validated if f.get("validation_status") == "VALID"]
print("VALID keys confirmed:", len(valid_keys))

# Top 5 repos by finding count (excluding FP)
repo_counts = Counter(f.get("repo","?") for f in not_fp)
top5 = repo_counts.most_common(5)
print("\nTop 5 repos by finding count (non-FP):")
for repo, cnt in top5:
    stars = next((f.get("repo_stars","?") for f in not_fp if f.get("repo") == repo), "?")
    print("  " + repo + "  (" + str(cnt) + " findings, stars=" + str(stars) + ")")

print("\nAll VALID keys (masked):")
if not valid_keys:
    print("  None confirmed VALID (all either INVALID, UNKNOWN, or SKIPPED_FP)")
else:
    for f in valid_keys:
        key = f.get("matched_text","")
        masked = key[:10] + "..." + key[-4:] if len(key) > 14 else key
        print("  [" + f.get("pattern_name","") + "] " + masked + " in " + f.get("repo",""))

# Pattern breakdown for non-FP
print("\nPattern breakdown (non-FP, top 10):")
pat_counts = Counter(f.get("pattern_name","") for f in not_fp)
for pat, cnt in pat_counts.most_common(10):
    print("  " + pat + ": " + str(cnt))

# Severity breakdown non-FP
sev_counts = Counter(f.get("severity","") for f in not_fp)
print("\nSeverity breakdown (non-FP):")
for sev in ("CRITICAL","HIGH","MEDIUM"):
    print("  " + sev + ": " + str(sev_counts.get(sev, 0)))
