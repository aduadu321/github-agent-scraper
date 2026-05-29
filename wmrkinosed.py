"""
Merge all hunt_*.json files into one master dataset and print summary by pattern.
"""
import json, os, glob
from collections import defaultdict

OUTPUT_DIR = 'output'

# Load all hunt JSON files
all_findings = []
seen_dedup = set()  # repo|path|pattern_name

files = sorted(glob.glob(f'{OUTPUT_DIR}/hunt_*.json'))
file_counts = {}
for fp in files:
    try:
        data = json.load(open(fp, encoding='utf-8'))
        added = 0
        for x in data:
            key = f"{x.get('repo')}|{x.get('path')}|{x.get('pattern_name')}"
            if key not in seen_dedup:
                seen_dedup.add(key)
                all_findings.append(x)
                added += 1
        file_counts[os.path.basename(fp)] = (len(data), added)
    except Exception as e:
        print(f"  ERROR reading {fp}: {e}")

print(f"\n=== MASTER MERGE SUMMARY ===")
print(f"Files processed: {len(files)}")
print(f"Total unique findings: {len(all_findings)}")

# By pattern_name
by_pattern = defaultdict(list)
for x in all_findings:
    by_pattern[x.get('pattern_name','unknown')].append(x)

print(f"\nTop 40 patterns by count:")
for pn, items in sorted(by_pattern.items(), key=lambda x:-len(x[1]))[:40]:
    fp_count = sum(1 for i in items if i.get('is_fp_hint'))
    clean = len(items) - fp_count
    sev = items[0].get('severity','?')
    print(f"  {pn:<45} total={len(items):4d}  clean={clean:4d}  fp={fp_count:3d}  [{sev}]")

# By severity
by_sev = defaultdict(int)
by_sev_clean = defaultdict(int)
for x in all_findings:
    sev = x.get('severity','MEDIUM')
    by_sev[sev] += 1
    if not x.get('is_fp_hint'):
        by_sev_clean[sev] += 1

print(f"\nBy severity (total / clean):")
for sev in ['CRITICAL','HIGH','MEDIUM']:
    print(f"  {sev}: {by_sev[sev]} / {by_sev_clean[sev]}")

# By top repo
by_repo = defaultdict(int)
for x in all_findings:
    if not x.get('is_fp_hint'):
        by_repo[x.get('repo','?')] += 1

print(f"\nTop 15 repos with most clean findings:")
for repo, cnt in sorted(by_repo.items(), key=lambda x:-x[1])[:15]:
    print(f"  {cnt:4d}  {repo}")

# Save master
json.dump(all_findings, open(f'{OUTPUT_DIR}/hunt_MASTER.json', 'w', encoding='utf-8'), indent=2)
print(f"\nSaved: {OUTPUT_DIR}/hunt_MASTER.json  ({len(all_findings)} entries)")
