import json
from collections import Counter

d = json.load(open('output/hunt_MASTER.json', encoding='utf-8'))
print(f"Records: {len(d)}")
pats = Counter(x.get('pattern_name','') for x in d)
real = [x for x in d if not x.get('is_fp_hint')]
crit = [x for x in real if x.get('severity','') == 'CRITICAL']
print(f"Non-FP: {len(real)} | CRITICAL: {len(crit)}")
print("\nTop 20 patterns:")
for p,n in pats.most_common(20):
    print(f"  {n:5d}  {p}")
