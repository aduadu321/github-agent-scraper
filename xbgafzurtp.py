import json
d = json.load(open('output/hunt_openai.json', encoding='utf-8'))
print(f"Total findings: {len(d)}")
sevs = {}
for x in d:
    sevs[x["severity"]] = sevs.get(x["severity"], 0) + 1
print("Severity:", sevs)
repos = len(set(x["repo"] for x in d))
print(f"Unique repos: {repos}")
fps = sum(1 for x in d if x.get("is_fp_hint"))
print(f"FP hints: {fps}")
print(f"Non-FP findings: {len(d) - fps}")
patterns = {}
for x in d:
    patterns[x["pattern_name"]] = patterns.get(x["pattern_name"], 0) + 1
print("Patterns:", patterns)
