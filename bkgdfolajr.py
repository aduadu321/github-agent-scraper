import sys
sys.path.insert(0, r"C:\Users\aduad\tools\github-scraper")
from scraper import search
import json, os

os.makedirs("output", exist_ok=True)

financial_dorks = [
    "PAYPAL_CLIENT_SECRET filename:.env",
    "STRIPE_SECRET_KEY sk_live_ filename:.env",
    "payment gateway api_key secret filename:.env",
    "credit card number cvv test filename:config",
    "ADYEN_API_KEY AQE filename:.env",
]

all_results = []
for q in financial_dorks:
    results = search(q, kind="code", max_results=10)
    all_results.extend(results)
    print(f"Query '{q}': {len(results)} results")

with open(r"output\hunt_financial.json", "w", encoding="utf-8") as f:
    json.dump(all_results, f, ensure_ascii=False, indent=2)
print(f"Total: {len(all_results)} code results saved")
