import json
import csv

INPUT_FILE = "../benchmark_results_regex.json"
OUTPUT_FILE = "data/ml_dataset.csv"

with open(INPUT_FILE, "r") as f:
    report = json.load(f)

rows = []

for r in report["detailed_results"]:
    text = r["input"]
    label = 1 if r["expected_secret"] else 0
    category = r["category"]
    rows.append((text, label, category))

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["text", "label", "category"])
    writer.writerows(rows)

print(f"ML dataset created with {len(rows)} samples")
