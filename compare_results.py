import json

FILES = {
    "Regex Only": "benchmark_eval_regex.json",
    "ML Only (Logistic)": "benchmark_eval_ml_logistic.json",
    "ML Only (SVM)": "benchmark_eval_ml_svm.json",
    "ML Only (BiLSTM)": "benchmark_eval_ml_bilstm.json",
    "Hybrid (Regex + Logistic)": "benchmark_eval_hybrid_logistic.json",
    "Hybrid (Regex + SVM)": "benchmark_eval_hybrid_svm.json",
    "Hybrid (Regex + BiLSTM)": "benchmark_eval_hybrid_bilstm.json",
    "Cascade (Entropy + Regex + MLs)": "benchmark_eval_cascade.json"
}

def load(path):
    with open(path, "r") as f:
        return json.load(f)

def compute_metrics(report):
    cm = report["confusion_matrix"]

    tp = cm["true_positives"]
    fp = cm["false_positives"]
    tn = cm["true_negatives"]
    fn = cm["false_negatives"]

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    return {
        "precision": precision * 100,
        "recall": recall * 100,
        "f1": f1 * 100,
        "fp": fp,
        "fn": fn,
        "tests": report["total_tests"]
    }

def main():
    results = {}

    for name, path in FILES.items():
        report = load(path)
        results[name] = compute_metrics(report)

    # Print table header
    print("\n=== FINAL COMPARISON RESULTS ===\n")
    print(f"{'System':35s} {'Prec (%)':>9s} {'Rec (%)':>9s} {'F1 (%)':>9s} {'FP':>6s} {'FN':>6s}")
    print("-" * 80)

    for name, m in results.items():
        print(
            f"{name:35s} "
            f"{m['precision']:9.2f} "
            f"{m['recall']:9.2f} "
            f"{m['f1']:9.2f} "
            f"{m['fp']:6d} "
            f"{m['fn']:6d}"
            # f"{m['avg_ms']:>10s}"
        )

    # Highlight best recall system
    best_recall = max(results.items(), key=lambda x: x[1]["recall"])
    best_f1 = max(results.items(), key=lambda x: x[1]["f1"])

    print("\n=== SUMMARY ===")
    print(f"Best Recall : {best_recall[0]} ({best_recall[1]['recall']:.2f}%)")
    print(f"Best F1     : {best_f1[0]} ({best_f1[1]['f1']:.2f}%)")
    # print(f"Best Latency: {max(results.items(), key=lambda x: x[1]['avg_ms'])[0]}")

if __name__ == "__main__":
    main()
