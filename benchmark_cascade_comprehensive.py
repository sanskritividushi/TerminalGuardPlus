"""
TerminalGuard++ Cascade Benchmark
Runs the comprehensive test database through the cascade detector
and produces metrics matching the format from the minor report:
  - Table 5.1: Detection Accuracy Metrics
  - Table 5.2: Performance Metrics
  - Confusion Matrix
  - Category Breakdown
  - Severity Detection Rates
  - Cascade Level Distribution (new for TerminalGuard++)
"""

import json
import time
import sys
import os
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secret_detector import SecretDetector
from config_manager import ConfigManager
from ml.cascade_entropy_detector import CascadeEnsembleDetector
from benchmarkold import BenchmarkTestCase, create_comprehensive_test_database


class CascadeComprehensiveBenchmark:

    def __init__(self):
        self.config = ConfigManager()
        self.regex_detector = SecretDetector(self.config)
        self.cascade = CascadeEnsembleDetector(
            use_bilstm=True,
            use_svm=True,
            use_entropy=True,
            use_regex=True,
        )
        self.results = []
        self.latencies = []

    def run_single_test(self, test: BenchmarkTestCase) -> Dict:
        start = time.perf_counter()

        cascade_result = self.cascade.detect(test.input_text)
        was_detected = cascade_result["decision"]
        cascade_level = cascade_result.get("cascade_level")
        cascade_confidence = cascade_result.get("confidence")
        cascade_reason = cascade_result.get("reasoning")

        # Also get regex hits for type/severity reporting
        regex_hits = self.regex_detector.detect(test.input_text)
        detected_types = [s["type"] for s in regex_hits]
        detected_severities = [s.get("severity", "unknown") for s in regex_hits]

        latency_ms = (time.perf_counter() - start) * 1000

        if test.has_secret and was_detected:
            result_type = "TRUE_POSITIVE"
        elif test.has_secret and not was_detected:
            result_type = "FALSE_NEGATIVE"
        elif not test.has_secret and was_detected:
            result_type = "FALSE_POSITIVE"
        else:
            result_type = "TRUE_NEGATIVE"

        return {
            "input": test.input_text[:100] + ("..." if len(test.input_text) > 100 else ""),
            "category": test.category,
            "expected_secret": test.has_secret,
            "expected_type": test.secret_type,
            "expected_severity": test.severity,
            "was_detected": was_detected,
            "detected_types": detected_types,
            "detected_severities": detected_severities,
            "result_type": result_type,
            "latency_ms": round(latency_ms, 4),
            "correct": result_type in ("TRUE_POSITIVE", "TRUE_NEGATIVE"),
            "cascade_level": cascade_level,
            "cascade_confidence": round(cascade_confidence, 4) if cascade_confidence is not None else None,
            "cascade_reason": cascade_reason,
        }

    def run_benchmark(self, tests: List[BenchmarkTestCase]) -> Dict:
        print(f"\n{'='*80}")
        print("TERMINALGUARD++ CASCADE COMPREHENSIVE BENCHMARK")
        print(f"{'='*80}")
        print(f"Running {len(tests)} test cases through cascade (BiLSTM→SVM→Entropy→Regex)...\n")

        self.results = []
        self.latencies = []

        tp = fp = tn = fn = 0
        category_results = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        severity_detection = defaultdict(lambda: {"detected": 0, "missed": 0})
        cascade_level_counts = defaultdict(int)

        for i, test in enumerate(tests):
            r = self.run_single_test(test)
            self.results.append(r)
            self.latencies.append(r["latency_ms"])

            if r["result_type"] == "TRUE_POSITIVE":
                tp += 1
                category_results[test.category]["tp"] += 1
                if test.severity:
                    severity_detection[test.severity]["detected"] += 1
            elif r["result_type"] == "FALSE_POSITIVE":
                fp += 1
                category_results[test.category]["fp"] += 1
            elif r["result_type"] == "TRUE_NEGATIVE":
                tn += 1
                category_results[test.category]["tn"] += 1
            else:
                fn += 1
                category_results[test.category]["fn"] += 1
                if test.severity:
                    severity_detection[test.severity]["missed"] += 1

            level_key = str(r["cascade_level"]) if r["cascade_level"] is not None else "safe_exit"
            cascade_level_counts[level_key] += 1

            if (i + 1) % 20 == 0:
                print(f"  Processed {i + 1}/{len(tests)} tests...", end="\r")

        print(f"  Completed {len(tests)} tests!     ")

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        specificity = tn / (tn + fp) if (tn + fp) else 0
        fpr = fp / (fp + tn) if (fp + tn) else 0
        fnr = fn / (tp + fn) if (tp + fn) else 0

        lat_sorted = sorted(self.latencies)
        n = len(lat_sorted)

        return {
            "timestamp": datetime.now().isoformat(),
            "detector": "Cascade (BiLSTM + SVM + Entropy + Regex)",
            "total_tests": total,
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
            "accuracy_metrics": {
                "accuracy": round(accuracy * 100, 2),
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "specificity": round(specificity * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "false_positive_rate": round(fpr * 100, 2),
                "false_negative_rate": round(fnr * 100, 2),
            },
            "latency_metrics": {
                "avg_ms": round(sum(self.latencies) / n, 4) if n else 0,
                "min_ms": round(min(self.latencies), 4) if n else 0,
                "max_ms": round(max(self.latencies), 4) if n else 0,
                "p50_ms": round(lat_sorted[int(n * 0.50)], 4) if n else 0,
                "p95_ms": round(lat_sorted[int(n * 0.95)], 4) if n else 0,
                "p99_ms": round(lat_sorted[min(int(n * 0.99), n - 1)], 4) if n else 0,
                "total_time_ms": round(sum(self.latencies), 2),
            },
            "category_breakdown": {k: dict(v) for k, v in category_results.items()},
            "severity_detection": {k: dict(v) for k, v in severity_detection.items()},
            "cascade_level_distribution": dict(cascade_level_counts),
            "detailed_results": self.results,
        }

    def print_report(self, report: Dict):
        cm = report["confusion_matrix"]
        acc = report["accuracy_metrics"]
        lat = report["latency_metrics"]

        print(f"\n{'='*80}")
        print("TERMINALGUARD++ CASCADE — COMPREHENSIVE RESULTS")
        print(f"{'='*80}")

        # --- Test Summary ---
        print(f"\n📋 TEST SUMMARY")
        print(f"-" * 40)
        print(f"  Total Tests:     {report['total_tests']}")
        print(f"  True Positives:  {cm['true_positives']:4d}  (Secrets correctly detected)")
        print(f"  True Negatives:  {cm['true_negatives']:4d}  (Safe content correctly allowed)")
        print(f"  False Positives: {cm['false_positives']:4d}  (Safe content incorrectly blocked)")
        print(f"  False Negatives: {cm['false_negatives']:4d}  (Secrets incorrectly missed)")

        # --- Confusion Matrix (matches Fig 5.2 format) ---
        print(f"\n📊 CONFUSION MATRIX")
        print(f"-" * 40)
        print(f"                   | Predicted Secret | Predicted Safe")
        print(f"  Actual Secret    |     {cm['true_positives']:4d}         |     {cm['false_negatives']:4d}")
        print(f"  Actual Safe      |     {cm['false_positives']:4d}         |     {cm['true_negatives']:4d}")

        # --- Table 5.1: Detection Accuracy Metrics ---
        print(f"\n📈 TABLE 5.1: DETECTION ACCURACY METRICS")
        print(f"-" * 40)
        print(f"  Accuracy:             {acc['accuracy']:6.2f}%")
        print(f"  Precision:            {acc['precision']:6.2f}%")
        print(f"  Recall (Sensitivity): {acc['recall']:6.2f}%")
        print(f"  Specificity:          {acc['specificity']:6.2f}%")
        print(f"  F1 Score:             {acc['f1_score']:6.2f}%")
        print(f"  False Positive Rate:  {acc['false_positive_rate']:6.2f}%")
        print(f"  False Negative Rate:  {acc['false_negative_rate']:6.2f}%")

        # --- Table 5.2: Performance Metrics ---
        throughput = report['total_tests'] / (lat['total_time_ms'] / 1000) if lat['total_time_ms'] > 0 else 0
        print(f"\n⚡ TABLE 5.2: PERFORMANCE METRICS")
        print(f"-" * 40)
        print(f"  Average Latency:  {lat['avg_ms']:8.4f} ms")
        print(f"  Min Latency:      {lat['min_ms']:8.4f} ms")
        print(f"  Max Latency:      {lat['max_ms']:8.4f} ms")
        print(f"  P50 Latency:      {lat['p50_ms']:8.4f} ms")
        print(f"  P95 Latency:      {lat['p95_ms']:8.4f} ms")
        print(f"  P99 Latency:      {lat['p99_ms']:8.4f} ms")
        print(f"  Total Time:       {lat['total_time_ms']:8.2f} ms")
        print(f"  Throughput:       {throughput:.0f} tests/sec")

        # --- Cascade Level Distribution (NEW for TerminalGuard++) ---
        print(f"\n🔄 CASCADE LEVEL DISTRIBUTION")
        print(f"-" * 40)
        for level, count in sorted(report["cascade_level_distribution"].items()):
            pct = count / report["total_tests"] * 100
            bar = "█" * int(pct / 2)
            print(f"  L{level:>10s}: {count:4d} ({pct:5.1f}%) {bar}")

        # --- Category Breakdown ---
        print(f"\n📂 RESULTS BY CATEGORY")
        print(f"-" * 80)
        print(f"  {'Category':<25s} {'TP':>4s} {'FP':>4s} {'TN':>4s} {'FN':>4s} {'Accuracy':>10s}")
        print(f"  {'-'*65}")
        for cat, s in sorted(report["category_breakdown"].items()):
            total = s["tp"] + s["fp"] + s["tn"] + s["fn"]
            a = (s["tp"] + s["tn"]) / total * 100 if total else 0
            print(f"  {cat:<25s} {s['tp']:>4d} {s['fp']:>4d} {s['tn']:>4d} {s['fn']:>4d} {a:>9.1f}%")

        # --- Severity Detection (matches Fig 5.5 format) ---
        print(f"\n🔐 DETECTION BY SEVERITY")
        print(f"-" * 40)
        for sev in ["critical", "high", "medium", "low"]:
            if sev in report["severity_detection"]:
                s = report["severity_detection"][sev]
                total = s["detected"] + s["missed"]
                rate = s["detected"] / total * 100 if total else 0
                print(f"  {sev.upper():10s}: {s['detected']:3d}/{total:3d} detected ({rate:5.1f}%)")

        # --- False Positives ---
        fps = [r for r in report["detailed_results"] if r["result_type"] == "FALSE_POSITIVE"]
        if fps:
            print(f"\n⚠️  FALSE POSITIVES ({len(fps)} total)")
            print(f"-" * 40)
            for r in fps[:15]:
                print(f"  • {r['input']}")
                if r.get("cascade_level"):
                    print(f"    Cascade L{r['cascade_level']} conf={r['cascade_confidence']}")
                if r["detected_types"]:
                    print(f"    Regex matched: {', '.join(r['detected_types'][:3])}")

        # --- False Negatives ---
        fns = [r for r in report["detailed_results"] if r["result_type"] == "FALSE_NEGATIVE"]
        if fns:
            print(f"\n❌ FALSE NEGATIVES ({len(fns)} total)")
            print(f"-" * 40)
            for r in fns[:15]:
                print(f"  • {r['input']}")
                print(f"    Expected: {r['expected_type']} ({r['expected_severity']})")
                if r.get("cascade_reason"):
                    print(f"    Cascade: {r['cascade_reason']}")

        # --- Comparison with old paper ---
        print(f"\n{'='*80}")
        print("COMPARISON: TerminalGuard (Minor) vs TerminalGuard++ (Major)")
        print(f"{'='*80}")
        print(f"  {'Metric':<25s} {'TG (Regex)':>12s} {'TG++ (Cascade)':>15s} {'Delta':>10s}")
        print(f"  {'-'*65}")

        old_metrics = {
            "accuracy": 88.14, "precision": 93.92, "recall": 87.97,
            "specificity": 88.46, "f1_score": 90.85,
            "false_positive_rate": 11.54, "false_negative_rate": 12.03,
        }
        for key, old_val in old_metrics.items():
            new_val = acc.get(key, 0)
            delta = new_val - old_val
            sign = "+" if delta >= 0 else ""
            # For FPR/FNR, negative delta is good
            print(f"  {key:<25s} {old_val:>11.2f}% {new_val:>14.2f}% {sign}{delta:>8.2f}%")

        old_lat = {"avg_ms": 0.1124, "p50_ms": 0.0870, "p95_ms": 0.1635, "p99_ms": 0.3921}
        print(f"\n  {'Latency':<25s} {'TG (Regex)':>12s} {'TG++ (Cascade)':>15s}")
        print(f"  {'-'*55}")
        for key, old_val in old_lat.items():
            new_val = lat.get(key, 0)
            print(f"  {key:<25s} {old_val:>11.4f}  {new_val:>14.4f}")

        print(f"\n{'='*80}")
        print(f"Benchmark completed at {report['timestamp']}")
        print(f"{'='*80}")


def main():
    print("\n🚀 Initializing TerminalGuard++ Cascade Comprehensive Benchmark...")

    tests = create_comprehensive_test_database()
    pos = sum(1 for t in tests if t.has_secret)
    neg = sum(1 for t in tests if not t.has_secret)
    print(f"✅ {len(tests)} test cases ({pos} secrets, {neg} safe)")

    benchmark = CascadeComprehensiveBenchmark()
    report = benchmark.run_benchmark(tests)
    benchmark.print_report(report)

    output_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "benchmark_comprehensive_cascade.json",
    )
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Full report saved to: {output_file}")


if __name__ == "__main__":
    main()
