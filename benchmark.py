#!/usr/bin/env python3
"""
TerminalGuard Benchmark Suite (Scaled)
Runs large-scale benchmark tests (1000+ cases) with deterministic ground truth
"""
from ml.ml_detector import MLDetector

import json
import time
import sys
import os
import random
import string
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

MODE = "cascade"  # Change as needed
OUTPUT_FILE = f"benchmark_eval_{MODE}.json"

# options:
# "regex"
# "ml_logistic"
# "ml_svm"
# "hybrid_logistic"
# "hybrid_svm"
# "ml_bilstm"
# "hybrid_bilstm"
# "cascade"

from ml.tf_bilstm_detector import TFBiLSTMDetector
from ml.cascade_entropy_detector import CascadeEnsembleDetector 


# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secret_detector import SecretDetector
from config_manager import ConfigManager


# =========================
# Utility generators
# =========================

def rand_base64(n=40):
    chars = string.ascii_letters + string.digits + "+/="
    return "".join(random.choices(chars, k=n))

def rand_hex(n=32):
    return "".join(random.choices("abcdef0123456789", k=n))

def rand_alnum(n=24):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


# =========================
# Test Case class
# =========================

class BenchmarkTestCase:
    def __init__(self, input_text: str, has_secret: bool,
                 secret_type: str = None, severity: str = None,
                 category: str = "general"):
        self.input_text = input_text
        self.has_secret = has_secret
        self.secret_type = secret_type
        self.severity = severity
        self.category = category


# =========================
# Test database generator
# =========================

def create_test_database() -> List[BenchmarkTestCase]:
    tests: List[BenchmarkTestCase] = []

    # ---------- AWS KEYS ----------
    for _ in range(100):
        tests.extend([
            BenchmarkTestCase(
                f"AKIA{rand_alnum(16)}",
                True, "aws_access_key", "critical", "AWS"
            ),
            BenchmarkTestCase(
                f"aws_secret_access_key={rand_base64()}",
                True, "aws_secret_key", "critical", "AWS"
            ),
            BenchmarkTestCase(
                f"export AWS_SECRET_ACCESS_KEY='{rand_base64()}'",
                True, "aws_secret_key", "critical", "AWS"
            ),
        ])

    # ---------- DATABASE URIs ----------
    for _ in range(100):
        pwd = rand_alnum(12)
        tests.extend([
            BenchmarkTestCase(
                f"postgres://admin:{pwd}@localhost:5432/db",
                True, "postgres_uri", "critical", "Database"
            ),
            BenchmarkTestCase(
                f"mysql://root:{pwd}@db.server.com/prod",
                True, "mysql_uri", "critical", "Database"
            ),
            BenchmarkTestCase(
                f"redis://default:{pwd}@redis.server.com:6379",
                True, "redis_uri", "high", "Database"
            ),
        ])

    # ---------- API KEYS ----------
    for _ in range(150):
        tests.extend([
            BenchmarkTestCase(
                f"sk-proj-{rand_alnum(40)}",
                True, "openai_api_key", "critical", "API Keys"
            ),
            BenchmarkTestCase(
                f"ghp_{rand_alnum(36)}",
                True, "github_token", "critical", "API Keys"
            ),
            BenchmarkTestCase(
                f"glpat-{rand_alnum(20)}",
                True, "gitlab_token", "critical", "API Keys"
            ),
        ])

    # ---------- PASSWORD ASSIGNMENTS ----------
    for _ in range(100):
        pwd = rand_alnum(10)
        tests.extend([
            BenchmarkTestCase(
                f"password={pwd}",
                True, "password_assignment", "high", "Passwords"
            ),
            BenchmarkTestCase(
                f"DB_PASSWORD={pwd}",
                True, "db_password", "critical", "Passwords"
            ),
        ])

    # ---------- PRIVATE / CRYPTO KEYS ----------
    for _ in range(50):
        tests.extend([
            BenchmarkTestCase(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
                True, "ssh_private_key", "critical", "Crypto Keys"
            ),
            BenchmarkTestCase(
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                True, "ssh_private_key", "critical", "Crypto Keys"
            ),
        ])

    # ---------- TOKENS ----------
    for _ in range(50):
        tests.append(
            BenchmarkTestCase(
                f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{rand_base64(30)}.{rand_base64(30)}",
                True, "jwt_token", "high", "Tokens"
            )
        )

    # ---------- SAFE COMMANDS (NEGATIVES) ----------
    for _ in range(300):
        tests.extend([
            BenchmarkTestCase("git status", False, None, None, "Safe Commands"),
            BenchmarkTestCase("ls -la", False, None, None, "Safe Commands"),
            BenchmarkTestCase("docker ps", False, None, None, "Safe Commands"),
            BenchmarkTestCase("npm run dev", False, None, None, "Safe Commands"),
        ])

    # ---------- PLACEHOLDERS (NEGATIVES) ----------
    for _ in range(200):
        tests.extend([
            BenchmarkTestCase(
                f"API_KEY=your_api_key_{rand_alnum(5)}",
                False, None, None, "Placeholders"
            ),
            BenchmarkTestCase(
                f"user{rand_alnum(3)}@example.com",
                False, None, None, "Placeholders"
            ),
            BenchmarkTestCase(
                "https://example.com/api",
                False, None, None, "Placeholders"
            ),
        ])

    # ---------- EDGE CASES ----------
    for _ in range(50):
        tests.extend([
            BenchmarkTestCase(
                "password=abc123",
                True, "password_assignment", "high", "Edge Cases"
            ),
            BenchmarkTestCase(
                "pwd=test",
                False, None, None, "Edge Cases"
            ),
        ])

    # Natural language negatives (IMPORTANT for ML)
    natural_sentences = [
        "Hello how are you",
        "Please review the document",
        "The meeting is scheduled for tomorrow",
        "Can you send me the file",
        "Thanks for your help",
        "Let me know if you need anything",
        "We will deploy this tomorrow",
        "The build failed due to timeout",
    ]

    for _ in range(200):
        for s in natural_sentences:
            tests.append(
                BenchmarkTestCase(
                    s,
                    False,
                    None,
                    None,
                    "Natural Language"
                )
            )
    # ==========================================================
    # ML-ONLY POSITIVES (Regex-unknown secrets)
    # These SHOULD be detected by ML but NOT by regex
    # ==========================================================
    for _ in range(200):
        tests.extend([
            BenchmarkTestCase(
                f"token_{rand_alnum(48)}",
                True,
                "generic_token",
                "high",
                "ML_Only_Positive"
            ),
            BenchmarkTestCase(
                f"auth:{rand_hex(64)}",
                True,
                "hex_auth_token",
                "high",
                "ML_Only_Positive"
            ),
            BenchmarkTestCase(
                f"secret={rand_base64(60)}",
                True,
                "generic_secret",
                "high",
                "ML_Only_Positive"
            ),
        ])
        # ==========================================================
    # HARD NEGATIVES (Look like secrets but are NOT)
    # Prevents ML-only false confidence
    # ==========================================================
    for _ in range(300):
        tests.extend([
            BenchmarkTestCase(
                f"example_token_{rand_alnum(32)}",
                False,
                None,
                None,
                "Hard_Negative"
            ),
            BenchmarkTestCase(
                "password=example123",
                False,
                None,
                None,
                "Hard_Negative"
            ),
            BenchmarkTestCase(
                f"sk-EXAMPLE-{rand_alnum(20)}",
                False,
                None,
                None,
                "Hard_Negative"
            ),
        ])

    assert len(tests) >= 1000, f"Benchmark too small: {len(tests)} tests"
    return tests


# =========================
# Benchmark runner
# =========================

# class TerminalGuardBenchmark:
#     def __init__(self):
#         self.config = ConfigManager()
#         self.detector = SecretDetector(self.config)
#         self.ml=MLDetector()
#         self.results = []
#         self.latencies = []

    # def run_single_test(self, test: BenchmarkTestCase) -> Dict:
    #     start = time.perf_counter()
    #     detected = self.detector.detect(test.input_text)
    #     latency = (time.perf_counter() - start) * 1000

    #     was_detected = len(detected) > 0
        

    #     if test.has_secret and was_detected:
    #         result_type = "TRUE_POSITIVE"
    #     elif test.has_secret and not was_detected:
    #         result_type = "FALSE_NEGATIVE"
    #     elif not test.has_secret and was_detected:
    #         result_type = "FALSE_POSITIVE"
    #     else:
    #         result_type = "TRUE_NEGATIVE"

    #     return {
    #         "input": test.input_text,
    #         "category": test.category,
    #         "expected_secret": test.has_secret,
    #         "expected_type": test.secret_type,
    #         "expected_severity": test.severity,
    #         "was_detected": was_detected,
    #         "result_type": result_type,
    #         "latency_ms": round(latency, 4),
    #         "correct": result_type in ("TRUE_POSITIVE", "TRUE_NEGATIVE")
    #     }
class TerminalGuardBenchmark:
    def __init__(self):
        self.config = ConfigManager()
        self.detector = SecretDetector(self.config)
        self.ml = None

        if MODE in ("ml_logistic", "hybrid_logistic"):
            self.ml = MLDetector("logistic")
        elif MODE in ("ml_svm", "hybrid_svm"):
            self.ml = MLDetector("svm")
        elif MODE in ("ml_bilstm", "hybrid_bilstm"):
            self.ml = TFBiLSTMDetector()
        elif MODE == "cascade":  # NEW
            # Initialize cascade ensemble
            self.cascade = CascadeEnsembleDetector(
                use_bilstm=True,
                use_svm=True,
                use_entropy=True,
                use_regex=True,
                bilstm_bounds=(0.2, 0.8),
                svm_bounds=(0.25, 0.75),
                entropy_threshold=4.5,
            )

        self.results = []
        self.latencies = []

    def run_single_test(self, test: BenchmarkTestCase) -> Dict:
        start = time.perf_counter()
        regex_hits = self.detector.detect(test.input_text)
        regex_detected = len(regex_hits) > 0

        ml_score = None
        cascade_level = None  # NEW
        cascade_confidence = None  # NEW
        cascade_reason = None  # NEW

        if MODE == "cascade":  # NEW: Cascade branch
            # Use cascade ensemble directly
            cascade_result = self.cascade.detect(test.input_text)
            was_detected = cascade_result["decision"]
            cascade_level = cascade_result.get("cascade_level")
            cascade_confidence = cascade_result.get("confidence")
            cascade_reason = cascade_result.get("reasoning")
        else:
            if self.ml:
                ml_score = self.ml.score(test.input_text)

            if MODE == "regex":
                was_detected = regex_detected

            elif MODE == "ml_logistic":
                was_detected = ml_score > 0.8

            elif MODE == "ml_svm":
                was_detected = ml_score > 0.0

            elif MODE == "hybrid_logistic":
                was_detected = regex_detected or (ml_score > 0.8)

            elif MODE == "hybrid_svm":
                was_detected = regex_detected or (ml_score > 0.0)
            elif MODE == "ml_bilstm":
                was_detected = self.ml.score(test.input_text) > 0.5

            elif MODE == "hybrid_bilstm":
                was_detected = regex_detected or (self.ml.score(test.input_text) > 0.5)

            else:
                raise ValueError("Invalid MODE")


        # # Regex detection
        # detected = self.detector.detect(test.input_text)
        # regex_detected = len(detected) > 0

        # regex_safe = any(
        #     hit.get("type") == "whitelist"
        #     for hit in detected
        # )
        # # ML detection
        # ml_score = self.ml.score(test.input_text)

        latency = (time.perf_counter() - start) * 1000

        # # Hybrid decision
        # # was_detected = regex_detected or (ml_score > 0.80)
        # if regex_detected and not regex_safe:
        #     was_detected = True
        # elif regex_safe:
        #     was_detected = False
        # elif ml_score > 0.85:
        #     was_detected = True
        # else:
        #     was_detected = False


        # Confusion matrix logic
        if test.has_secret and was_detected:
            result_type = "TRUE_POSITIVE"
        elif test.has_secret and not was_detected:
            result_type = "FALSE_NEGATIVE"
        elif not test.has_secret and was_detected:
            result_type = "FALSE_POSITIVE"
        else:
            result_type = "TRUE_NEGATIVE"

        return {
            "input": test.input_text,
            "category": test.category,
            "expected_secret": test.has_secret,
            "expected_type": test.secret_type,
            "expected_severity": test.severity,
            "was_detected": was_detected,
            "result_type": result_type,
            "latency_ms": round(latency, 4),
            "ml_score": round(ml_score, 4) if ml_score is not None else None,
            # NEW: cascade-specific fields
            "cascade_level": cascade_level,
            "cascade_confidence": round(cascade_confidence, 4) if cascade_confidence is not None else None,
            "cascade_reason": cascade_reason,
            "correct": result_type in ("TRUE_POSITIVE", "TRUE_NEGATIVE"),
        }


    def run_benchmark(self, tests: List[BenchmarkTestCase]) -> Dict:
        tp = fp = tn = fn = 0

        for test in tests:
            r = self.run_single_test(test)
            self.results.append(r)
            self.latencies.append(r["latency_ms"])

            if r["result_type"] == "TRUE_POSITIVE":
                tp += 1
            elif r["result_type"] == "FALSE_POSITIVE":
                fp += 1
            elif r["result_type"] == "TRUE_NEGATIVE":
                tn += 1
            else:
                fn += 1

        total = tp + fp + tn + fn
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        accuracy = (tp + tn) / total if total else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0

        return {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total,
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn
            },
            "accuracy_metrics": {
                "accuracy": round(accuracy * 100, 2),
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1_score": round(f1 * 100, 2),
            },
            "latency_metrics": {
                "avg_ms": round(sum(self.latencies) / len(self.latencies), 4),
                "p95_ms": round(sorted(self.latencies)[int(len(self.latencies) * 0.95)], 4)
            },
            "detailed_results": self.results
        }


# =========================
# Main
# =========================

def main():
    print("🚀 Running TerminalGuard Scaled Benchmark")

    # tests = create_test_database()
    from benchmark_eval import create_eval_database
    tests = create_eval_database()

    print(f"✅ Generated {len(tests)} test cases")

    benchmark = TerminalGuardBenchmark()
    report = benchmark.run_benchmark(tests)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    print(f"📄 Results written to {OUTPUT_FILE}")



if __name__ == "__main__":
    main()
