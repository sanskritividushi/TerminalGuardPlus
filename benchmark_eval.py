from typing import List
from benchmark import BenchmarkTestCase

def create_eval_database() -> List[BenchmarkTestCase]:
    tests: List[BenchmarkTestCase] = []

    # ==========================================================
    # 1. UNSEEN POSITIVE SECRETS (250)
    # ==========================================================

    # Auth headers (non-standard)
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                f"Authorization: Token AUTHX{i:04d}9f8e7d6c5b4a3",
                True, None, None, "Eval_Positive"
            )
        )

    # Session / bearer variants
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                f"session-key=abcd{i:03d}.abcd{i:03d}.abcd{i:03d}",
                True, None, None, "Eval_Positive"
            )
        )

    # Base64 credentials (not in regex)
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                f"cred:ZXZhbF9iYXNlNjRfY3JlZF9rZXlfe3{i:03d}f",
                True, None, None, "Eval_Positive"
            )
        )

    # Hash-like secrets
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                f"key_hash=9f8e7d6c5b4a3{i:03d}aa55bb66cc",
                True, None, None, "Eval_Positive"
            )
        )

    # Config secrets
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                f"secrets.production.api={i:03d}xYzZxYzZxYz",
                True, None, None, "Eval_Positive"
            )
        )

    # ==========================================================
    # 2. HARD NEGATIVES (150)
    # ==========================================================

    # Placeholder tokens
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                f"token_example_value_{i:03d}",
                False, None, None, "Eval_Negative"
            )
        )

    # Fake password examples
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                "password=changeme",
                False, None, None, "Eval_Negative"
            )
        )

    # Test / dev API keys
    for i in range(50):
        tests.append(
            BenchmarkTestCase(
                f"sk-test-{i:05d}",
                False, None, None, "Eval_Negative"
            )
        )

    # ==========================================================
    # 3. NATURAL LANGUAGE (100)
    # ==========================================================

    natural_sentences = [
        "Please rotate the API key tomorrow",
        "The credentials are stored securely",
        "This token is only an example",
        "Do not commit secrets to git",
        "The password policy was updated",
        "Contact the admin for access",
        "Secrets should never be logged",
        "Authentication failed due to timeout",
        "This config file contains no secrets",
        "Key rotation is scheduled next week"
    ]

    for i in range(100):
        tests.append(
            BenchmarkTestCase(
                natural_sentences[i % len(natural_sentences)],
                False, None, None, "Eval_Natural"
            )
        )

    # ==========================================================
    # Final sanity check
    # ==========================================================

    assert len(tests) == 500, f"Expected 500 eval tests, got {len(tests)}"
    return tests
