from ml_detector import MLDetector

ml = MLDetector()

tests = [
    "git status",
    "export AWS_SECRET_ACCESS_KEY=abcd1234",
    "password=secret123",
    "Hello how are you"
]

for t in tests:
    print(t, "->", ml.score(t))
