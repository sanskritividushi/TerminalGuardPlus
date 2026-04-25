from pathlib import Path
import joblib

class MLDetector:
    def __init__(self, model_type="logistic"):
        base = Path(__file__).parent
        models_dir = base / "models"

        if model_type == "logistic":
            self.vectorizer = joblib.load(models_dir / "vectorizer.pkl")
            self.model = joblib.load(models_dir / "ml_model.pkl")
            self.mode = "logistic"

        elif model_type == "svm":
            self.vectorizer = joblib.load(models_dir / "svm_vectorizer.pkl")
            self.model = joblib.load(models_dir / "svm_model.pkl")
            self.mode = "svm"

        else:
            raise ValueError("Invalid model_type")


    def score(self, text: str) -> float:
        X = self.vectorizer.transform([text])

        if self.mode == "logistic":
            return float(self.model.predict_proba(X)[0][1])
        else:
            # SVM decision margin (positive = secret)
            return float(self.model.decision_function(X)[0])
