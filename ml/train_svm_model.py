import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import classification_report
import joblib

# Load dataset
df = pd.read_csv("data/ml_dataset.csv")

X_train, X_test, y_train, y_test = train_test_split(
    df["text"],
    df["label"],
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

# Character-level TF-IDF
vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 6),
    max_features=5000
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# SVM model
model = LinearSVC(class_weight="balanced")

model.fit(X_train_vec, y_train)
y_pred = model.predict(X_test_vec)

print(classification_report(y_test, y_pred))

# Save
joblib.dump(vectorizer, "svm_vectorizer.pkl")
joblib.dump(model, "svm_model.pkl")

print("SVM model saved.")

