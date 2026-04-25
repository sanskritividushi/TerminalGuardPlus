from ml.tf_dataset import load_dataset
from ml.tf_bilstm_model import build_model

X, y = load_dataset("data/ml_dataset.csv")

model = build_model()
model.summary()

model.fit(
    X, y,
    epochs=5,
    batch_size=64,
    validation_split=0.2
)

model.save("tf_bilstm_model.keras")
print("✅ TensorFlow BiLSTM model saved")
