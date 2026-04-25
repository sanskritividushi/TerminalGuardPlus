import os
import tensorflow as tf
import numpy as np
from .tf_char_tokenizer import encode

class TFBiLSTMDetector:
    def __init__(self):
        base_dir = os.path.dirname(__file__)               # .../ml
        model_path = os.path.join(base_dir, "models", "tf_bilstm_model.keras")
        self.model = tf.keras.models.load_model(model_path)

    def score(self, text: str) -> float:
        x = np.array([encode(text)])
        return float(self.model.predict(x, verbose=0)[0][0])
