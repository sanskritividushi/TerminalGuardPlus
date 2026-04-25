import pandas as pd
import numpy as np
from ml.tf_char_tokenizer import encode, MAX_LEN

def load_dataset(csv_path):
    df = pd.read_csv(csv_path)
    X = np.array([encode(t) for t in df["text"]])
    y = df["label"].values
    return X, y
