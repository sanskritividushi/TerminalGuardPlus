import tensorflow as tf
from tensorflow.keras import layers, models
from ml.tf_char_tokenizer import VOCAB_SIZE, MAX_LEN

def build_model():
    model = models.Sequential([
        layers.Embedding(
            input_dim=VOCAB_SIZE,
            output_dim=64,
            input_length=MAX_LEN,
            mask_zero=True
        ),
        layers.Bidirectional(layers.LSTM(64)),
        layers.Dense(1, activation="sigmoid")
    ])

    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"]
    )
    return model
