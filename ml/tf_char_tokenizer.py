import string

ALL_CHARS = (
    string.ascii_letters +
    string.digits +
    "-_=:/+.@{}[]()<>"
)

char2idx = {c: i + 1 for i, c in enumerate(ALL_CHARS)}
VOCAB_SIZE = len(char2idx) + 1
MAX_LEN = 120

def encode(text):
    seq = [char2idx.get(c, 0) for c in text[:MAX_LEN]]
    return seq + [0] * (MAX_LEN - len(seq))
