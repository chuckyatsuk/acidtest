# Vulnerable: deserializes untrusted data.
import pickle
import sys

def load():
    return pickle.loads(sys.stdin.buffer.read())
