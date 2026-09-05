# Legitimate: uses safe_load, no dangerous calls.
import yaml

def parse(text):
    return yaml.safe_load(text)
