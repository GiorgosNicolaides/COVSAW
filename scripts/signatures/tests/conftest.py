import os
import sys

# Path to scripts/signatures
here     = os.path.abspath(os.path.dirname(__file__))
sig_root = os.path.abspath(os.path.join(here, ".."))

# Prepend so pytest can do `import detect_insecure_signature_algos` etc.
sys.path.insert(0, sig_root)
