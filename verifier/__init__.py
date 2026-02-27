"""
verifier – Security verification for skill scripts.

CLI:
    python -m verifier.scan_skill --skill docx-to-pdf
    python -m verifier.scan_skill --all
    python -m verifier.extract  skills/docx-to-pdf
"""

# Lazy imports to avoid RuntimeWarning when running submodules via -m
def extract_from_skill(*args, **kwargs):
    from verifier.extract import extract_from_skill as _f
    return _f(*args, **kwargs)

def scan_one_skill(*args, **kwargs):
    from verifier.scan_skill import scan_one_skill as _f
    return _f(*args, **kwargs)
