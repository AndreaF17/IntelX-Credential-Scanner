"""Feature extraction for the credential-confidence model.

Turns a candidate credential dict (as produced by
``credential_extractor.extract_credentials_from_line``) into a fixed-length
numeric feature vector. The features are deliberately interpretable — pattern
type, password shape/entropy, identity shape, and a few strong "this is junk"
signals — so the learned weights stay auditable, which matters for a security
tool.

Pure standard library; no third-party dependencies.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional

# Ordered feature names. The training script and the scorer both rely on this
# exact order, so only ever append new features to the end.
FEATURE_NAMES: List[str] = [
    'pattern_url_delimited',
    'pattern_host_delimited',
    'pattern_email_delimited',
    'pattern_kv_pairs',
    'pattern_window_triplet',
    'identity_is_email',
    'identity_len',
    'identity_all_digits',
    'password_len',
    'password_entropy_bits',
    'password_has_digit',
    'password_has_alpha',
    'password_has_symbol',
    'password_charset_classes',
    'password_all_digits',
    'url_present',
    'url_has_dot',
    'identity_equals_password',
    'password_is_common',
    'line_delimiter_count',
]

# A small embedded list of obviously-weak passwords. Not exhaustive — it only
# needs to flag the most common junk so the model gets a strong negative signal.
COMMON_PASSWORDS = frozenset({
    'password', 'passwd', '123456', '12345678', '123456789', 'qwerty',
    'admin', 'root', 'letmein', 'welcome', 'login', 'changeme', 'test',
    'guest', 'abc123', 'iloveyou', '111111', '000000', 'secret', 'default',
})

_SYMBOL_RE = re.compile(r'[^A-Za-z0-9]')
_DIGIT_RE = re.compile(r'\d')
_ALPHA_RE = re.compile(r'[A-Za-z]')
_UPPER_RE = re.compile(r'[A-Z]')
_LOWER_RE = re.compile(r'[a-z]')
_DELIMITER_RE = re.compile(r'[:;|,\t]')


def shannon_entropy_bits(value: str) -> float:
    """Return the total Shannon entropy of ``value`` in bits (H per char * length)."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    per_char = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return per_char * length


def _charset_classes(value: str) -> int:
    """Count how many of {lower, upper, digit, symbol} appear in ``value``."""
    classes = 0
    if _LOWER_RE.search(value):
        classes += 1
    if _UPPER_RE.search(value):
        classes += 1
    if _DIGIT_RE.search(value):
        classes += 1
    if _SYMBOL_RE.search(value):
        classes += 1
    return classes


def extract_features(candidate: Dict[str, Any], raw_line: Optional[str] = None) -> Dict[str, float]:
    """Compute the named feature dict for a single candidate credential.

    ``raw_line`` is optional context (the source line); when omitted, the
    candidate's ``raw_line``/``canonical`` field is used for line-level features.
    """
    identity = str(candidate.get('identity') or '')
    password = str(candidate.get('password') or '')
    url = str(candidate.get('url') or '')
    pattern = str(candidate.get('pattern') or '')
    line = raw_line if raw_line is not None else str(candidate.get('raw_line') or candidate.get('canonical') or '')

    identity_lower = identity.lower()
    password_lower = password.lower()

    features: Dict[str, float] = {
        'pattern_url_delimited': 1.0 if pattern == 'url_delimited' else 0.0,
        'pattern_host_delimited': 1.0 if pattern == 'host_delimited' else 0.0,
        'pattern_email_delimited': 1.0 if pattern == 'email_delimited' else 0.0,
        'pattern_kv_pairs': 1.0 if pattern == 'kv_pairs' else 0.0,
        'pattern_window_triplet': 1.0 if pattern == 'window_triplet' else 0.0,
        'identity_is_email': 1.0 if '@' in identity else 0.0,
        'identity_len': float(len(identity)),
        'identity_all_digits': 1.0 if identity.isdigit() else 0.0,
        'password_len': float(len(password)),
        'password_entropy_bits': shannon_entropy_bits(password),
        'password_has_digit': 1.0 if _DIGIT_RE.search(password) else 0.0,
        'password_has_alpha': 1.0 if _ALPHA_RE.search(password) else 0.0,
        'password_has_symbol': 1.0 if _SYMBOL_RE.search(password) else 0.0,
        'password_charset_classes': float(_charset_classes(password)),
        'password_all_digits': 1.0 if password.isdigit() else 0.0,
        'url_present': 1.0 if url else 0.0,
        'url_has_dot': 1.0 if '.' in url else 0.0,
        'identity_equals_password': 1.0 if identity_lower and identity_lower == password_lower else 0.0,
        'password_is_common': 1.0 if password_lower in COMMON_PASSWORDS else 0.0,
        'line_delimiter_count': float(len(_DELIMITER_RE.findall(line))),
    }
    return features


def features_to_vector(features: Dict[str, float]) -> List[float]:
    """Project a feature dict onto the canonical ordered vector."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def candidate_to_vector(candidate: Dict[str, Any], raw_line: Optional[str] = None) -> List[float]:
    """Convenience: extract features for a candidate and return the ordered vector."""
    return features_to_vector(extract_features(candidate, raw_line))
