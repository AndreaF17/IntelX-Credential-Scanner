#!/usr/bin/env python3
"""Train the credential-confidence model.

The model predicts P(a candidate is a real credential) and is an optional,
drop-in replacement for the hand-tuned ``calculate_confidence`` heuristic.

Two sources of labeled data, combinable:

  * ``--synthetic N`` — generate N deterministic synthetic labeled lines
    (positives across all patterns + hard negatives that still extract a
    candidate). Self-contained; needs no external corpus. This is the default.
  * ``--input FILE …`` — real leak/dump text. Labels are derived by *weak
    supervision*: candidates the existing heuristic is very confident about
    (and which aren't trivial) become positives; clearly weak/trivial
    candidates become negatives; the ambiguous middle band is dropped so the
    training labels stay clean.

A held-out split is always evaluated and the metrics are baked into the model
file so you can see how it scored at training time.

Pure standard library.
"""
from __future__ import annotations

import argparse
import random
import sys
from typing import Dict, List, Optional, Sequence, Tuple

from custom.confidence_features import COMMON_PASSWORDS, candidate_to_vector
from custom.confidence_model import LogisticRegression
from custom.credential_extractor import extract_credentials_from_line

# Weak-supervision thresholds over the *heuristic* confidence.
WEAK_POS_THRESHOLD = 0.85
WEAK_NEG_THRESHOLD = 0.60

Example = Tuple[List[float], int]


# ── Trivial-credential heuristic (shared by labeling) ────────────────────────
def is_trivial_candidate(candidate: Dict[str, object]) -> bool:
    """Return True for candidates that are almost certainly not real credentials."""
    identity = str(candidate.get('identity') or '').lower()
    password = str(candidate.get('password') or '')
    if not identity or not password:
        return True
    if identity == password.lower():
        return True
    if password.lower() in COMMON_PASSWORDS:
        return True
    if len(password) < 4:
        return True
    return False


# ── Synthetic data generation ────────────────────────────────────────────────
_HOSTS = ['portal.acme.com', 'login.example.org', 'vpn.corp.net', 'mail.test.io',
          'shop.brand.co', 'app.startup.dev', 'intranet.bigco.com', 'cloud.host.eu']
_USERS = ['jsmith', 'a.rossi', 'admin01', 'm_jones', 'carla.bianchi', 'dev_ops',
          'support', 'k.nguyen', 'paolo', 'helpdesk']
_DOMAINS = ['gmail.com', 'icloud.com', 'corp.com', 'outlook.com', 'proton.me']
_STRONG_PW = ['Str0ng!Pass9', 'Tr0ub4dor&3', 'Wint3r#2023', 'V3ry$ecret77',
              'Qx7!mLp2zR', 'Summer@2024!', 'p@ssW0rd2023', 'Zeta9$Kappa1']


def _rand_strong_pw(rng: random.Random) -> str:
    return rng.choice(_STRONG_PW) + str(rng.randint(0, 99))


def generate_positive_line(rng: random.Random) -> str:
    """Produce a realistic credential line of a randomly chosen format."""
    host = rng.choice(_HOSTS)
    user = rng.choice(_USERS)
    pw = _rand_strong_pw(rng)
    fmt = rng.randint(0, 3)
    if fmt == 0:  # url_delimited
        return f"https://{host}/login:{user}:{pw}"
    if fmt == 1:  # host_delimited
        return f"{host}:{user}:{pw}"
    if fmt == 2:  # email_delimited
        email = f"{user}@{rng.choice(_DOMAINS)}"
        return f"{email}:{pw}"
    # kv_pairs
    return f"url={host} user={user} password={pw}"


def generate_negative_line(rng: random.Random) -> str:
    """Produce a junk line that nonetheless tends to extract a candidate."""
    fmt = rng.randint(0, 6)
    if fmt == 0:  # trivial equal creds
        u = rng.choice(['admin', 'root', 'test', 'user', 'guest'])
        return f"{rng.choice(_HOSTS)}:{u}:{u}"
    if fmt == 1:  # common password
        return f"{rng.choice(_HOSTS)}:{rng.choice(_USERS)}:{rng.choice(list(COMMON_PASSWORDS))}"
    if fmt == 2:  # version/build string
        return f"nginx:{rng.randint(1, 9)}.{rng.randint(0, 30)}:stable"
    if fmt == 3:  # log-ish timestamp
        return f"{rng.randint(2019, 2024)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}:INFO:started"
    if fmt == 4:  # config triple
        return f"timeout:{rng.randint(10, 90)}:retries"
    if fmt == 5:  # numeric/ip-ish junk
        return f"{rng.randint(1, 255)}:{rng.randint(1, 255)}:{rng.randint(1, 255)}"
    # short numeric password (weak)
    return f"{rng.choice(_HOSTS)}:{rng.choice(_USERS)}:{rng.randint(1, 999)}"


def build_synthetic_dataset(n: int, seed: int = 7) -> List[Example]:
    """Generate ``n`` labeled examples (~half positive, half negative).

    Each generated line is run through the real extractor so the feature vectors
    reflect production extraction; lines that yield no candidate are skipped.
    """
    rng = random.Random(seed)
    examples: List[Example] = []
    attempts = 0
    target = max(n, 2)
    while len(examples) < target and attempts < target * 20:
        attempts += 1
        positive = (len(examples) % 2 == 0)
        line = generate_positive_line(rng) if positive else generate_negative_line(rng)
        candidates = extract_credentials_from_line(line, mode='aggressive')
        if not candidates:
            continue
        candidate = candidates[0]
        label = 1 if (positive and not is_trivial_candidate(candidate)) else 0
        examples.append((candidate_to_vector(candidate, line), label))
    return examples


# ── Weak supervision over real corpora ───────────────────────────────────────
def label_line_weak(line: str) -> List[Example]:
    """Derive weakly-labeled examples from one real dump line. May return []."""
    out: List[Example] = []
    for candidate in extract_credentials_from_line(line, mode='aggressive'):
        confidence = float(candidate.get('confidence', 0.0))
        trivial = is_trivial_candidate(candidate)
        if confidence >= WEAK_POS_THRESHOLD and not trivial:
            label: Optional[int] = 1
        elif confidence <= WEAK_NEG_THRESHOLD or trivial:
            label = 0
        else:
            label = None  # ambiguous: drop
        if label is not None:
            out.append((candidate_to_vector(candidate, line), label))
    return out


def build_dataset_from_files(paths: Sequence[str]) -> List[Example]:
    """Build a weakly-labeled dataset from one or more text files."""
    examples: List[Example] = []
    for path in paths:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line:
                    examples.extend(label_line_weak(line))
    return examples


# ── Evaluation ───────────────────────────────────────────────────────────────
def evaluate(model: LogisticRegression, examples: Sequence[Example], threshold: float = 0.5) -> Dict[str, float]:
    """Compute accuracy/precision/recall/F1 for ``model`` over ``examples``."""
    tp = fp = tn = fn = 0
    for vector, label in examples:
        pred = 1 if model.predict_proba_vector(vector) >= threshold else 0
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
        elif pred == 0 and label == 0:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        'accuracy': round(accuracy, 4),
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'support': float(total),
    }


def split_dataset(examples: List[Example], test_fraction: float, seed: int) -> Tuple[List[Example], List[Example]]:
    """Shuffle and split into (train, test)."""
    shuffled = list(examples)
    random.Random(seed).shuffle(shuffled)
    n_test = int(len(shuffled) * test_fraction)
    return shuffled[n_test:], shuffled[:n_test]


def train_and_evaluate(
    examples: List[Example],
    *,
    test_fraction: float = 0.25,
    seed: int = 7,
    epochs: int = 400,
    learning_rate: float = 0.1,
    l2: float = 0.001,
) -> Tuple[LogisticRegression, Dict[str, float]]:
    """Train a model on a split of ``examples`` and return (model, held-out metrics)."""
    if len(examples) < 4:
        raise ValueError('need at least 4 labeled examples to train and evaluate')
    train_set, test_set = split_dataset(examples, test_fraction, seed)
    if not test_set:  # tiny datasets: evaluate on train as a fallback
        test_set = train_set
    X = [vec for vec, _ in train_set]
    y = [label for _, label in train_set]
    model = LogisticRegression(epochs=epochs, learning_rate=learning_rate, l2=l2, seed=seed)
    model.fit(X, y)
    metrics = evaluate(model, test_set)
    model.metrics = metrics
    return model, metrics


# ── CLI ──────────────────────────────────────────────────────────────────────
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse trainer command-line arguments."""
    parser = argparse.ArgumentParser(description='Train the credential-confidence model')
    parser.add_argument('-i', '--input', nargs='*', default=None,
                        help='Real dump text file(s) for weak-supervision labeling')
    parser.add_argument('-s', '--synthetic', type=int, default=600,
                        help='Number of synthetic labeled examples to add (default: 600; 0 to disable)')
    parser.add_argument('-o', '--out', type=str, default='models/confidence_model.json',
                        help='Output model path (default: models/confidence_model.json)')
    parser.add_argument('--test-fraction', type=float, default=0.25, help='Held-out fraction for evaluation')
    parser.add_argument('--epochs', type=int, default=400, help='Gradient-descent epochs')
    parser.add_argument('--seed', type=int, default=7, help='Random seed')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Trainer entry point. Returns a process exit code."""
    args = parse_args(argv)

    examples: List[Example] = []
    if args.input:
        examples.extend(build_dataset_from_files(args.input))
        print(f"[INFO] Weak-labeled {len(examples)} examples from {len(args.input)} file(s)")
    if args.synthetic > 0:
        synth = build_synthetic_dataset(args.synthetic, seed=args.seed)
        examples.extend(synth)
        print(f"[INFO] Generated {len(synth)} synthetic examples")

    if len(examples) < 4:
        print('[ERROR] Not enough labeled examples to train. Provide --input or raise --synthetic.', file=sys.stderr)
        return 1

    positives = sum(1 for _, label in examples if label == 1)
    print(f"[INFO] Dataset: {len(examples)} examples ({positives} positive, {len(examples) - positives} negative)")

    model, metrics = train_and_evaluate(
        examples, test_fraction=args.test_fraction, seed=args.seed, epochs=args.epochs
    )
    model.save(args.out)

    print(f"[INFO] Saved model -> {args.out}")
    print(
        "[INFO] Held-out metrics - "
        f"accuracy: {metrics['accuracy']}, precision: {metrics['precision']}, "
        f"recall: {metrics['recall']}, f1: {metrics['f1']}, support: {int(metrics['support'])}"
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
