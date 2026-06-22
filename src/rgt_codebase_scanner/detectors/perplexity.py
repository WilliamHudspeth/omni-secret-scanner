# SPDX-License-Identifier: MIT
"""Perplexity-based secret detection via repo-trained Markov model.

Trains an n-gram character model on safe-looking source code, then flags
tokens whose perplexity exceeds a per-language threshold — catching
high-entropy strings that don't match known code patterns.

Activated via --perplexity flag.
"""

from __future__ import annotations

import math
import pickle
import re
from collections import defaultdict
from pathlib import Path


class CharMarkovModel:
    """Character-level Markov model with backoff smoothing.

    Uses n=5 by default to capture patterns like AKIA, ghp_, sk- etc.
    Kneser-Ney-style backoff prevents the 1e-6 probability cliff.
    """

    def __init__(self, n: int = 5):
        self.n = n
        # {context: {char: count}}
        self.ngrams: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # {context: total_count}
        self.totals: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, corpus: str, exclude_spans: list[tuple[int, int]] | None = None):
        """Train on *corpus*, skipping ranges in *exclude_spans*.

        exclude_spans: list of (start_byte, end_byte) ranges to zero out
        before training — use this to strip known secret-bearing regions.
        """
        if exclude_spans:
            chars = list(corpus)
            for start, end in sorted(exclude_spans, reverse=True):
                for i in range(start, min(end, len(chars))):
                    chars[i] = " "
            corpus = "".join(chars)

        padded = " " * (self.n - 1) + corpus
        for i in range(len(padded) - self.n + 1):
            ctx = padded[i : i + self.n - 1]
            ch = padded[i + self.n - 1]
            self.ngrams[ctx][ch] += 1
            self.totals[ctx] += 1

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def logprob(self, text: str) -> float:
        """Average log2-probability per character (lower = more surprising)."""
        if len(text) < self.n:
            return -999.0
        padded = " " * (self.n - 1) + text
        lp = 0.0
        count = 0
        for i in range(len(padded) - self.n + 1):
            ctx = padded[i : i + self.n - 1]
            ch = padded[i + self.n - 1]
            char_count = self.ngrams[ctx].get(ch, 0)
            total = self.totals[ctx]
            # backoff smoothing
            prob = (char_count + 0.1) / (total + 0.1 * 256) if total else 1.0 / 256
            lp += math.log2(max(prob, 1e-15))
            count += 1
        return lp / max(1, count)

    def perplexity(self, text: str) -> float:
        """Perplexity (2 ** -logprob). Higher = more anomalous."""
        return 2.0 ** (-self.logprob(text))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        data = {"n": self.n, "ngrams": {k: dict(v) for k, v in self.ngrams.items()}}
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def load(self, path: str | Path) -> None:
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.n = data["n"]
        for ctx, counts in data["ngrams"].items():
            self.ngrams[ctx] = defaultdict(int, counts)
            self.totals[ctx] = sum(counts.values())


# ------------------------------------------------------------------
# Per-language adaptive thresholds
# ------------------------------------------------------------------

# Higher = more tolerant (minified JS is naturally high-entropy)
PERPLEXITY_THRESHOLDS: dict[str, float] = {
    "py": 14.0,
    "js": 18.0,
    "ts": 18.0,
    "jsx": 18.0,
    "tsx": 18.0,
    "mjs": 18.0,
    "json": 12.0,
    "yml": 10.0,
    "yaml": 10.0,
    "xml": 10.0,
    "html": 15.0,
    "css": 14.0,
    "java": 14.0,
    "go": 13.0,
    "rs": 12.0,
    "cpp": 12.0,
    "c": 12.0,
    "h": 12.0,
    "rb": 13.0,
    "php": 14.0,
    "sh": 12.0,
    "bash": 12.0,
}


def get_perplexity_threshold(filepath: str) -> float:
    ext = Path(filepath).suffix.lower().lstrip(".")
    return PERPLEXITY_THRESHOLDS.get(ext, 14.0)


# ------------------------------------------------------------------
# Cache management
# ------------------------------------------------------------------


def get_model_cache_path(repo_dir: str) -> Path:
    cache_dir = Path(repo_dir) / ".omni-cache"
    cache_dir.mkdir(exist_ok=True)
    return cache_dir / "markov.pkl"


# ------------------------------------------------------------------
# Helper: collect safe corpus from repo files
# ------------------------------------------------------------------

_SECRET_LOOKALIKE = r"AKIA|sk-|hf_|gsk_|pplx-|nvapi-|ghp_|glpat-|xox[bpras]-|AIza|ya29\.|eyJ"


def collect_safe_corpus(text_files: list[Path], max_bytes_per_file: int = 65536) -> str:
    """Concatenate text from *text_files*, skipping secret-lookalike lines."""
    parts: list[str] = []
    for fp in text_files:
        try:
            raw = fp.read_text(encoding="utf-8", errors="ignore")
            # strip lines that look like secrets
            safe = [line for line in raw.splitlines() if not re.search(_SECRET_LOOKALIKE, line)]
            chunk = "\n".join(safe)[:max_bytes_per_file]
            if chunk:
                parts.append(chunk)
        except Exception:
            pass
    return "\n".join(parts)
