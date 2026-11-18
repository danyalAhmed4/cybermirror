"""Smoke tests for XSS feature extraction (prints top feature values)."""
from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.monitoring.features_xss import (  # noqa: E402
    build_features,
    get_feature_names,
    predict_xss,
)

BENIGN = [
    ("https://127.0.0.1:5000/search?q=laptop", {"q": "laptop"}),
    ("https://127.0.0.1:5000/search?q=john+smith", {"q": "john smith"}),
    ("https://127.0.0.1:5000/register", {"username": "alice", "email": "a@ex.com"}),
    ("https://127.0.0.1:5000/home", {}),
    ("https://127.0.0.1:5000/search?q=office+chair", {"q": "office chair"}),
]

MALICIOUS = [
    (
        "https://127.0.0.1:5000/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        {"q": "<script>alert(1)</script>"},
    ),
    (
        "https://127.0.0.1:5000/search?q=img",
        {"q": "<img src=x onerror=alert(1)>"},
    ),
    (
        "https://127.0.0.1:5000/register",
        {"username": "<svg onload=alert(1)>", "email": "x@ex.com"},
    ),
    (
        "https://127.0.0.1:5000/search?q=javascript:alert(1)",
        {"q": "javascript:alert(1)"},
    ),
    (
        "https://127.0.0.1:5000/search?q=xss",
        {"q": "\"><script>alert(1)</script>"},
    ),
]


def _top_features(url, form, n=8):
    names = get_feature_names()
    vec = build_features(url, form)
    pairs = sorted(
        ((names[i], float(vec[i])) for i in range(len(names))),
        key=lambda x: x[1],
        reverse=True,
    )
    return [(k, v) for k, v in pairs if v > 0][:n]


def main() -> int:
    print("Feature count:", len(get_feature_names()))
    print("\n=== Benign samples ===")
    for url, form in BENIGN:
        label, proba, _ = predict_xss(url, form)
        print(f"\nURL={url!r} form={form!r}")
        print(f"  predict={label} proba={None if proba is None else round(proba, 4)}")
        print("  top:", _top_features(url, form))

    print("\n=== Malicious samples ===")
    for url, form in MALICIOUS:
        label, proba, _ = predict_xss(url, form)
        print(f"\nURL={url!r} form={form!r}")
        print(f"  predict={label} proba={None if proba is None else round(proba, 4)}")
        print("  top:", _top_features(url, form))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
