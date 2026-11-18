"""
Approximate XSS feature extractor for models/xss_detector.joblib.

Assumptions (original Data_66_featurs.csv counting rules are unknown)
-------------------------------------------------------------------
1. ``url_*`` features are counted on the URL path + query only (scheme/host
   stripped when an absolute URL is provided). Absolute lab URLs otherwise
   inflate ``url_length`` far beyond the training distribution.
2. ``html_*`` / ``js_*`` features are counted on the concatenation of
   serialized ``form_values`` plus optional ``response_html``.
3. Counts are case-insensitive substring / tag occurrences (not a real HTML
   parser). A tag feature ``html_tag_script`` increments for each ``<script``
   (and ``</script>`` is not double-counted as a separate open tag).
4. Attribute / event features count raw token occurrences (e.g. ``onerror``),
   not only well-formed ``attr="..."`` pairs.
5. ``url_special_characters`` = count of characters outside [A-Za-z0-9].
6. ``url_number_keywords_param`` = number of ``=`` signs in the URL (proxy for
   query parameters).
7. ``url_number_domain`` = number of ``.`` characters in the URL netloc/path
   (rough domain / hostname complexity proxy).
8. ``html_number_keywords_evil`` counts hits from a fixed keyword list
   (alert, prompt, confirm, javascript, eval, xss, onerror, document.cookie).
9. ``js_file`` counts ``.js`` substring hits; ``js_pseudo_protocol`` counts
   ``javascript:``.
10. ``js_min_length`` is the length of the HTML/JS corpus; ``js_min_define_function``
    counts ``function ``; ``js_min_function_calls`` counts ``(``; 
    ``js_string_max_length`` is the longest single/double-quoted literal.
11. Missing HTML response (``response_html=None``) means HTML/JS features come
    only from form fields (common for before_request detection).
12. Unknown feature names (if the joblib list changes) default to 0.0.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Mapping, Optional
from urllib.parse import urlparse

import joblib
import numpy as np

logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_DEFAULT_MODEL_PATH = os.path.join(_PROJECT_ROOT, "models", "xss_detector.joblib")

_EVIL_KEYWORDS = (
    "alert",
    "prompt",
    "confirm",
    "javascript",
    "eval",
    "xss",
    "onerror",
    "document.cookie",
)

# Cached bundle
_XSS_BUNDLE: Optional[dict[str, Any]] = None


def load_xss_bundle(model_path: Optional[str] = None) -> dict[str, Any]:
    """Load ``{model, scaler, features}`` once."""
    global _XSS_BUNDLE
    path = model_path or _DEFAULT_MODEL_PATH
    if _XSS_BUNDLE is not None and _XSS_BUNDLE.get("_path") == path:
        return _XSS_BUNDLE
    bundle = joblib.load(path)
    if not isinstance(bundle, dict) or "features" not in bundle:
        raise ValueError(f"Unexpected XSS model format at {path}")
    bundle = dict(bundle)
    bundle["_path"] = path
    _XSS_BUNDLE = bundle
    return bundle


def get_feature_names(model_path: Optional[str] = None) -> list[str]:
    return list(load_xss_bundle(model_path)["features"])


def _count_ci(text: str, needle: str) -> int:
    if not text or not needle:
        return 0
    return len(re.findall(re.escape(needle), text, flags=re.IGNORECASE))


def _count_tag(text: str, tag: str) -> int:
    """Count opening tags like <script / <img (assumption #3)."""
    return len(re.findall(rf"<\s*{re.escape(tag)}\b", text, flags=re.IGNORECASE))


def _serialize_form_values(form_values: Optional[Mapping[str, Any]]) -> str:
    if not form_values:
        return ""
    parts: list[str] = []
    for key, value in form_values.items():
        if isinstance(value, (list, tuple)):
            for item in value:
                parts.append(f"{key}={item}")
        else:
            parts.append(f"{key}={value}")
    return "\n".join(parts)


def _max_quoted_string_len(text: str) -> int:
    matches = re.findall(r"'([^']*)'|\"([^\"]*)\"", text)
    if not matches:
        return 0
    return max((len(a or b) for a, b in matches), default=0)


def _url_features(url: str) -> dict[str, float]:
    """Fill url_* feature names."""
    raw = url or ""
    parsed = urlparse(raw)
    # Prefer path+query so absolute lab URLs do not dominate length features
    if parsed.scheme or parsed.netloc:
        u = parsed.path or "/"
        if parsed.query:
            u = f"{u}?{parsed.query}"
    else:
        u = raw
    host_path = f"{parsed.netloc}{parsed.path}"
    return {
        # url_length
        "url_length": float(len(u)),
        # url_special_characters
        "url_special_characters": float(sum(1 for ch in u if not ch.isalnum())),
        # url_tag_script / url_tag_iframe
        "url_tag_script": float(_count_tag(u, "script")),
        "url_tag_iframe": float(_count_tag(u, "iframe")),
        # url_attr_src
        "url_attr_src": float(_count_ci(u, "src")),
        # url_event_onload / url_event_onmouseover
        "url_event_onload": float(_count_ci(u, "onload")),
        "url_event_onmouseover": float(_count_ci(u, "onmouseover")),
        # url_cookie
        "url_cookie": float(_count_ci(u, "cookie")),
        # url_number_keywords_param
        "url_number_keywords_param": float(u.count("=")),
        # url_number_domain
        "url_number_domain": float(host_path.count(".")),
    }


def _html_js_features(corpus: str) -> dict[str, float]:
    """Fill html_* and js_* feature names from the HTML/JS corpus."""
    t = corpus or ""
    feats: dict[str, float] = {}

    # html_tag_*
    for tag in (
        "script",
        "iframe",
        "meta",
        "object",
        "embed",
        "link",
        "svg",
        "frame",
        "form",
        "div",
        "style",
        "img",
        "input",
        "textarea",
    ):
        feats[f"html_tag_{tag}"] = float(_count_tag(t, tag))

    # html_attr_*
    for attr in (
        "action",
        "background",
        "classid",
        "codebase",
        "href",
        "longdesc",
        "profile",
        "src",
        "usemap",
        "http-equiv",
    ):
        feats[f"html_attr_{attr}"] = float(_count_ci(t, attr))

    # html_event_*
    for ev in (
        "onblur",
        "onchange",
        "onclick",
        "onerror",
        "onfocus",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onload",
        "onmousedown",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onsubmit",
    ):
        feats[f"html_event_{ev}"] = float(_count_ci(t, ev))

    # html_number_keywords_evil
    feats["html_number_keywords_evil"] = float(
        sum(_count_ci(t, kw) for kw in _EVIL_KEYWORDS)
    )

    # html_length
    feats["html_length"] = float(len(t))

    # js_file / js_pseudo_protocol
    feats["js_file"] = float(_count_ci(t, ".js"))
    feats["js_pseudo_protocol"] = float(_count_ci(t, "javascript:"))

    # js_dom_* / js_prop_* / js_method_*
    feats["js_dom_location"] = float(_count_ci(t, "location"))
    feats["js_dom_document"] = float(_count_ci(t, "document"))
    feats["js_prop_cookie"] = float(_count_ci(t, "cookie"))
    feats["js_prop_referrer"] = float(_count_ci(t, "referrer"))
    feats["js_method_write"] = float(_count_ci(t, "write"))
    feats["js_method_getElementsByTagName"] = float(
        _count_ci(t, "getElementsByTagName")
    )
    feats["js_method_getElementById"] = float(_count_ci(t, "getElementById"))
    feats["js_method_alert"] = float(_count_ci(t, "alert"))
    feats["js_method_eval"] = float(_count_ci(t, "eval"))
    feats["js_method_fromCharCode"] = float(_count_ci(t, "fromCharCode"))
    feats["js_method_confirm"] = float(_count_ci(t, "confirm"))

    # js_min_* length proxies
    feats["js_min_length"] = float(len(t))
    feats["js_min_define_function"] = float(_count_ci(t, "function "))
    feats["js_min_function_calls"] = float(t.count("("))
    feats["js_string_max_length"] = float(_max_quoted_string_len(t))

    return feats


def build_features(
    url: str,
    form_values: Optional[Mapping[str, Any]] = None,
    response_html: Optional[str] = None,
    *,
    model_path: Optional[str] = None,
) -> np.ndarray:
    """
    Build a feature vector in exactly the joblib ``features`` order.

    See module docstring for counting assumptions.
    """
    feature_names = get_feature_names(model_path)
    form_text = _serialize_form_values(form_values)
    html_corpus = "\n".join(x for x in (form_text, response_html or "") if x)

    values: dict[str, float] = {}
    values.update(_url_features(url or ""))
    values.update(_html_js_features(html_corpus))

    vector = np.array(
        [float(values.get(name, 0.0)) for name in feature_names],
        dtype=float,
    )
    return vector


def predict_xss(
    url: str,
    form_values: Optional[Mapping[str, Any]] = None,
    response_html: Optional[str] = None,
    *,
    model_path: Optional[str] = None,
    bundle: Optional[dict[str, Any]] = None,
) -> tuple[Optional[int], Optional[float], np.ndarray]:
    """
    Scale + predict. Returns ``(label, proba_class_1, raw_vector)``.
    Never raises — returns ``(None, None, vector_or_empty)`` on failure.
    """
    try:
        packed = bundle or load_xss_bundle(model_path)
        raw = build_features(
            url, form_values, response_html, model_path=packed.get("_path")
        )
        scaler = packed["scaler"]
        model = packed["model"]
        names = list(packed["features"])
        try:
            import pandas as pd

            frame = pd.DataFrame([raw], columns=names)
            scaled = scaler.transform(frame)
        except Exception:
            scaled = scaler.transform(raw.reshape(1, -1))
        label = int(model.predict(scaled)[0])
        proba = None
        if hasattr(model, "predict_proba"):
            proba = float(model.predict_proba(scaled)[0][1])
        return label, proba, raw
    except Exception:
        logger.exception("XSS predict failed")
        try:
            return None, None, build_features(url, form_values, response_html)
        except Exception:
            return None, None, np.array([])
