from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping
from functools import lru_cache
from typing import Literal


AliasMap = tuple[tuple[str, tuple[str, ...]], ...]


_ALIAS_GROUPS: AliasMap = (
    (
        "write",
        (
            "書き込み",
            "書込",
            "書いた",
            "入力",
            "更新",
            "編集",
            "write",
            "writing",
            "edit",
            "edited",
        ),
    ),
    (
        "reload",
        (
            "再読み込み",
            "再読込",
            "読み直し",
            "読み込ん",
            "再確認",
            "reload",
            "refresh",
            "read again",
        ),
    ),
    (
        "target",
        (
            "対象範囲",
            "対象箇所",
            "対象部分",
            "シート",
            "worksheet",
            "spreadsheet",
            "target",
        ),
    ),
    (
        "formula",
        (
            "数式",
            "式",
            "formula",
            "formulas",
        ),
    ),
    (
        "verify",
        (
            "確認",
            "検証",
            "チェック",
            "verify",
            "validate",
            "validation",
            "check",
        ),
    ),
)
_NEGATION_PHRASES = (
    "してはいけない",
    "してはならない",
    "禁止",
    "不要",
    "避ける",
    "避け",
    "無効",
    "失敗",
    "誤り",
    "never",
    "do not",
    "does not",
    "doesn't",
    "must not",
    "not",
    "cannot",
    "can't",
    "disable",
    "disabled",
    "avoid",
    "failed",
    "failure",
)
_POSITIVE_PHRASES = (
    "推奨",
    "有効",
    "成功",
    "改善",
    "必須",
    "必要",
    "確認する",
    "検証する",
    "実施する",
    "使用する",
    "することで",
    "should",
    "recommended",
    "success",
    "succeeded",
    "improve",
    "improved",
    "must",
    "enable",
    "enabled",
    "use",
    "works",
    "passed",
)
_JAPANESE_RUN = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fffー]+")
_ASCII_WORD = re.compile(r"[a-z0-9_]+")
_ASCII_CASE = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_VERSION_RE = re.compile(
    r"(?<![a-z0-9])(?:version|ver|v|release|対応|互換|バージョン)[\s:=/-]*([0-9]+(?:\.[0-9]+){0,3})",
    re.IGNORECASE,
)


def _require_text(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("CLAIM_TEXT_REQUIRED")
    return text


def normalize_claim(text: str) -> str:
    """Normalize only comparison material; the stored claim remains unchanged."""
    value = unicodedata.normalize("NFKC", _require_text(text))
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"\s+", " ", value).strip()
    value = re.sub(r"\s*([,、。．.!！?？:：;；/／])\s*", r"\1", value)
    value = re.sub(r"\s*([()[\]{}「」『』])\s*", r"\1", value)
    value = re.sub(r"[ \t]*([+＝=])\s*", r"\1", value)
    return value.translate(_ASCII_CASE)


def claim_fingerprint(text: str) -> str:
    """Return the SHA-256 digest of the normalized UTF-8 claim."""
    return hashlib.sha256(normalize_claim(text).encode("utf-8")).hexdigest()


def content_fingerprint(text: str) -> str:
    """Backward-compatible name used by the journal and migration code."""
    return claim_fingerprint(text)


def _with_aliases(text: str) -> str:
    value = normalize_claim(text)
    for canonical, aliases in sorted(_ALIAS_GROUPS, key=lambda item: (-max(map(len, item[1])), item[0])):
        for alias in sorted(aliases, key=lambda item: (-len(item), item)):
            value = value.replace(alias.translate(_ASCII_CASE), f" {canonical} ")
    return re.sub(r"\s+", " ", value).strip()


@lru_cache(maxsize=8192)
def tokenize_similarity(text: str) -> frozenset[str]:
    """Build deterministic Japanese bigram and ASCII-token features."""
    value = _with_aliases(_require_text(text))
    tokens: set[str] = set(_ASCII_WORD.findall(value))
    canonical = {name for name, _ in _ALIAS_GROUPS}
    semantic_tokens = tokens & canonical
    if len(semantic_tokens) >= 2:
        return frozenset(tokens)
    for run in _JAPANESE_RUN.findall(value):
        if len(run) == 1:
            tokens.add(run)
        else:
            tokens.update(run[index : index + 2] for index in range(len(run) - 1))
    return frozenset(token for token in tokens if token)


def jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    left_set = set(left)
    right_set = set(right)
    if not left_set and not right_set:
        return 1.0
    union = left_set | right_set
    return len(left_set & right_set) / len(union)


def similarity(left: str, right: str) -> float:
    """Return deterministic Jaccard similarity over normalized claim features."""
    _require_text(left)
    _require_text(right)
    if claim_fingerprint(left) == claim_fingerprint(right):
        return 1.0
    return jaccard(tokenize_similarity(left), tokenize_similarity(right))


def alias_match(left: str, right: str) -> bool:
    """Return whether two claims share at least two explicit semantic aliases."""
    left_tokens = tokenize_similarity(left)
    right_tokens = tokenize_similarity(right)
    canonical = {name for name, _ in _ALIAS_GROUPS}
    return len((left_tokens & right_tokens) & canonical) >= 2


def classify_polarity(text: str) -> Literal["SUPPORTS", "CONTRADICTS", "MIXED"]:
    value = normalize_claim(_require_text(text))
    has_negative = any(
        (phrase in value if any(ord(char) > 127 for char in phrase) else re.search(r"(?<![a-z])" + re.escape(phrase) + r"(?![a-z])", value) is not None)
        for phrase in _NEGATION_PHRASES
    )
    positive_material = re.sub(
        r"(?<![a-z])(?:never|do not|does not|doesn't|must not|not|cannot|can't|disable|disabled|avoid)(?:\s+[a-z0-9_]+)?(?![a-z])",
        " ",
        value,
    )
    has_positive = any(
        (phrase in positive_material if any(ord(char) > 127 for char in phrase) else re.search(r"(?<![a-z])" + re.escape(phrase) + r"(?![a-z])", positive_material) is not None)
        for phrase in _POSITIVE_PHRASES
    )
    if has_negative and has_positive:
        return "MIXED"
    if has_negative:
        return "CONTRADICTS"
    return "SUPPORTS"


def detect_polarity(text: str) -> str:
    """Backward-compatible polarity labels used by lifecycle reconciliation."""
    value = classify_polarity(text)
    return {"SUPPORTS": "positive", "CONTRADICTS": "negative", "MIXED": "mixed"}[value]


def extract_version(text: str) -> str | None:
    match = _VERSION_RE.search(normalize_claim(_require_text(text)))
    return match.group(1) if match else None


def extract_outcome(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = normalize_claim(value)
    if any(token in normalized for token in ("failed", "failure", "error", "ng", "不成功", "失敗", "否定")):
        return "negative"
    if any(token in normalized for token in ("success", "succeeded", "passed", "ok", "改善", "成功", "有効", "positive")):
        return "positive"
    return None


def _field(value: object, name: str, default: object = None) -> object:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _provenance_value(observation: object, name: str, default: object = None) -> object:
    value = _field(observation, name, default)
    if value is not None and value != "":
        return value
    provenance = _field(observation, "provenance", ())
    if isinstance(provenance, (tuple, list)) and provenance:
        return _field(provenance[0], name, default)
    return default


def provenance_identity(value: object) -> tuple[str, str, str, str]:
    """Collapse aliases of source/session/rollout provenance to stable identity."""
    source_hash = _provenance_value(value, "source_hash", "")
    session_hash = _provenance_value(value, "session_id_hash", "")
    rollout_hash = _provenance_value(value, "rollout_id_hash", "")
    provenance_key = _field(value, "provenance_key", "")
    if not isinstance(source_hash, str):
        source_hash = ""
    if not isinstance(session_hash, str):
        session_hash = ""
    if not isinstance(rollout_hash, str):
        rollout_hash = ""
    if not isinstance(provenance_key, str):
        provenance_key = ""
    if not source_hash and provenance_key.startswith("source:"):
        source_hash = provenance_key[7:]
    if not session_hash and provenance_key.startswith("session:"):
        session_hash = provenance_key[8:]
    if not rollout_hash and provenance_key.startswith("rollout:"):
        rollout_hash = provenance_key[8:]
    copied = ""
    for name in ("copied_from_hash", "copy_of_hash", "copy_source_hash", "copy_origin_hash"):
        candidate = _provenance_value(value, name, "")
        if candidate:
            copied = candidate
            break
    if not isinstance(copied, str):
        copied = ""
    return source_hash, session_hash, rollout_hash, copied


def is_independent(left: object, right: object) -> bool:
    """Determine whether two observations are independent evidence."""
    left_identity = provenance_identity(left)
    right_identity = provenance_identity(right)
    if left_identity == right_identity:
        return False
    for index in range(4):
        if left_identity[index] and left_identity[index] == right_identity[index]:
            return False
    left_scope = _provenance_value(left, "cwd_hash", "") or _field(left, "cwd_fingerprint", "") or _field(left, "scope", "")
    right_scope = _provenance_value(right, "cwd_hash", "") or _field(right, "cwd_fingerprint", "") or _field(right, "scope", "")
    left_domain = _provenance_value(left, "domain", "") or _field(left, "domain", "")
    right_domain = _provenance_value(right, "domain", "") or _field(right, "domain", "")
    if not isinstance(left_scope, str) or not isinstance(right_scope, str) or not isinstance(left_domain, str) or not isinstance(right_domain, str):
        return False
    if not left_scope and not left_domain:
        return False
    if left_scope and right_scope and left_scope == right_scope and left_domain == right_domain:
        return False
    if left_domain and right_domain and left_domain == right_domain and not left_scope and not right_scope:
        return False
    return bool((left_scope and right_scope and left_scope != right_scope) or (left_domain and right_domain and left_domain != right_domain) or (left_scope != right_scope and (left_scope or right_scope)))


def version_constraint(text: str) -> str | None:
    return extract_version(text)
