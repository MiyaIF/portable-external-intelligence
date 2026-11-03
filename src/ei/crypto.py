from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from .key_provider import KeyProvider, KeyProviderError


class CryptoError(ValueError):
    """Raised when encrypted spool content cannot be authenticated or decoded."""


def _cryptography_primitives() -> tuple[Any, type[Exception]]:
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise CryptoError("CRYPTO_DEPENDENCY_UNAVAILABLE") from exc
    return AESGCM, InvalidTag


def _aware_iso(moment: datetime) -> str:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise CryptoError("SPOOL_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _content_hash(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def canonical_aad(spool_id: str, classification: str, expires_at: datetime | str, content_hash: str, *, aad_version: int | None = None, purpose: str = "legacy", capture_id: str | None = None) -> bytes:
    if not isinstance(spool_id, str) or not spool_id or not isinstance(classification, str) or not classification or not isinstance(content_hash, str) or not content_hash:
        raise CryptoError("SPOOL_AAD_INVALID")
    expiry = _aware_iso(expires_at) if isinstance(expires_at, datetime) else expires_at
    if not isinstance(expiry, str) or not expiry:
        raise CryptoError("SPOOL_AAD_INVALID")
    fields = {"classification": classification, "content_hash": content_hash, "expires_at": expiry, "spool_id": spool_id}
    if aad_version is None:
        if purpose != "legacy" or capture_id is not None:
            raise CryptoError("SPOOL_AAD_VERSION_INVALID")
    elif type(aad_version) is int and aad_version == 2:
        if not isinstance(purpose, str) or purpose not in {"pending", "validated-result"}:
            raise CryptoError("SPOOL_PURPOSE_INVALID")
        if not isinstance(capture_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", capture_id):
            raise CryptoError("SPOOL_CAPTURE_ID_INVALID")
        fields.update(aad_version=2, purpose=purpose, capture_id=capture_id)
    else:
        raise CryptoError("SPOOL_AAD_VERSION_INVALID")
    return json.dumps(
        fields,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encrypt_payload(content: bytes, spool_id: str, classification: str, expires_at: datetime, provider: KeyProvider, *, created_at: datetime | None = None, aad_version: int | None = None, purpose: str = "legacy", capture_id: str | None = None) -> dict[str, Any]:
    if not isinstance(content, bytes):
        raise TypeError("SPOOL_CONTENT_BYTES_REQUIRED")
    created = created_at or datetime.now(timezone.utc)
    content_hash = _content_hash(content)
    aad = canonical_aad(spool_id, classification, expires_at, content_hash, aad_version=aad_version, purpose=purpose, capture_id=capture_id)
    material = provider.current()
    nonce = __import__("secrets").token_bytes(12)
    aes_gcm, _invalid_tag = _cryptography_primitives()
    ciphertext = aes_gcm(material.key).encrypt(nonce, content, aad)
    envelope = {
        "spool_id": spool_id,
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad_sha256": "sha256:" + hashlib.sha256(aad).hexdigest(),
        "content_sha256": content_hash,
        "classification": classification,
        "created_at": _aware_iso(created),
        "expires_at": _aware_iso(expires_at),
        "key_id": material.key_id,
    }
    if aad_version is not None:
        envelope.update(aad_version=aad_version, purpose=purpose, capture_id=capture_id)
    return envelope


def decrypt_payload(
    envelope: Mapping[str, Any],
    provider: KeyProvider,
    *,
    now: datetime | None = None,
    expected_classification: str | None = None,
) -> bytes:
    if not isinstance(envelope, Mapping):
        raise CryptoError("SPOOL_ENVELOPE_INVALID")
    if any(name in envelope for name in ("aad_version", "purpose", "capture_id")):
        if type(envelope.get("aad_version")) is not int or envelope["aad_version"] != 2:
            raise CryptoError("SPOOL_AAD_VERSION_INVALID")
    required = ("spool_id", "algorithm", "nonce", "ciphertext", "aad_sha256", "content_sha256", "classification", "created_at", "expires_at", "key_id")
    if any(field not in envelope for field in required) or envelope.get("algorithm") != "AES-256-GCM":
        raise CryptoError("SPOOL_ENVELOPE_INVALID")
    if expected_classification is not None and envelope.get("classification") != expected_classification:
        raise CryptoError("SPOOL_CLASSIFICATION_MISMATCH")
    try:
        nonce = base64.b64decode(str(envelope["nonce"]), validate=True)
        ciphertext = base64.b64decode(str(envelope["ciphertext"]), validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise CryptoError("SPOOL_ENCODING_INVALID") from exc
    if len(nonce) != 12 or not ciphertext:
        raise CryptoError("SPOOL_ENCODING_INVALID")
    try:
        expiry = datetime.fromisoformat(str(envelope["expires_at"]).replace("Z", "+00:00"))
        created = datetime.fromisoformat(str(envelope["created_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise CryptoError("SPOOL_TIME_INVALID") from exc
    if expiry.tzinfo is None or created.tzinfo is None:
        raise CryptoError("SPOOL_TIME_INVALID")
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise CryptoError("SPOOL_TIME_INVALID")
    aad = canonical_aad(str(envelope["spool_id"]), str(envelope["classification"]), expiry, str(envelope["content_sha256"]),
        aad_version=envelope.get("aad_version"), purpose=envelope.get("purpose", "legacy"), capture_id=envelope.get("capture_id"))
    expected_aad_hash = "sha256:" + hashlib.sha256(aad).hexdigest()
    if envelope["aad_sha256"] != expected_aad_hash:
        raise CryptoError("SPOOL_AAD_MISMATCH")
    aes_gcm, invalid_tag = _cryptography_primitives()
    try:
        key = provider.get(str(envelope["key_id"]))
        plaintext = aes_gcm(key).decrypt(nonce, ciphertext, aad)
    except (KeyProviderError, invalid_tag, ValueError) as exc:
        raise CryptoError("SPOOL_DECRYPT_FAILED") from exc
    if _content_hash(plaintext) != envelope["content_sha256"]:
        raise CryptoError("SPOOL_CONTENT_HASH_MISMATCH")
    if expiry <= moment.astimezone(timezone.utc):
        raise CryptoError("SPOOL_EXPIRED")
    return plaintext


__all__ = ["CryptoError", "canonical_aad", "decrypt_payload", "encrypt_payload"]
