from __future__ import annotations

import base64
import binascii
import ctypes
import json
import os
import platform
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol


KEY_BYTES = 32


class KeyProviderError(RuntimeError):
    """Raised when an OS-backed key cannot be created or retrieved."""


@dataclass(frozen=True)
class KeyMaterial:
    key_id: str
    key: bytes

    def __post_init__(self) -> None:
        if not self.key_id or len(self.key) != KEY_BYTES:
            raise ValueError("KEY_MATERIAL_INVALID")


class KeyProvider(Protocol):
    def current(self) -> KeyMaterial:
        ...

    def get(self, key_id: str) -> bytes:
        ...


class InMemoryKeyProvider:
    """Explicit test provider; production setup never selects it implicitly."""

    def __init__(self, key_id: str = "test-memory-v1", key: bytes | None = None) -> None:
        self._material = KeyMaterial(key_id, key or secrets.token_bytes(KEY_BYTES))

    def current(self) -> KeyMaterial:
        return self._material

    def get(self, key_id: str) -> bytes:
        if key_id != self._material.key_id:
            raise KeyProviderError("KEY_ID_UNKNOWN")
        return self._material.key


def _write_state(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    try:
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            if os.name != "nt":
                raise KeyProviderError("KEY_STATE_PERMISSION_FAILED") from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_state(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KeyProviderError("KEY_STATE_INVALID") from exc
    if not isinstance(value, dict):
        raise KeyProviderError("KEY_STATE_INVALID")
    return value


def _decode_key(value: Any) -> bytes:
    if not isinstance(value, str):
        raise KeyProviderError("KEY_STATE_INVALID")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise KeyProviderError("KEY_STATE_INVALID") from exc
    if len(decoded) != KEY_BYTES:
        raise KeyProviderError("KEY_STATE_INVALID")
    return decoded


class WindowsDPAPIKeyProvider:
    key_id = "windows-dpapi-currentuser-v1"

    def __init__(self, state_path: Path) -> None:
        self.state_path = Path(state_path).expanduser().resolve()

    @staticmethod
    def _protect(key: bytes) -> bytes:
        if platform.system() != "Windows":
            raise KeyProviderError("DPAPI_UNAVAILABLE")
        class Blob(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        source = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
        input_blob = Blob(len(key), source)
        output_blob = Blob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptProtectData(ctypes.byref(input_blob), None, None, None, None, 0, ctypes.byref(output_blob)):
            raise KeyProviderError("DPAPI_PROTECT_FAILED")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)

    @staticmethod
    def _unprotect(protected: bytes) -> bytes:
        if platform.system() != "Windows":
            raise KeyProviderError("DPAPI_UNAVAILABLE")
        class Blob(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        source = (ctypes.c_ubyte * len(protected)).from_buffer_copy(protected)
        input_blob = Blob(len(protected), source)
        output_blob = Blob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptUnprotectData(ctypes.byref(input_blob), None, None, None, None, 0, ctypes.byref(output_blob)):
            raise KeyProviderError("DPAPI_UNPROTECT_FAILED")
        try:
            key = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)
        if len(key) != KEY_BYTES:
            raise KeyProviderError("DPAPI_KEY_LENGTH_INVALID")
        return key

    def current(self) -> KeyMaterial:
        if self.state_path.exists():
            state = _read_state(self.state_path)
            if state.get("key_id") != self.key_id:
                raise KeyProviderError("KEY_ID_UNKNOWN")
            try:
                protected = base64.b64decode(state["protected_key"], validate=True)
            except (KeyError, ValueError, binascii.Error) as exc:
                raise KeyProviderError("KEY_STATE_INVALID") from exc
            return KeyMaterial(self.key_id, self._unprotect(protected))
        key = secrets.token_bytes(KEY_BYTES)
        protected = self._protect(key)
        _write_state(
            self.state_path,
            {
                "schema_version": 1,
                "key_id": self.key_id,
                "backend": "DPAPI_CurrentUser",
                "protected_key": base64.b64encode(protected).decode("ascii"),
            },
        )
        return KeyMaterial(self.key_id, key)

    def get(self, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise KeyProviderError("KEY_ID_UNKNOWN")
        return self.current().key


class MacOSKeychainProvider:
    key_id = "macos-keychain-user-v1"

    def __init__(self, service: str = "portable-external-intelligence", account: str = "spool-key") -> None:
        self.service = service
        self.account = account

    def _run(self, argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(argv, input=input_text, text=True, capture_output=True, check=False, shell=False, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            raise KeyProviderError("KEYCHAIN_UNAVAILABLE") from exc

    def current(self) -> KeyMaterial:
        if platform.system() != "Darwin":
            raise KeyProviderError("KEYCHAIN_UNAVAILABLE")
        lookup = self._run(["security", "find-generic-password", "-s", self.service, "-a", self.account, "-w"])
        if lookup.returncode == 0:
            return KeyMaterial(self.key_id, _decode_key(lookup.stdout.strip()))
        key = base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode("ascii")
        stored = self._run(["security", "add-generic-password", "-U", "-s", self.service, "-a", self.account, "-w", key])
        if stored.returncode != 0:
            raise KeyProviderError("KEYCHAIN_WRITE_FAILED")
        return KeyMaterial(self.key_id, base64.b64decode(key, validate=True))

    def get(self, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise KeyProviderError("KEY_ID_UNKNOWN")
        return self.current().key


class LinuxSecretServiceProvider:
    key_id = "linux-secret-service-user-v1"

    def __init__(self, service: str = "portable-external-intelligence", account: str = "spool-key") -> None:
        self.service = service
        self.account = account

    def _run(self, argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(argv, input=input_text, text=True, capture_output=True, check=False, shell=False, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            raise KeyProviderError("SECRET_SERVICE_UNAVAILABLE") from exc

    def current(self) -> KeyMaterial:
        if platform.system() != "Linux":
            raise KeyProviderError("SECRET_SERVICE_UNAVAILABLE")
        lookup = self._run(["secret-tool", "lookup", "service", self.service, "account", self.account])
        if lookup.returncode == 0 and lookup.stdout.strip():
            return KeyMaterial(self.key_id, _decode_key(lookup.stdout.strip()))
        key = base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode("ascii")
        stored = self._run(
            ["secret-tool", "store", "--label", "Portable external intelligence spool key", "service", self.service, "account", self.account],
            input_text=key,
        )
        if stored.returncode != 0:
            raise KeyProviderError("SECRET_SERVICE_WRITE_FAILED")
        return KeyMaterial(self.key_id, base64.b64decode(key, validate=True))

    def get(self, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise KeyProviderError("KEY_ID_UNKNOWN")
        return self.current().key


def default_key_provider(runtime_root: Path) -> KeyProvider:
    system = platform.system()
    if system == "Windows":
        return WindowsDPAPIKeyProvider(Path(runtime_root) / "key-provider.json")
    if system == "Darwin":
        return MacOSKeychainProvider()
    if system == "Linux":
        return LinuxSecretServiceProvider()
    raise KeyProviderError("OS_KEY_BACKEND_UNSUPPORTED")


__all__ = [
    "InMemoryKeyProvider",
    "KEY_BYTES",
    "KeyMaterial",
    "KeyProvider",
    "KeyProviderError",
    "LinuxSecretServiceProvider",
    "MacOSKeychainProvider",
    "WindowsDPAPIKeyProvider",
    "default_key_provider",
]