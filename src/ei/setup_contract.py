"""Selection contracts for the single organizer and multiple work hosts.

The installer accepts legacy provider lists only as migration input.  This
module intentionally never guesses when that input is ambiguous.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Collection, Literal, Mapping, Sequence


OrganizerStatus = Literal["READY", "SELECTION_REQUIRED"]
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_SELECTION_REQUIRED = "ORGANIZER_SELECTION_REQUIRED"


@dataclass(frozen=True)
class OrganizerSelection:
    status: OrganizerStatus
    provider_id: str | None
    host_id: str | None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"READY", "SELECTION_REQUIRED"}:
            raise ValueError("ORGANIZER_STATUS_INVALID")
        if self.status == "SELECTION_REQUIRED":
            if self.provider_id is not None or self.host_id is not None:
                raise ValueError("ORGANIZER_SELECTION_REQUIRED_FIELDS_INVALID")
            if not isinstance(self.reason_code, str) or not self.reason_code:
                raise ValueError("ORGANIZER_REASON_REQUIRED")
            return
        if not isinstance(self.provider_id, str) or not _SAFE_ID.fullmatch(self.provider_id):
            raise ValueError("ORGANIZER_PROVIDER_ID_INVALID")
        if self.provider_id == "subscription-cli":
            if not isinstance(self.host_id, str) or not _SAFE_ID.fullmatch(self.host_id):
                raise ValueError("ORGANIZER_HOST_REQUIRED")
        elif self.host_id is not None:
            raise ValueError("ORGANIZER_HOST_MUST_BE_EMPTY")
        if self.reason_code is not None:
            raise ValueError("ORGANIZER_READY_REASON_INVALID")

    def to_dict(self) -> dict[str, str | None]:
        return {
            "status": self.status,
            "provider_id": self.provider_id,
            "host_id": self.host_id,
            "reason_code": self.reason_code,
        }


def _required(reason_code: str = _SELECTION_REQUIRED) -> OrganizerSelection:
    return OrganizerSelection("SELECTION_REQUIRED", None, None, reason_code)


def _normalise_id(value: object) -> str | None:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        return None
    return value


def _normalise_ids(values: Sequence[str] | Collection[str] | None) -> tuple[str, ...] | None:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    result: list[str] = []
    try:
        iterator = iter(values)
    except TypeError:
        return None
    for value in iterator:
        item = _normalise_id(value)
        if item is None:
            return None
        if item not in result:
            result.append(item)
    return tuple(result)


def _normalise_values_preserving_multiplicity(values: Sequence[str] | Collection[str] | None) -> tuple[str, ...] | None:
    """Validate a legacy list without hiding repeated selections."""

    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    result: list[str] = []
    try:
        iterator = iter(values)
    except TypeError:
        return None
    for value in iterator:
        item = _normalise_id(value)
        if item is None:
            return None
        result.append(item)
    return tuple(result)


def resolve_organizer(
    provider_id: str | None,
    host_id: str | None,
    work_hosts: Sequence[str],
    configured_provider_ids: Collection[str],
) -> OrganizerSelection:
    """Resolve one explicit organizer without selecting a fallback.

    ``subscription-cli`` is the only provider whose organizer is tied to a
    host.  The host may be organizer-only, so it is deliberately not required
    to be present in ``work_hosts`` here; manifest validation enforces the
    permitted one-host difference.
    """

    normalised_hosts = _normalise_ids(work_hosts)
    configured = _normalise_ids(configured_provider_ids)
    provider = _normalise_id(provider_id) if provider_id is not None else None
    host = _normalise_id(host_id) if host_id is not None else None
    if normalised_hosts is None or configured is None or (provider_id is not None and provider is None) or (host_id is not None and host is None):
        return _required("ORGANIZER_ID_INVALID")
    if not normalised_hosts:
        return _required()
    if provider is None:
        return _required()
    if provider not in configured:
        return _required("ORGANIZER_PROVIDER_NOT_CONFIGURED")
    if provider == "subscription-cli":
        if host is None:
            return _required("ORGANIZER_HOST_REQUIRED")
        return OrganizerSelection("READY", provider, host)
    return OrganizerSelection("READY", provider, None)


def migrate_legacy_organizer(
    providers: Sequence[str],
    work_hosts: Sequence[str],
) -> OrganizerSelection:
    """Migrate the v7 provider list without ever choosing its first item."""

    normalised_providers = _normalise_values_preserving_multiplicity(providers)
    normalised_hosts = _normalise_values_preserving_multiplicity(work_hosts)
    if normalised_providers is None or normalised_hosts is None:
        return _required("ORGANIZER_ID_INVALID")
    if not normalised_hosts:
        return _required()
    if len(normalised_providers) != 1:
        return _required()
    provider = normalised_providers[0]
    if provider == "subscription-cli":
        if len(normalised_hosts) != 1:
            return _required()
        return OrganizerSelection("READY", provider, normalised_hosts[0])
    return OrganizerSelection("READY", provider, None)


def organizer_from_mapping(value: Mapping[str, object]) -> OrganizerSelection:
    """Build a typed selection from a validated manifest object."""

    if not isinstance(value, Mapping):
        raise ValueError("ORGANIZER_INVALID")
    try:
        return OrganizerSelection(
            status=value.get("status"),  # type: ignore[arg-type]
            provider_id=value.get("provider_id"),  # type: ignore[arg-type]
            host_id=value.get("host_id"),  # type: ignore[arg-type]
            reason_code=value.get("reason_code"),  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("ORGANIZER_INVALID") from exc


__all__ = [
    "OrganizerSelection",
    "OrganizerStatus",
    "migrate_legacy_organizer",
    "organizer_from_mapping",
    "resolve_organizer",
]
