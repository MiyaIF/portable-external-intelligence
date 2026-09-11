"""Plain-language rendering and parsing for the setup wizard.

The setup flow keeps machine-facing identifiers and paths out of its normal
screen.  JSON output remains the place for those details; this module is the
small, deterministic presentation boundary used by the interactive flow.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imports are only for static typing.
    from .installer import InstallPlanItem, SetupSelection


ChoiceStatus = Literal[
    "AVAILABLE",
    "AUTH_REQUIRED",
    "NOT_FOUND",
    "NOT_CONFIGURED",
    "UNSUPPORTED",
]

_CHOICE_STATUS_LABELS: dict[str, str] = {
    "AVAILABLE": "利用可能",
    "AUTH_REQUIRED": "要認証",
    "NOT_FOUND": "未検出",
    "NOT_CONFIGURED": "未設定",
    "UNSUPPORTED": "非対応",
}
_CHOICE_STATUSES = frozenset(_CHOICE_STATUS_LABELS)
_HOST_LABELS = {
    "codex-cli": "Codex CLI",
    "claude-code": "Claude Code",
    "gemini-cli": "Gemini CLI",
    "qwen-code": "Qwen Code",
}
_PROVIDER_LABELS = {
    "local-openai-compatible": "ローカルAI",
    "ollama": "ローカルAI",
    "cloud-api": "接続したAIサービス",
}


@dataclass(frozen=True)
class SetupChoice:
    """One user-facing setup option and its availability explanation."""

    value: str
    label: str
    status: ChoiceStatus
    selectable: bool
    help_text: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("SETUP_CHOICE_VALUE_INVALID")
        if not isinstance(self.label, str) or not self.label.strip():
            raise ValueError("SETUP_CHOICE_LABEL_INVALID")
        if self.status not in _CHOICE_STATUSES:
            raise ValueError("SETUP_CHOICE_STATUS_INVALID")
        if type(self.selectable) is not bool:
            raise ValueError("SETUP_CHOICE_SELECTABLE_INVALID")
        if not isinstance(self.help_text, str) or not self.help_text.strip():
            raise ValueError("SETUP_CHOICE_HELP_INVALID")
        if self.selectable != (self.status == "AVAILABLE"):
            raise ValueError("SETUP_CHOICE_AVAILABILITY_MISMATCH")


def _validated_choices(choices: Sequence[SetupChoice]) -> tuple[SetupChoice, ...]:
    if isinstance(choices, (str, bytes)):
        raise ValueError("SETUP_CHOICES_INVALID")
    try:
        result = tuple(choices)
    except TypeError as exc:
        raise ValueError("SETUP_CHOICES_INVALID") from exc
    if any(not isinstance(choice, SetupChoice) for choice in result):
        raise ValueError("SETUP_CHOICES_INVALID")
    if len({choice.value for choice in result}) != len(result):
        raise ValueError("SETUP_CHOICES_DUPLICATE")
    return result


def _choice_lines(title: str, choices: Sequence[SetupChoice], *, multiple: bool) -> list[str]:
    if not isinstance(title, str) or not title.strip():
        raise ValueError("SETUP_CHOICE_TITLE_INVALID")
    selected = _validated_choices(choices)
    lines = [title.strip()]
    for index, choice in enumerate(selected, 1):
        status = _CHOICE_STATUS_LABELS[choice.status]
        lines.append(f"  {index}. {choice.label} [{status}]")
        if not choice.selectable:
            # Help text is supplied by the detector and is intentionally one
            # sentence so a blocked option is understandable at a glance.
            lines.append(f"     {choice.help_text.strip()}")
    lines.append("入力例: 1,2" if multiple else "入力例: 1")
    return lines


def render_intro() -> str:
    return "\n".join(
        (
            "外部知能をセットアップします。",
            "",
            "外部知能は1つです。複数のCLIを選んでも、CLIごとに別の記憶は作りません。",
            "ここでは次の2つを決めます。",
            "",
            "1. 記憶の整理AI",
            "   記憶を整理するAIです。作業後に得た候補を整理・統合し、今後も使う知識を選びます。1つだけ選びます。",
            "",
            "2. 作業・記憶取得CLI",
            "   hookで作業の経験を送り、作業前に関係する記憶を受け取るCLIです。複数選べます。",
            "",
            "同じCLIを両方に選んでも、別々のCLIを選んでも構いません。",
            "個人ナレッジはそのまま使い、必要な場合だけ任意のチームナレッジも共用します。",
            "再実行では既存設定を初期値として使い、明示した変更だけ更新します。ナレッジ、イベント、パターンは保持されます。",
        )
    )


def render_single_choice(title: str, choices: Sequence[SetupChoice]) -> str:
    return "\n".join(_choice_lines(title, choices, multiple=False))


def render_multiple_choices(title: str, choices: Sequence[SetupChoice]) -> str:
    return "\n".join(_choice_lines(title, choices, multiple=True))


def _parse_indexes(answer: str, choices: tuple[SetupChoice, ...], *, multiple: bool) -> tuple[int, ...]:
    if not isinstance(answer, str):
        raise ValueError("SETUP_CHOICE_INVALID")
    raw = answer.strip()
    if not raw:
        raise ValueError("SETUP_CHOICES_REQUIRED" if multiple else "SETUP_CHOICE_REQUIRED")
    parts = tuple(item.strip() for item in raw.split(","))
    if any(not item or not item.isdecimal() for item in parts):
        raise ValueError("SETUP_CHOICE_INVALID")
    indexes = tuple(int(item) for item in parts)
    if not multiple and len(indexes) != 1:
        raise ValueError("SETUP_SINGLE_CHOICE_REQUIRED")
    if any(index < 1 or index > len(choices) for index in indexes):
        raise ValueError("SETUP_CHOICE_INVALID")
    if any(not choices[index - 1].selectable for index in indexes):
        raise ValueError("SETUP_CHOICE_UNAVAILABLE")
    return tuple(dict.fromkeys(indexes))


def parse_single_choice(answer: str, choices: Sequence[SetupChoice]) -> str:
    selected = _validated_choices(choices)
    indexes = _parse_indexes(answer, selected, multiple=False)
    return selected[indexes[0] - 1].value


def parse_multiple_choices(answer: str, choices: Sequence[SetupChoice]) -> tuple[str, ...]:
    selected = _validated_choices(choices)
    indexes = _parse_indexes(answer, selected, multiple=True)
    return tuple(selected[index - 1].value for index in indexes)


def _host_label(host_id: object, custom_labels: Mapping[str, str] | None = None) -> str:
    value = str(host_id or "")
    if value in _HOST_LABELS:
        return _HOST_LABELS[value]
    if isinstance(custom_labels, Mapping) and isinstance(custom_labels.get(value), str) and custom_labels[value]:
        return str(custom_labels[value])
    return "互換カスタムCLI"


def _organizer_label(selection: Any) -> str:
    provider = getattr(selection, "organizer_provider", None)
    if provider is None:
        provider = ""
    provider = str(provider)
    if provider == "subscription-cli":
        host = getattr(selection, "organizer_host", None)
        return _host_label(host) if host else "CLIのAI"
    return _PROVIDER_LABELS.get(provider, "選択した整理AI")


def _organizer_text(provider: object, host: object, custom_labels: Mapping[str, str] | None = None) -> str:
    provider_text = str(provider or "")
    if provider_text == "subscription-cli":
        return _host_label(host, custom_labels) if host else "CLIのAI"
    return _PROVIDER_LABELS.get(provider_text, "選択した整理AI")


def _previous_hosts(previous: Mapping[str, Any] | None) -> set[str]:
    if not isinstance(previous, Mapping):
        return set()
    hosts = previous.get("work_hosts")
    if isinstance(hosts, (list, tuple, set)):
        return {str(item) for item in hosts if isinstance(item, str) and item}
    records = previous.get("hosts")
    if isinstance(records, Mapping):
        return {str(item) for item in records if isinstance(item, str) and item}
    return set()


def _previous_organizer(previous: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    if not isinstance(previous, Mapping):
        return None, None
    organizer = previous.get("organizer")
    if not isinstance(organizer, Mapping):
        return None, None
    provider = organizer.get("provider_id")
    host = organizer.get("host_id")
    return (
        str(provider) if isinstance(provider, str) else None,
        str(host) if isinstance(host, str) else None,
    )


def _previous_store(previous: Mapping[str, Any], kind: str) -> Mapping[str, Any] | None:
    stores = previous.get("knowledge_stores")
    if isinstance(stores, Mapping) and isinstance(stores.get(kind), Mapping):
        return stores[kind]
    if isinstance(previous.get(kind), Mapping):
        return previous[kind]
    if kind == "personal" and isinstance(previous.get("knowledge_repository"), Mapping):
        return previous["knowledge_repository"]
    return None


def _comparison_path(value: object) -> str | None:
    if value is None:
        return None
    try:
        return os.path.normcase(os.path.abspath(os.fspath(value)))
    except (TypeError, ValueError, OSError):
        return str(value)


def _action_host(action: Any) -> str | None:
    details = getattr(action, "details", {})
    if isinstance(details, Mapping) and isinstance(details.get("host_id"), str):
        return str(details["host_id"])
    return None


def _action_text(action: Any) -> str | None:
    name = str(getattr(action, "action", "") or "")
    details = getattr(action, "details", {})
    kind = str(details.get("kind", "")) if isinstance(details, Mapping) else ""
    host = _action_host(action)
    label = _host_label(host) if host else "設定"
    if name in {"unchanged", ""}:
        return None
    if name in {"create", "skill-copy", "skill-link"} or kind.endswith("-create"):
        return f"{label}を追加"
    if name in {"remove", "remove-or-restore"} or kind.endswith("-remove"):
        return f"{label}を削除（管理対象だけ）"
    if name in {"update", "create-or-update"} or kind in {"hook-config", "managed-context", "skill-binding"}:
        return f"{label}の設定を更新"
    return f"{label}の設定を確認"


def _action_is_noop(action: Any) -> bool:
    """Return whether a plan item has no observable change to report."""

    name = str(getattr(action, "action", "") or "")
    if name in {"", "unchanged"}:
        return True
    before = getattr(action, "before_hash", None)
    after = getattr(action, "after_hash", None)
    if before is not None and after is not None and before == after:
        return True
    # Planning deliberately leaves manifest/binding after hashes unresolved;
    # an existing target is still unchanged when no higher-level selection
    # changed.  Applied plans carry their concrete after hash and remain
    # visible when they actually mutate the target.
    return name == "create-or-update" and before is not None and after is None


def render_setup_summary(
    selection: "SetupSelection",
    previous_manifest: Mapping[str, Any] | None,
    actions: Sequence["InstallPlanItem"],
) -> str:
    """Render a confirmation summary without exposing paths or raw commands."""

    previous = previous_manifest if isinstance(previous_manifest, Mapping) else {}
    custom_labels = {
        str(host_id): str(document.get("display_name"))
        for host_id, document in (getattr(selection, "host_profile_documents", {}) or {}).items()
        if isinstance(document, Mapping) and isinstance(document.get("display_name"), str) and document.get("display_name")
    }
    current_hosts = {
        str(item)
        for item in getattr(selection, "work_hosts", ())
        if isinstance(item, str) and item
    }
    previous_hosts = _previous_hosts(previous)
    organizer_provider, organizer_host = _previous_organizer(previous)
    current_provider = getattr(selection, "organizer_provider", None)
    current_host = getattr(selection, "organizer_host", None)
    effective_provider = current_provider if current_provider is not None else organizer_provider
    effective_host = current_host if current_host is not None else organizer_host
    current_organizer = (effective_provider, effective_host)
    action_texts = [
        text
        for action in actions or ()
        if not _action_is_noop(action)
        for text in (_action_text(action),)
        if text
    ]
    selection_changes: list[str] = []
    if current_hosts != previous_hosts:
        selection_changes.append("hosts")
    if current_organizer != (organizer_provider, organizer_host):
        selection_changes.append("organizer")

    previous_personal = _previous_store(previous, "personal")
    previous_root = previous.get("knowledge_root")
    if not isinstance(previous_root, str) and isinstance(previous_personal, Mapping):
        previous_root = previous_personal.get("root")
    current_root = getattr(selection, "personal_knowledge_root", None)
    if current_root is None:
        current_root = getattr(selection, "knowledge_root", None)
    if previous_root is not None and current_root is not None and _comparison_path(previous_root) != _comparison_path(current_root):
        selection_changes.append("personal-root")

    previous_mode = previous_personal.get("mode") if isinstance(previous_personal, Mapping) else None
    current_mode = getattr(selection, "knowledge_mode", None)
    if isinstance(previous_mode, str) and isinstance(current_mode, str) and previous_mode != current_mode:
        selection_changes.append("personal-mode")
    previous_sync = previous.get("sync_enabled")
    if not isinstance(previous_sync, bool) and isinstance(previous_personal, Mapping):
        previous_sync = previous_personal.get("sync_enabled")
    current_sync = getattr(selection, "sync", None)
    if isinstance(previous_sync, bool) and type(current_sync) is bool and previous_sync != current_sync:
        selection_changes.append("sync")
    previous_privacy = previous.get("privacy_profile")
    current_privacy = getattr(selection, "privacy_profile", None)
    if isinstance(previous_privacy, str) and isinstance(current_privacy, str) and previous_privacy != current_privacy:
        selection_changes.append("privacy")
    previous_experiment = previous.get("experiment_enabled")
    current_experiment = getattr(selection, "experiment", None)
    if isinstance(previous_experiment, bool) and type(current_experiment) is bool and previous_experiment != current_experiment:
        selection_changes.append("experiment")
    previous_scheduler = previous.get("scheduler_requested")
    current_scheduler = getattr(selection, "scheduler", None)
    if isinstance(previous_scheduler, bool) and type(current_scheduler) is bool and previous_scheduler != current_scheduler:
        selection_changes.append("scheduler")

    previous_team = _previous_store(previous, "team")
    previous_team_enabled = previous_team.get("enabled") is True if isinstance(previous_team, Mapping) else False
    current_team_enabled = getattr(selection, "team_knowledge", None)
    effective_team_enabled = current_team_enabled if type(current_team_enabled) is bool else previous_team_enabled
    if type(current_team_enabled) is bool and previous and current_team_enabled != previous_team_enabled:
        selection_changes.append("team")
    if current_team_enabled is True and previous_team_enabled and isinstance(previous_team, Mapping):
        current_team_root = getattr(selection, "team_knowledge_root", None)
        if current_team_root is not None and isinstance(previous_team.get("root"), str) and _comparison_path(current_team_root) != _comparison_path(previous_team["root"]):
            selection_changes.append("team-root")
        current_member = getattr(selection, "team_member_id", None)
        if isinstance(current_member, str) and isinstance(previous_team.get("team_member_id"), str) and current_member != previous_team["team_member_id"]:
            selection_changes.append("team-member")

    # ``render_install_plan`` intentionally leaves manifest/binding hashes
    # unresolved.  The semantic fields above make those manifest-only
    # changes visible instead of incorrectly presenting them as a no-op.
    structural_change = bool(selection_changes)
    is_update = bool(previous) or bool(previous_hosts) or organizer_provider is not None
    already_current = is_update and not structural_change and not action_texts
    lines = ["設定内容を確認してください。", ""]
    lines.append(
        f"実行内容: {'ALREADY_CURRENT（変更なし）' if already_current else ('既存設定の更新' if is_update else '新規セットアップ')}"
    )
    lines.append("外部知能: 1つ（既存ナレッジを共用）")
    lines.append(f"記憶の整理AI: {_organizer_text(effective_provider, effective_host, custom_labels)}")
    display_hosts = current_hosts | previous_hosts
    host_labels = [_host_label(item, custom_labels) for item in sorted(display_hosts)]
    lines.append("作業・記憶取得CLI: " + (", ".join(host_labels) if host_labels else "未選択"))
    if effective_team_enabled is True:
        lines.append("チームナレッジ: 使用（個人ナレッジとは別の任意領域）")
    else:
        lines.append("チームナレッジ: 使用しない（個人ナレッジは使用）")

    changes: list[str] = []
    for host_id in sorted(current_hosts - previous_hosts):
        changes.append(f"{_host_label(host_id, custom_labels)}を追加")
    for host_id in sorted(previous_hosts - current_hosts):
        changes.append(f"{_host_label(host_id, custom_labels)}を削除（管理対象だけ）")
    if previous and current_organizer != (organizer_provider, organizer_host):
        changes.append("記憶の整理AIを変更")
    if previous and "personal-root" in selection_changes:
        changes.append("個人ナレッジの保存先を変更")
    if previous and "personal-mode" in selection_changes:
        changes.append("個人ナレッジの保存方法を変更")
    if previous and "sync" in selection_changes:
        changes.append("ナレッジ同期設定を変更")
    if previous and "privacy" in selection_changes:
        changes.append("プライバシー設定を変更")
    if previous and "experiment" in selection_changes:
        changes.append("測定設定を変更")
    if previous and "scheduler" in selection_changes:
        changes.append("保守scheduler設定を変更")
    if previous and any(item.startswith("team") for item in selection_changes):
        changes.append("チームナレッジ設定を変更")
    for text in action_texts:
        if text not in changes:
            changes.append(text)
    lines.append("変更内容:")
    if changes:
        lines.extend(f"  - {item}" for item in changes)
    else:
        lines.append("  - 変更なし")
    lines.extend(
        (
            "ナレッジ: 既存ナレッジは削除・初期化しません",
            "確定後も、選ばなかったCLIの設定や過去のイベント・パターンは変更しません。",
        )
    )
    return "\n".join(lines)


__all__ = [
    "ChoiceStatus",
    "SetupChoice",
    "parse_multiple_choices",
    "parse_single_choice",
    "render_intro",
    "render_multiple_choices",
    "render_setup_summary",
    "render_single_choice",
]
