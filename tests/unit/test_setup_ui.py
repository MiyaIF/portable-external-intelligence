from __future__ import annotations

import unittest
from pathlib import Path

from ei.installer import InstallPlanItem, SetupSelection
from ei.setup_ui import (
    SetupChoice,
    parse_multiple_choices,
    parse_single_choice,
    render_intro,
    render_multiple_choices,
    render_setup_summary,
    render_single_choice,
)


def choices() -> tuple[SetupChoice, ...]:
    return (
        SetupChoice("first", "First CLI", "AVAILABLE", True, "そのまま選べます。"),
        SetupChoice("second", "Second CLI", "AVAILABLE", True, "そのまま選べます。"),
        SetupChoice("third", "Third CLI", "NOT_FOUND", False, "実行ファイルを確認してください。"),
    )


class SetupUiTests(unittest.TestCase):
    def test_intro_explains_the_two_roles_before_selection(self) -> None:
        rendered = render_intro()
        self.assertIn("記憶の整理AI", rendered)
        self.assertIn("1つだけ選びます", rendered)
        self.assertIn("作業・記憶取得CLI", rendered)
        self.assertIn("複数選べます", rendered)
        self.assertIn("再実行では既存設定を初期値として使い", rendered)
        self.assertIn("ナレッジ、イベント、パターンは保持されます", rendered)

    def test_single_choice_shows_example_and_rejects_unavailable(self) -> None:
        rendered = render_single_choice("記憶の整理AI", choices())
        self.assertIn("入力例: 1", rendered)
        self.assertIn("未検出", rendered)
        with self.assertRaisesRegex(ValueError, "SETUP_CHOICE_UNAVAILABLE"):
            parse_single_choice("3", choices())
        self.assertEqual(parse_single_choice("2", choices()), "second")

    def test_multiple_choice_shows_example_and_deduplicates(self) -> None:
        rendered = render_multiple_choices("作業・記憶取得CLI", choices())
        self.assertIn("入力例: 1,2", rendered)
        self.assertEqual(parse_multiple_choices("2,1,2", choices()), ("second", "first"))

    def test_multiple_choice_rejects_empty_or_unavailable(self) -> None:
        with self.assertRaisesRegex(ValueError, "SETUP_CHOICES_REQUIRED"):
            parse_multiple_choices("", choices())
        with self.assertRaisesRegex(ValueError, "SETUP_CHOICE_UNAVAILABLE"):
            parse_multiple_choices("1,3", choices())

    def test_summary_confirms_knowledge_is_preserved_and_shows_update(self) -> None:
        selection = SetupSelection(
            engine_root=Path("C:/engine"),
            knowledge_root=Path("C:/knowledge"),
            runtime_root=Path("C:/runtime"),
            work_hosts=("codex-cli", "gemini-cli"),
            organizer_provider="ollama",
            skip_venv=True,
        )
        previous = {"status": "INSTALLED", "work_hosts": ["codex-cli"], "organizer": {"provider_id": "ollama"}}
        actions = (
            InstallPlanItem(Path("C:/host/hooks.json"), "update", None, None, None, {"kind": "hook-config"}),
            InstallPlanItem(Path("C:/host/skill"), "create", None, None, None, {"kind": "skill"}),
        )
        rendered = render_setup_summary(selection, previous, actions)
        self.assertIn("既存ナレッジは削除・初期化しません", rendered)
        self.assertIn("更新", rendered)
        self.assertIn("Codex CLI", rendered)
        self.assertIn("Gemini CLI", rendered)
        self.assertNotIn("C:/host/hooks.json", rendered)

    def test_summary_for_identical_selection_is_already_current_without_update_claim(self) -> None:
        selection = SetupSelection(
            engine_root=Path("C:/engine"),
            knowledge_root=Path("C:/knowledge"),
            runtime_root=Path("C:/runtime"),
            work_hosts=("codex-cli",),
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            skip_venv=True,
        )
        previous = {
            "status": "INSTALLED",
            "work_hosts": ["codex-cli"],
            "organizer": {"provider_id": "subscription-cli", "host_id": "codex-cli"},
        }
        rendered = render_setup_summary(selection, previous, ())
        self.assertIn("ALREADY_CURRENT", rendered)
        self.assertIn("変更なし", rendered)
        self.assertIn("既存ナレッジは削除・初期化しません", rendered)
        self.assertNotIn("設定を更新", rendered)
        self.assertNotIn("を追加", rendered)

    def test_summary_makes_disabled_team_memory_explicit(self) -> None:
        selection = SetupSelection(
            engine_root=Path("C:/engine"),
            knowledge_root=Path("C:/knowledge"),
            runtime_root=Path("C:/runtime"),
            work_hosts=("codex-cli",),
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            team_knowledge=False,
            skip_venv=True,
        )
        previous = {
            "status": "INSTALLED",
            "work_hosts": ["codex-cli"],
            "organizer": {"provider_id": "subscription-cli", "host_id": "codex-cli"},
            "knowledge_stores": {"team": {"enabled": True}},
        }
        rendered = render_setup_summary(selection, previous, ())
        self.assertIn("チームナレッジ: 使用しない", rendered)
        self.assertIn("個人ナレッジは使用", rendered)
        self.assertNotIn("ALREADY_CURRENT", rendered)
        self.assertIn("チームナレッジ設定を変更", rendered)

    def test_summary_makes_enabled_team_memory_explicit(self) -> None:
        selection = SetupSelection(
            engine_root=Path("C:/engine"),
            knowledge_root=Path("C:/knowledge"),
            runtime_root=Path("C:/runtime"),
            team_knowledge_root=Path("C:/team-knowledge"),
            team_member_id="member-a",
            work_hosts=("codex-cli",),
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            team_knowledge=True,
            skip_venv=True,
        )
        rendered = render_setup_summary(selection, {}, ())
        self.assertIn("チームナレッジ: 使用", rendered)
        self.assertIn("個人ナレッジとは別の任意領域", rendered)

    def test_summary_preserves_omitted_team_state(self) -> None:
        selection = SetupSelection(
            engine_root=Path("C:/engine"),
            knowledge_root=Path("C:/knowledge"),
            runtime_root=Path("C:/runtime"),
            work_hosts=("codex-cli",),
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            team_knowledge=None,
            skip_venv=True,
        )
        previous = {
            "status": "INSTALLED",
            "work_hosts": ["codex-cli"],
            "organizer": {"provider_id": "subscription-cli", "host_id": "codex-cli"},
            "knowledge_stores": {"team": {"enabled": True}},
        }
        rendered = render_setup_summary(selection, previous, ())
        self.assertIn("チームナレッジ: 使用（個人ナレッジとは別の任意領域）", rendered)
        self.assertNotIn("チームナレッジ: 使用しない", rendered)


if __name__ == "__main__":
    unittest.main()
