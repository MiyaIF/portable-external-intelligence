"""Post-setup guidance. User acknowledgement is never Hook evidence."""
from __future__ import annotations

from typing import Any, Mapping, TYPE_CHECKING

from .canary import read_hook_status
from .config import load_settings
from .stdio import write_utf8
from .task_scheduler import inspect_registered_task

if TYPE_CHECKING:
    from .installer import SetupResult, SetupSelection


_HOOK_GUIDANCE = {
    "codex-cli": "別のターミナルでCodex CLIを起動し、/hooks でExternal intelligenceのHook内容を確認して承認してください。Codex Appは対象外です。",
    "claude-code": "別のターミナルでClaude Codeを起動し、/hooks で外部知能のHookを確認し、変更の承認が求められたら内容を確認してください。",
    "gemini-cli": "別のターミナルでGemini CLIを起動し、/hooks list で外部知能のHookを確認してください。無効な場合はそのHookだけを有効化し、同意の画面に従ってください。",
    "qwen-code": "別のターミナルでQwen Codeを起動し、公式のHook設定・起動時の確認画面で外部知能のHookを確認してください。",
}


def activation_report(host_ids, hosts, scheduler, requested: bool) -> dict[str, Any]:
    rows = {row.get("host_id"): row for row in hosts if isinstance(row, Mapping)}
    hooks = []
    for host_id in host_ids:
        row = rows.get(host_id, {})
        static = row.get("static_checks", {})
        verified = row.get("hook_status") == "HOOK_VERIFIED" and isinstance(static, Mapping) and static.get("valid") is True
        hooks.append({
            "host_id": host_id, "status": "VERIFIED" if verified else "UNVERIFIED",
            "received_events": list(row.get("received_events", ())),
            "next_action": "" if verified else _HOOK_GUIDANCE.get(host_id, "互換CLI自身のHook承認手順に従ってください。adapterの互換性だけでは承認・動作確認済みになりません。"),
        })
    scheduler = scheduler if isinstance(scheduler, Mapping) else {}
    verification = scheduler.get("verification", {})
    enabled = isinstance(verification, Mapping) and verification.get("ok") is True and verification.get("registered") is True
    maintenance = {
        "requested": requested,
        "status": "ENABLED" if requested and enabled else "UNVERIFIED" if requested else "DISABLED",
    }
    return {"hooks": hooks, "maintenance": maintenance, "automatic_operation": "UNVERIFIED"}


def _refresh(selection: SetupSelection) -> dict[str, Any]:
    settings = load_settings(
        engine_root=selection.engine_root or selection.repo_root,
        knowledge_root=selection.personal_knowledge_root or selection.knowledge_root,
        runtime_root=selection.runtime_root,
    )
    rows = []
    for host_id in selection.work_hosts or selection.hosts:
        try:
            rows.append(read_hook_status(host_id, host_id, settings).to_dict())
        except (OSError, ValueError, TypeError):
            rows.append({"host_id": host_id, "hook_status": "HOOK_UNVERIFIED"})
    try:
        scheduler = {"verification": inspect_registered_task(settings)} if selection.scheduler else {}
    except (OSError, ValueError, TypeError):
        scheduler = {}
    return activation_report(selection.work_hosts or selection.hosts, rows, scheduler, bool(selection.scheduler))


def render_activation(report: Mapping[str, Any]) -> str:
    lines = ["", "設定完了後の動作確認（設定完了と自動運用の確認は別です）"]
    for row in report["hooks"]:
        lines.append(f"  {row['host_id']} のHook受信: {'確認済み' if row['status'] == 'VERIFIED' else '未確認'}")
        if row["next_action"]:
            lines.append("    " + row["next_action"])
    maintenance = report["maintenance"]["status"]
    labels = {"ENABLED": "有効（継続稼働の実績は別途確認）", "DISABLED": "無効（自動整理は実行されません）", "UNVERIFIED": "未確認・停止の可能性あり（登録情報だけでは有効と判定しません）"}
    lines.append("  定期処理: " + labels[maintenance])
    if maintenance != "ENABLED":
        lines.append("    自動整理を使う場合はsetupで有効化してください。停止中のタスクはOSのタスク管理画面で状態・実行結果を確認してください。")
    lines.append("未確認: 作業から蓄積・整理・次回取得までの一連の実運用。Hook受信だけでは運用完了にはなりません。")
    lines.append("確認する場合は、対象CLIで新しいセッションを開始し、機密情報を含まない短い依頼を1回送り、応答後にセッションを終了してください。AIの利用枠を消費する場合があります。")
    return "\n".join(lines)


def setup_result_with_guidance(selection: SetupSelection, result: SetupResult, *, interactive: bool = False, check_only: bool = False) -> dict[str, Any]:
    value = result.to_dict()
    if check_only or value.get("status") == "CHECK_ONLY":
        return value
    retained = isinstance(value.get("rollback"), Mapping) and value["rollback"].get("status") == "INSTALLATION_RETAINED"
    if not value.get("ok") and not retained:
        return value
    report = activation_report(selection.work_hosts or selection.hosts, value.get("hosts", ()), value.get("scheduler", {}), bool(selection.scheduler))
    reconciliation = value.get("reconciliation", {})
    if isinstance(reconciliation, Mapping) and reconciliation.get("status") == "ALREADY_CURRENT":
        try:
            report = _refresh(selection)
        except (OSError, ValueError, TypeError):
            report["verification_error"] = "ACTIVATION_STATUS_UNAVAILABLE"
    if interactive:
        write_utf8(render_activation(report))
        # No receipt/state reads on check-only. Never start a model, fabricate
        # receipts, mutate trust, or interpret the user's answer as verification.
        if isinstance(value.get("manifest_path"), str):
            while True:
                write_utf8("CLI側の操作後に r で再確認、後で行う場合は Enter（設定は保持します）: ", end="")
                try:
                    answer = input().strip().casefold()
                except (EOFError, KeyboardInterrupt):
                    break
                if answer != "r":
                    break
                try:
                    report = _refresh(selection)
                except (OSError, ValueError, TypeError):
                    report = activation_report(selection.work_hosts or selection.hosts, (), {}, bool(selection.scheduler))
                    write_utf8("状態の再取得に失敗しました。設定は保持しています。setupを再実行して確認できます。")
                write_utf8(render_activation(report))
    value["activation"] = report
    return value
