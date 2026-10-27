import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import patch

from ei.notifications.base import DeliveryResult, NotificationMessage, render_notification
from ei.notifications.cli import encode_user_notice
from ei.notifications import linux, macos, windows
from ei.hooks.base import HookResult
from ei.hooks.codex import CodexAdapter, CodexAppAdapter
from ei.hooks.claude import ClaudeAdapter
from ei.hooks.gemini import GeminiAdapter
from ei.hooks.qwen import QwenAdapter


class NotificationTests(unittest.TestCase):
    def test_unknown_and_partial_custody_are_not_displayed_as_complete_holdings(self):
        try:
            unknown = render_notification("RUNTIME_CATALOG_MISSING", None, pending_count_status="UNKNOWN")
            partial = render_notification("AUTH_FAILED", 3, pending_count_status="PARTIAL")
        except (TypeError, ValueError) as exc:
            self.fail(f"scoped custody rendering unavailable: {type(exc).__name__}")
        self.assertIn("保存領域", unknown.body)
        self.assertIn("件数は未確認", unknown.body)
        self.assertNotIn("0件", unknown.body)
        self.assertIn("確認できた範囲", partial.body)
        self.assertIn("3件", partial.body)
        self.assertIn("総数不明", partial.body)

    def test_unknown_error_is_not_printed(self):
        text = "private source content should never be displayed"
        message = render_notification(text, 3)
        self.assertNotIn(text, message.body)
        self.assertIn("3", message.body)
        self.assertIsNone(encode_user_notice("codex-cli", message, verified=False))

    def test_risk_aliases_and_confirmed_count_only(self):
        for reason in ("CAPACITY_RISK", "EXPIRY_RISK", "PENDING_LOSS_RISK"):
            message = render_notification(reason, 0)
            self.assertIn("保持期限または容量", message.body)
            self.assertIn("0件", message.body)
        self.assertIn("未取得", render_notification("SOURCE_UNAVAILABLE", 2).body)
        self.assertIn("OSの設定", render_notification("SCHEDULER_STOPPED", 2).body)
        self.assertIn("復旧", render_notification("AUTH_FAILED", 2, recovered=True).body)
        for count in (-1, True, 1.2, "3"):
            with self.assertRaises(ValueError):
                render_notification("AUTH_FAILED", count)

    def test_unverified_host_notices_preserve_single_json_contract(self):
        for adapter in (CodexAdapter(), CodexAppAdapter(), ClaudeAdapter(), GeminiAdapter(), QwenAdapter()):
            message = render_notification("AUTH_FAILED", 1)
            self.assertIsNone(encode_user_notice(adapter.host_id, message, verified=True))
            before = adapter.encode(HookResult(True))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                after = adapter.encode(HookResult(True, user_notice=message))
            self.assertEqual(after, before)
            self.assertNotIn(message.body, json.dumps(after, ensure_ascii=False))
            self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_macos_argv_not_script_interpolation_and_output_is_private(self):
        message = NotificationMessage('-e quote " title', 'text <&> " $(private)')
        with patch.object(macos.sys, "platform", "darwin"), patch.object(macos.Path, "is_file", return_value=True), patch.object(macos.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = macos.send_notification(message, timeout_seconds=0.1)
        self.assertEqual(result.status, "SENT")
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "/usr/bin/osascript")
        self.assertEqual(args[0][-2:], [message.title, message.body])
        self.assertEqual(args[0][-3], "--")
        self.assertNotIn(message.body, args[0][2])
        self.assertFalse(kwargs["shell"])
        self.assertLessEqual(kwargs["timeout"], 0.1)
        self.assertEqual(out.getvalue(), "")

    def test_macos_denial_failure_timeout_and_missing(self):
        with patch.object(macos.sys, "platform", "darwin"), patch.object(macos.Path, "is_file", return_value=True), patch.object(macos.subprocess, "run") as run:
            for response, expected in ((subprocess.CompletedProcess([], 1, "", "execution error (-1743) private"), "DENIED"), (subprocess.CompletedProcess([], 1, "", "private"), "FAILED")):
                run.return_value = response
                result = macos.send_notification(render_notification("AUTH_FAILED", 1))
                self.assertEqual(result.status, expected)
                self.assertNotIn("private", repr(result))
            run.side_effect = subprocess.TimeoutExpired("osascript", 0.1)
            self.assertEqual(macos.send_notification(render_notification("AUTH_FAILED", 1)).status, "FAILED")
        with patch.object(macos.sys, "platform", "darwin"), patch.object(macos.Path, "is_file", return_value=False):
            self.assertEqual(macos.send_notification(render_notification("AUTH_FAILED", 1)).status, "UNAVAILABLE")

    def test_linux_service_results_and_literal_gvariant_arguments(self):
        message = NotificationMessage("title", 'a"b\\c<&>')
        with patch.object(linux.sys, "platform", "linux"), patch.dict(linux.os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/test"}), patch.object(linux.Path, "is_file", return_value=True), patch.object(linux.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "(uint32 42,)\n", "")
            result = linux.send_notification(message)
            self.assertEqual(result, DeliveryResult("SENT", "OS_ACCEPTED", "42"))
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/gdbus")
            self.assertIn("org.freedesktop.Notifications.Notify", argv)
            self.assertIn('"a\\"b\\\\c&lt;&amp;&gt;"', argv)
            self.assertFalse(run.call_args.kwargs["shell"])
            for stderr, expected in (("org.freedesktop.DBus.Error.ServiceUnknown", "UNAVAILABLE"), ("org.freedesktop.DBus.Error.AccessDenied", "DENIED"), ("unknown private", "FAILED")):
                run.return_value = subprocess.CompletedProcess([], 1, "", stderr)
                result = linux.send_notification(message)
                self.assertEqual(result.status, expected)
                self.assertNotIn("private", repr(result))
            run.return_value = subprocess.CompletedProcess([], 0, "private malformed", "")
            self.assertEqual(linux.send_notification(message).status, "FAILED")
            run.side_effect = subprocess.TimeoutExpired("gdbus", 0.1)
            self.assertEqual(linux.send_notification(message).status, "FAILED")

    def test_linux_headless_and_missing_client_are_unavailable(self):
        with patch.object(linux.sys, "platform", "linux"), patch.dict(linux.os.environ, {}, clear=True):
            self.assertEqual(linux.send_notification(render_notification("AUTH_FAILED", 1)).status, "UNAVAILABLE")
        with patch.object(linux.sys, "platform", "linux"), patch.dict(linux.os.environ, {"DBUS_SESSION_BUS_ADDRESS": "x"}), patch.object(linux.Path, "is_file", return_value=False):
            self.assertEqual(linux.send_notification(render_notification("AUTH_FAILED", 1)).status, "UNAVAILABLE")

    def test_windows_unregistered_is_unavailable_and_registered_send_is_hidden(self):
        with patch.object(windows.sys, "platform", "win32"), patch.object(windows.Path, "is_file", return_value=False):
            self.assertEqual(windows.send_notification(render_notification("AUTH_FAILED", 1)).status, "UNAVAILABLE")
        with patch.object(windows.sys, "platform", "win32"), patch.dict(windows.os.environ, {"SystemRoot": "C:/Windows", "APPDATA": "C:/Roaming", "LOCALAPPDATA": "C:/Local"}), patch.object(windows.Path, "is_file", return_value=True), patch.object(windows.subprocess, "run") as run:
            for output, status in (("SENT", "SENT"), ("DENIED", "DENIED"), ("UNAVAILABLE", "UNAVAILABLE"), ("private error", "FAILED")):
                run.return_value = subprocess.CompletedProcess([], 0, output, "")
                result = windows.send_notification(render_notification("AUTH_FAILED", 1))
                self.assertEqual(result.status, status)
                self.assertNotIn("private", repr(result))
            argv = run.call_args.args[0]
            self.assertIn("-NonInteractive", argv)
            self.assertIn("-File", argv)
            self.assertNotIn("-ExecutionPolicy", argv)
            self.assertNotIn("-Command", argv)
            kwargs = run.call_args.kwargs
            self.assertTrue(kwargs["creationflags"] & 0x08000000)
            self.assertFalse(kwargs["shell"])
            self.assertEqual(json.loads(kwargs["input"])["title"], "External Intelligence")
            run.return_value = subprocess.CompletedProcess([], 1, "", "PSSecurityException UnauthorizedAccess")
            self.assertEqual(windows.send_notification(render_notification("AUTH_FAILED", 1)).status, "DENIED")
            run.side_effect = subprocess.TimeoutExpired("powershell", 0.1)
            self.assertEqual(windows.send_notification(render_notification("AUTH_FAILED", 1)).status, "FAILED")

    def test_delivery_result_cannot_claim_arbitrary_status_or_free_text(self):
        for status, reason, delivery_id in (("OK", "OS_ACCEPTED", None), ("SENT", "private body", None), ("SENT", "OS_ACCEPTED", "private /path")):
            with self.assertRaises(ValueError):
                DeliveryResult(status, reason, delivery_id)

    def test_invalid_timeout_cannot_launch_an_adapter(self):
        for module in (windows, macos, linux):
            for timeout in (0, -1, float("inf"), float("nan"), True):
                with self.assertRaises(ValueError):
                    module.send_notification(render_notification("AUTH_FAILED", 1), timeout_seconds=timeout)


if __name__ == "__main__":
    unittest.main()
