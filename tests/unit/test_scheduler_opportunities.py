import json
import tempfile
import unittest
from pathlib import Path
from datetime import timedelta
from unittest.mock import patch
from subprocess import CompletedProcess
from xml.sax.saxutils import escape

from tests.unattended_helpers import NOW, make_settings
from ei import task_scheduler as scheduler
from ei.operation_runtime import OperationBudget


def sample(**updates):
    value = {"platform": "linux", "identity_verified": True, "registered": True,
        "enabled": True, "running": False, "conditions_verified": True,
        "boot_id": "boot-one", "generation": "timer-generation-one", "definition_hash": "a" * 64,
        "monotonic_us": 200_000_000, "awake_us": 200_000_000, "observed_at": NOW.isoformat(),
        "activation_us": 100_000_000, "accuracy_us": 1_000_000, "random_delay_us": 0,
        "timers": [["OnUnitActiveUSec", 1800_000_000, 1900_000_000], ["OnUnitActiveUSec", 3600_000_000, 3700_000_000]],
        "next_run_at": (NOW + timedelta(seconds=1700)).isoformat()}
    value.update(updates)
    return value


class SchedulerOpportunityTests(unittest.TestCase):
    def test_resumption_requires_new_timer_trigger_and_actual_successful_service_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            previous = sample(last_trigger_us=100_000_000, service_activation_us=100_000_000)
            current = sample(monotonic_us=4500_000_000, awake_us=4500_000_000,
                observed_at=(NOW + timedelta(seconds=4300)).isoformat(), last_exit="success",
                activation_us=4000_000_000, last_trigger_us=4000_000_000, service_activation_us=4000_000_000,
                timers=[["OnUnitActiveUSec", 1800_000_000, 5800_000_000], ["OnUnitActiveUSec", 3600_000_000, 7600_000_000]])
            self.assertEqual(self.inspect(settings, current, previous=previous)["reason_code"], "SCHEDULER_EXECUTION_RESUMED")
            for change in ({"service_activation_us": 100_000_000}, {"last_trigger_us": 100_000_000}, {"last_exit": "exit-code"}, {"generation": "new"}, {"awake_us": 3000_000_000}):
                with self.subTest(change=change):
                    self.assertNotEqual(self.inspect(settings, {**current, **change}, previous=previous)["reason_code"], "SCHEDULER_EXECUTION_RESUMED")

    def native_fixture(self, root):
        from ei.config import RuntimePaths, Settings
        engine, knowledge = root / "engine", root / "knowledge"
        engine.mkdir()
        knowledge.mkdir()
        executable = root / "python"
        executable.write_bytes(b"fake executable - must never run")
        settings = Settings(paths=RuntimePaths(engine, knowledge, root / "runtime"))
        action = scheduler.build_maintenance_action(settings, executable)
        scheduler.write_scheduler_state(settings, action, True)
        return settings, action

    def test_linux_native_arrays_action_and_property_types_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings, action = self.native_fixture(root)
            units = root / "units"
            units.mkdir()
            (units / f"{scheduler.TASK_NAME}.service").write_text(scheduler.build_systemd_user_unit(action), encoding="utf-8")
            (units / f"{scheduler.TASK_NAME}.timer").write_text(scheduler.build_systemd_user_timer(action), encoding="utf-8")
            props = {
                "TimersMonotonic": ("a(stt)", sample()["timers"]), "TimersCalendar": ("a(sst)", []),
                "AccuracyUSec": ("t", 1000000), "RandomizedDelayUSec": ("t", 0), "WakeSystem": ("b", False), "LastTriggerUSecMonotonic": ("t", 100000000),
                "InvocationID": ("ay", [1] * 16), "ActiveState": ("s", "active"), "UnitFileState": ("s", "enabled"), "NeedDaemonReload": ("b", False),
                "Conditions": ("a(sbbsi)", []), "Asserts": ("a(sbbsi)", []), "DropInPaths": ("as", []), "Job": ("(uo)", [0, "/"]),
                "InactiveExitTimestampMonotonic": ("t", 100000000), "ExecStart": ("a(sasbttttuii)", [[str(action.executable), [str(action.executable), *action.argv], False, 0, 0, 0, 0, 0, 0, 0]]),
                "ExecCondition": ("a(sasbttttuii)", []), "WorkingDirectory": ("s", str(settings.paths.engine_root)), "Result": ("s", "success")}
            def query(argv, **kwargs):
                self.assertLessEqual(kwargs["timeout"], 2)
                self.assertIn("--allow-interactive-authorization=no", argv)
                if "GetUnit" in argv:
                    kind = "timer" if argv[-1].endswith(".timer") else "service"
                    return CompletedProcess(argv, 0, f'o "/org/freedesktop/systemd1/unit/{kind}"\n', "")
                offset = argv.index("get-property")
                kind = argv[offset + 2].rsplit("/", 1)[1]
                data = []
                for key in argv[offset + 4:]:
                    if key == "FragmentPath":
                        typ, value = "s", str(units / f"{scheduler.TASK_NAME}.{kind}")
                    elif key == "ActiveState" and kind == "service":
                        typ, value = "s", "inactive"
                    else:
                        typ, value = props[key]
                    data.append(json.dumps({"type": typ, "data": value}))
                return CompletedProcess(argv, 0, "\n".join(data), "")
            with patch("ei.task_scheduler._normalise_platform", return_value="linux"), patch("ei.task_scheduler._scheduler_clocks", return_value=("boot", 200000000, 200000000)), patch("ei.task_scheduler._systemd_user_dir", return_value=units), patch("ei.task_scheduler.subprocess.run", side_effect=query):
                observed = scheduler._native_scheduler_sample(settings, now=NOW, budget=OperationBudget(5000))
                self.assertTrue(observed["identity_verified"])
                self.assertTrue(observed["conditions_verified"])
                self.assertEqual(observed["timers"], [["OnUnitActiveUSec", 1800000000, 1900000000], ["OnUnitActiveUSec", 3600000000, 3700000000]])
                props["AccuracyUSec"] = ("s", 1000000)
                with self.assertRaisesRegex(ValueError, "SCHEDULER_QUERY_INVALID"):
                    scheduler._native_scheduler_sample(settings, now=NOW, budget=OperationBudget(5000))

    def test_macos_native_read_keeps_exit_but_does_not_infer_override_enablement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings, action = self.native_fixture(root)
            agents = root / "agents"
            agents.mkdir()
            (agents / f"{scheduler.TASK_NAME}.plist").write_text(scheduler.build_launchd_plist(action), encoding="utf-8")
            output = CompletedProcess([], 0, "state = waiting\nlast exit code = 78\nruns = 2\n", "")
            with patch("ei.task_scheduler._normalise_platform", return_value="macos"), patch("ei.task_scheduler._scheduler_clocks", return_value=("boot", 20, 10)), patch("ei.task_scheduler._launch_agents_dir", return_value=agents), patch("ei.task_scheduler.subprocess.run", return_value=output):
                value = scheduler._native_scheduler_sample(settings, now=NOW, budget=OperationBudget(5000))
            self.assertTrue(value["identity_verified"])
            self.assertEqual(value["last_exit"], 78)
            self.assertIsNone(value["generation"])
            self.assertIsNone(value["enabled"])
            self.assertFalse(value["plist_disabled"])

    def test_windows_native_read_retains_logon_and_battery_conditions_without_eligibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action = self.native_fixture(Path(tmp))
            fields = action.to_dict()
            xml = '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec>' + ''.join(f'<{tag}>{escape(fields[key])}</{tag}>' for tag, key in (("Command", "executable"), ("Arguments", "arguments"), ("WorkingDirectory", "working_directory"))) + '</Exec></Actions><Principals><Principal><LogonType>InteractiveToken</LogonType></Principal></Principals><Settings><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><RunOnlyIfIdle>false</RunOnlyIfIdle></Settings></Task>'
            native = {"xml": xml, "enabled": True, "state": "Ready", "last_exit": 2147943726, "last_run": NOW.isoformat(), "next_run": NOW.isoformat(), "native_missed_runs": 5, "boot": NOW.isoformat()}
            with patch("ei.task_scheduler._normalise_platform", return_value="windows"), patch("ei.task_scheduler._scheduler_clocks", return_value=(None, 20, 10)), patch("ei.task_scheduler.subprocess.run", return_value=CompletedProcess([], 0, json.dumps(native), "")):
                value = scheduler._native_scheduler_sample(settings, now=NOW, budget=OperationBudget(5000))
            self.assertTrue(value["identity_verified"])
            self.assertEqual(value["conditions"]["LogonType"], "InteractiveToken")
            self.assertEqual(value["conditions"]["DisallowStartIfOnBatteries"], "true")
            self.assertEqual(value["native_missed_runs"], 5)
            self.assertFalse(value["conditions_verified"])

    def test_windows_power_off_missed_count_is_not_eligible_and_is_still_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            native = sample(platform="windows", native_missed_runs=5, last_exit=2147943726, generation=None)
            result = self.inspect(settings, native, previous=native)
            self.assertIsNone(result["missed_eligible_runs"])
            self.assertEqual(result["reason_code"], "SCHEDULER_OPPORTUNITY_EVIDENCE_UNAVAILABLE")
            self.assertEqual(result["native"]["native_missed_runs"], 5)
            self.assertTrue(result["native"]["registered"])

    def test_baseline_is_retained_between_due_points_and_readonly_never_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            prior = sample()
            middle = sample(monotonic_us=2000_000_000, awake_us=2000_000_000, observed_at=(NOW + timedelta(seconds=1800)).isoformat())
            result = self.inspect(settings, middle, previous=prior)
            self.assertEqual(result["missed_eligible_runs"], 1)
            before = {path: path.read_bytes() for path in settings.paths.runtime_root.rglob("*") if path.is_file()}
            current = sample(monotonic_us=3800_000_000, awake_us=3800_000_000, observed_at=(NOW + timedelta(seconds=3600)).isoformat())
            with patch("ei.task_scheduler._native_scheduler_sample", return_value=current):
                readonly = scheduler.inspect_scheduler_opportunities(settings, now=NOW + timedelta(seconds=3600), budget=OperationBudget(1000), read_only=True)
            self.assertEqual(readonly["missed_eligible_runs"], 2)
            self.assertEqual({path: path.read_bytes() for path in settings.paths.runtime_root.rglob("*") if path.is_file()}, before)

    def test_minimum_next_elapse_duplicate_or_unbound_instants_are_not_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            for timers in ([], [sample()["timers"][0]] * 2, [["OnUnitActiveUSec", 1800_000_000, 1800_000_000], ["OnUnitActiveUSec", 3600_000_000, 3600_000_000]]):
                with self.subTest(timers=timers):
                    prior = sample(timers=timers, next_elapse_us=1900_000_000)
                    current = {**prior, "monotonic_us": 3800_000_000, "awake_us": 3800_000_000, "observed_at": (NOW + timedelta(seconds=3600)).isoformat()}
                    self.assertIsNone(self.inspect(settings, current, previous=prior)["missed_eligible_runs"])

    def inspect(self, settings, current, *, previous=None):
        function = getattr(scheduler, "inspect_scheduler_opportunities", None)
        self.assertTrue(callable(function), "native opportunity inspection is missing")
        if previous is not None:
            settings.paths.runtime_dir.mkdir(parents=True, exist_ok=True)
            from ei.operation_runtime import settings_binding
            (settings.paths.runtime_dir / "scheduler-opportunities.json").write_text(json.dumps({"schema_version": 1,
                "binding": settings_binding(settings), "sample": previous}))
        settings.paths.install_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        settings.paths.install_manifest_path.write_text(json.dumps({"scheduler_requested": True}))
        with patch("ei.task_scheduler._native_scheduler_sample", return_value=current):
            return function(settings, now=__import__("datetime").datetime.fromisoformat(current["observed_at"]), budget=OperationBudget(1000))

    def test_two_real_native_timer_points_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            prior = sample()
            current = sample(monotonic_us=3800_000_000, awake_us=3800_000_000,
                             observed_at=(NOW + timedelta(seconds=3600)).isoformat())
            result = self.inspect(settings, current, previous=prior)
            self.assertEqual(result["missed_eligible_runs"], 2)
            self.assertEqual(result["reason_code"], "SCHEDULER_MISSED_OPPORTUNITIES")
            legacy = sample(timers=prior["timers"][:1])
            result = self.inspect(settings, {**current, "timers": legacy["timers"]}, previous=legacy)
            self.assertIsNone(result["missed_eligible_runs"])
            self.assertEqual(result["reason_code"], "SCHEDULER_SECOND_OPPORTUNITY_UNAVAILABLE")

    def test_suspend_reboot_rearm_running_conditions_clock_jump_do_not_warn(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            current = sample(monotonic_us=3800_000_000, awake_us=3800_000_000,
                             observed_at=(NOW + timedelta(seconds=3600)).isoformat())
            variants = ({"awake_us": 3000_000_000}, {"boot_id": "boot-two"}, {"generation": "other"},
                {"activation_us": 3600_000_000}, {"running": True}, {"conditions_verified": False},
                {"observed_at": (NOW + timedelta(days=4)).isoformat()}, {"enabled": False},
                {"accuracy_us": 7200_000_000}, {"random_delay_us": 7200_000_000})
            for update in variants:
                with self.subTest(update=update):
                    result = self.inspect(settings, {**current, **update}, previous=sample())
                    self.assertNotEqual(result["missed_eligible_runs"], 2)

    def test_explicit_disabled_never_queries_native_or_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            settings.paths.install_manifest_path.parent.mkdir(parents=True)
            settings.paths.install_manifest_path.write_text('{"scheduler_requested":false}')
            function = getattr(scheduler, "inspect_scheduler_opportunities", None)
            self.assertTrue(callable(function))
            with patch("ei.task_scheduler._native_scheduler_sample", side_effect=AssertionError("native read when disabled")):
                result = function(settings, now=NOW)
            self.assertFalse(result["requested"])
            self.assertEqual(result["missed_eligible_runs"], 0)
            self.assertFalse((settings.paths.runtime_dir / "scheduler-opportunities.json").exists())

    def test_macos_native_observation_is_not_job_generation_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            native = sample(platform="macos", generation=None, last_exit=78, runs=2)
            result = self.inspect(settings, native, previous=native)
            self.assertIsNone(result["missed_eligible_runs"])
            self.assertEqual(result["reason_code"], "SCHEDULER_GENERATION_EVIDENCE_UNAVAILABLE")
            self.assertEqual(result["native"]["last_exit"], 78)
