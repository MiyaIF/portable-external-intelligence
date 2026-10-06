# Reliable Automatic Accumulation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 通常運用に追加の確認を挟まず、収集漏れの検知・回収、候補保持、障害復旧、利用者への異常通知を行う。

**Architecture:** 既存の暗号化spool、処理queue、append-only journal、単一整理AIを再利用する。収集追跡、回収、運用状態、通知を小さい独立モジュールに分け、Hookでは軽量処理、定期処理では回収と整理を実行する。設定、受付、保存、次回取得、通知送信、通知の実表示を別々の証拠として扱う。

**Tech Stack:** Python 3.11+、標準ライブラリ、既存のcryptography、JSON Schema、unittest、PowerShell、OS標準通知機能。新しい常駐アプリ・必須Python依存は追加しない。

**Spec:** [承認済み設計](../specs/2026-09-18-reliable-automatic-accumulation-design.md)

## Global Constraints

- 通常運用は無操作とする。setupで設定した範囲内では、収集、整理、保存、再試行、復旧に都度の承認を求めない。正常時の完了通知も出さない。
- 外部知能は論理的に1つ、整理AIは1つ、作業・記憶取得CLIは複数のまま維持する。
- 公開エンジンに個人ナレッジ、端末固有パス、認証情報を置かない。
- 生のプロンプト、応答、会話履歴、ツール出力、秘密情報、顧客機密を新たに保存しない。
- 生の会話履歴を後から読み直す収集経路は追加しない。取得元は許可された構造化記憶・要約・直接渡された再利用候補に限定する。
- 別の整理AIへの自動切替、追加課金、利用枠リセット、自動モデルダウンロードはしない。
- OS・CLIの承認、ログイン、通知拒否、集中モード、利用者による定期処理停止を迂回しない。
- 新しい常駐アプリ、通知用サービスへの登録、メール・チャット連携を必須にしない。
- setupの再実行・updateで既存の知識、identity、明示的な無効設定を初期化しない。
- 新規の未整理候補は既定30日、1,000件または暗号文64MiB。既存候補の期限と利用者が明示した設定を保持する。
- 容量80%以上または期限まで24時間以下で喪失リスクを判定する。満杯時は受付成功・cursor前進を返さない。
- 再試行間隔は300 / 900 / 3,600 / 21,600秒。Providerが指定する期限が長ければそちらを優先する。
- 同一未解決障害のOS再通知は24時間に1回以下。通知送信失敗の再試行は1時間に1回以下。CLIはsessionごとに1回。
- 既存journalは書換え・削除しない。旧記録にない収集証拠を成功として補完しない。
- 対象テストとcomplete unittest suiteの成功を各commitの条件とする。各TaskのFilesに列挙したファイルだけをstageする。
- 個人環境の更新、OS登録、実AI利用、公的公開は、コード実装・模擬検証と別の実行境界とする。公開用の手順を経ずに開発履歴をpushしない。

---

## 現状・実行境界

計画作成時点の基点は設計commit `1bead27`。この計画自身は機能の実装結果ではない。既存の保守文書に合わせて`docs/plans/`へ置く。`docs/superpowers/`は公開exportから除外されるため使用しない。

確認した接続点:

- `hook_entry.handle_normalized_hook`の`turn.stop`は本文なしのqueue受付。これだけで再利用候補を確保したことにはならない。
- `capture.record_agent_observation`と`ingest`は構造化済みの候補を扱う。`reconcile_fallback`は重複照合であり、未生成の知識を復元する機能ではない。
- `spool.write_spool`は暗号化・容量制限・原子的書込みを既に持つ。`queue`はlease、状態遷移、緊急回収を持つ。
- `ProviderRouter.generate`の既存予算消費はProvider呼出し後。呼出し前の予約が必要。
- `maintainer._process_claimed`はHook用`prompt_budget_ms`を推論に渡している。整理AIには`BudgetPolicy.deadline_ms`と保守処理の残り時間を使う。
- `setup_activation`は現在、自動運用を常に`UNVERIFIED`とする。新しい証拠なしにこの状態を変えない。

今回の文書変更は本計画と設計書の2ファイルのみ。以下のTask 1〜10は実装実行時に順番に行う。各Taskは実装・テスト・レビューを一組とし、Task間で未完成コードを実環境へ配布しない。

## ファイル責務と依存

| Task | 新しい主要モジュール | 責務 / 次への出力 |
| --- | --- | --- |
| 1 | `capture_contract.py` | ID、収集状態、保持設定の契約 |
| 2 | `capture_ledger.py` | 対象と受付の機械ローカルな関連付け |
| 3 | `pending_capture.py` | 暗号化候補と既存queueの耐障害受付 |
| 4 | `capture_recovery.py` | 許可された構造化取得元の有界な回収 |
| 5 | `organizer_recovery.py` | 再試行、予算予約、推論結果の再利用 |
| 6 | `operation_health.py`, `incidents.py` | 純粋な異常判定と永続incident |
| 7 | `notifications/` | 安全なOS送信と実証済みCLI表示 |
| 8 | `operation_runtime.py` | Hook・定期処理・statusへの接続 |
| 9 | `operation_activation.py` | setupの初回説明、設定保持、独立した証拠 |
| 10 | 障害注入テスト・運用文書 | OS/Host別の実証と公開判定 |

Task 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10。既存`maintainer.py`、`cli.py`には呼出し接続を置き、状態機械本体を増設しない。公開済みCLI名以外は架空ID`test-compatible-cli`だけをテストで使う。

### 共通の検証・commit手順

以下の`python`は当該checkoutの仮想環境のPythonを指す。Windowsでは`.venv/Scripts/python.exe`、POSIXでは`.venv/bin/python`を明示して実行する。グローバルPythonやユーザーの実knowledgeをテストに流用しない。

1. 各Taskの新テストを実行し、期待した未実装機能が原因で失敗することを確認する。
2. 最小実装後、列挙した対象テストを実行する。失敗を隠すskipを追加しない。
3. `scripts/run-release-validation.py`で全モジュールを実行する。全結果の成功、crash・timeoutゼロ、skip理由を確認する。
4. `git diff --check`、ソース監査、差分自己レビューを行う。実装仕様を変える必要が出た場合のみ、仕様変更の判断を先に求める。
5. Files欄の実際に変更したファイル名を明示して`git add`し、`git diff --cached --name-only`と一致させ、`git commit --signoff`する。

```powershell
python -B -X utf8 scripts/run-release-validation.py --jobs 2 --timeout-seconds 300
python -B -X utf8 scripts/audit-production-source.py --repo . --json
git diff --check
git diff --cached --name-only
```

**全体テスト用checkout:** clone試験は元ディレクトリを複製するため、古い`artifacts/`を含む作業checkoutから直接走らせない。公開export対象と同じ内容のクリーンな検証用checkoutを使い、変更前後の入力ファイルhashと全テスト集計を残す。privateな`tests.acceptance.test_implementation_plan_contract`は開発checkoutで別途実行する。クリーンなcheckoutを作るために利用者の既存成果物を削除しない。検証用checkoutへの複製は公開・pushではない。

### Task 1: 収集ID・状態・保持設定の契約

**Files:**

- Create: `src/ei/capture_contract.py`
- Create: `schemas/capture-receipt.schema.json`
- Create: `tests/unattended_helpers.py`
- Create: `tests/unit/test_capture_contract.py`
- Modify: `src/ei/hooks/base.py`、`schemas/hook-event.schema.json`
- Modify: `src/ei/models.py`、`policies/capture-policy.json`
- Modify: `src/ei/journal.py`（手書きvalidatorへの新しい任意field・receipt登録）
- Test: `tests/unit/test_capture.py`、`tests/unit/test_spool.py`

**Interfaces:** `CaptureIdentity`、`CaptureReceipt`、`PendingPolicy`、`capture_key(identity) -> str | None`、`pending_policy(mapping) -> PendingPolicy`を本Taskで定義する。時刻はUTC aware datetime。永続化時だけISO文字列へ変換する。`store_id`は既存store identityに由来するhashで、パスを使わない。targetのrecord_hashはHostの安定したevent IDから、候補のrecord_hashは安定したrecord IDから別namespaceで生成し、`covered_target_ids`で対応付ける。IDがない場合に本文hashだけで対応を推定しない。

- [ ] 次を`capture_contract.py`の公開データ型とし、同じ型を後続で使う。

```python
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

CaptureState = Literal["WAITING", "SECURED", "EVALUATED_NONE", "UNAVAILABLE", "UNKNOWN"]

@dataclass(frozen=True)
class CaptureIdentity:
    host_id: str
    instance_hash: str
    store_id: str
    session_hash: str | None
    turn_hash: str | None
    record_hash: str | None

@dataclass(frozen=True)
class CaptureReceipt:
    capture_id: str
    state: CaptureState
    candidate_ids: tuple[str, ...]
    covered_target_ids: tuple[str, ...]
    reason_code: str
    updated_at: datetime
    candidate_hashes: tuple[tuple[str, str], ...] = ()

@dataclass(frozen=True)
class PendingPolicy:
    ttl_seconds: int = 2_592_000
    max_items: int = 1_000
    max_bytes: int = 67_108_864
```

- [ ] 共通fixtureを`tests/unattended_helpers.py`へ追加する。新規コードテストはこのfixtureだけで隔離する。

```python
from datetime import datetime, timezone
from pathlib import Path
from ei.config import RuntimePaths, Settings
from ei.capture_contract import CaptureIdentity

NOW = datetime(2026, 9, 18, tzinfo=timezone.utc)

def make_settings(root: Path) -> Settings:
    return Settings(paths=RuntimePaths(
        engine_root=root / "engine", knowledge_root=root / "knowledge",
        runtime_root=root / "runtime"))

def identity(record: str = "a") -> CaptureIdentity:
    return CaptureIdentity("codex-cli", "sha256:" + "1" * 64,
                           "sha256:" + "2" * 64, "sha256:" + "3" * 64,
                           "sha256:" + "4" * 64, "sha256:" + record * 64)
```

- [ ] `tests/unit/test_capture_contract.py`へ最初の失敗テストを追加する。

```python
import unittest
from dataclasses import replace
from ei.capture_contract import capture_key, pending_policy
from tests.unattended_helpers import identity

class CaptureContractTests(unittest.TestCase):
    def test_missing_identity_is_not_a_shared_key(self):
        self.assertIsNone(capture_key(replace(identity(), record_hash=None)))
        self.assertEqual(capture_key(identity()), capture_key(identity()))
        self.assertNotEqual(capture_key(identity()), capture_key(identity("b")))

    def test_explicit_old_retention_survives(self):
        self.assertEqual(pending_policy({}).ttl_seconds, 2_592_000)
        self.assertEqual(pending_policy({"ttl_seconds": 600}).ttl_seconds, 600)
        with self.assertRaises(ValueError):
            pending_policy({"max_items": True})
```

- [ ] `python -m unittest tests.unit.test_capture_contract -v`で未定義importの失敗を確認する。
- [ ] identityをcanonical JSONのSHA-256にする。必須hashが欠けたら`None`、不正hashは固定codeの`ValueError`。同じ本文でもHost・instance・store・recordが異なれば別受付とする。

```python
import hashlib
import json
import re
from dataclasses import asdict

def capture_key(identity: CaptureIdentity) -> str | None:
    fields = asdict(identity)
    if not isinstance(identity.host_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}", identity.host_id):
        raise ValueError("CAPTURE_HOST_INVALID")
    for name, value in fields.items():
        if name == "host_id":
            continue
        if value is None and name in {"session_hash", "turn_hash", "record_hash"}:
            continue
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("CAPTURE_ID_INVALID")
    if identity.record_hash is None:
        return None
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def pending_policy(mapping: dict) -> PendingPolicy:
    defaults = PendingPolicy()
    selected = mapping.get("pending", {})
    if not isinstance(selected, dict):
        raise ValueError("PENDING_POLICY_INVALID")
    result = {}
    for name in ("ttl_seconds", "max_items", "max_bytes"):
        value = selected.get(name, mapping.get(name, getattr(defaults, name)))
        if type(value) is not int or value <= 0:
            raise ValueError("PENDING_POLICY_INVALID")
        result[name] = value
    return PendingPolicy(**result)
```

- [ ] `NormalizedHookEvent`、`CaptureContext`に任意の`capture_identity: CaptureIdentity | None = None`を追加する。旧payloadは`None`。既存の`<missing-...>`hashを新しい追跡IDへ昇格させない。trusted Host integrationが実在するIDから構築し、候補本文内のID・store指定を採用しない。session単位のcloseoutは複数target IDを明示できる。
- [ ] receipt schemaを`additionalProperties: false`で作成する。状態は上記5件、candidate/covered IDsはunique、reasonは固定code、本文・パス・自由記述欄なし。`SECURED`はcandidate IDが1件以上必要。旧記録は`UNKNOWN`として読むだけで書換えない。
- [ ] JSON Schemaは構造記述とし、最終受付には`ei.journal.validate_schema("capture-receipt", value)`による意味検証が必須と明記する。`candidate_hashes`は部分対応を許すが、IDは`candidate_ids`の要素に限り、1つのIDに複数のhashを対応させない。未登録ID・hash衝突の拒否と部分対応の受理をテストする。
- [ ] `candidate_ids`と`candidate_hashes`のID側は、既存の`queue_<32桁hex>`、既存event validatorと同じ`evt_...`形式、SHA-256 IDを受理する。`capture_id`、`covered_target_ids`、content hashはSHA-256形式を維持する。本文・パス・任意の自由記述IDは受理しない。
- [ ] shipped capture policyに`pending`の3値を追加する。既存利用者のトップレベル明示値は移行時に`pending`へコピーする。既定値との差だけでは利用者が明示したか判定せず、既存ファイルは保守的に明示値扱いする。既に保存したspoolの期限は変えない。
- [ ] `python -m unittest tests.unit.test_capture_contract tests.unit.test_capture tests.unit.test_spool -v`、全体検証、差分確認後、Files欄だけを`feat: define durable capture contracts`でcommitする。

### Task 2: 対象と受付の追跡台帳

**Files:**

- Create: `src/ei/capture_ledger.py`
- Create: `tests/unit/test_capture_ledger.py`
- Modify: `src/ei/hook_entry.py`、`src/ei/capture.py`
- Modify: `tests/integration/test_capture_fallback.py`
- Modify: `tests/unit/test_capture.py`（同じ本文・別scopeの直接保存とreceipt関連付けの回帰検証）

**Interfaces:** Task 1の型をconsume。`register_target(settings: Settings, identity: CaptureIdentity | None, *, now: datetime) -> CaptureReceipt`、`record_receipt(settings: Settings, receipt: CaptureReceipt) -> CaptureReceipt`、`read_receipt(settings: Settings, capture_id: str) -> CaptureReceipt | None`、`list_receipts(settings: Settings) -> tuple[CaptureReceipt, ...]`をproduceする。trusted identity object自体がない場合は`None`を渡し、仮のHost/store/instance identityを作らずlocal UNKNOWN receiptを生成する。

- [ ] 次のテストを追加し、`python -m unittest tests.unit.test_capture_ledger -v`で失敗を確認する。

```python
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from ei.capture_ledger import register_target, record_receipt, read_receipt
from tests.unattended_helpers import NOW, identity, make_settings

class CaptureLedgerTests(unittest.TestCase):
    def test_late_hook_does_not_erase_secured_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            waiting = register_target(settings, identity(), now=NOW)
            secured = replace(waiting, state="SECURED", candidate_ids=("queue_" + "1" * 32,))
            record_receipt(settings, secured)
            register_target(settings, identity(), now=NOW)
            self.assertEqual(read_receipt(settings, waiting.capture_id).state, "SECURED")
```

- [ ] `runtime/state/capture/`へIDを安全なファイル名に変換して保存する。`safe_fs.safe_atomic_write`と既存queue方式の排他lockを使う。全呼出しで`assert_safe_target`し、同時更新をmergeする。関数内lockの取得順はcapture → spool → queue、逆順取得しない。journalはこの台帳の代用品にしない。

```python
def merge_receipt(old: CaptureReceipt, new: CaptureReceipt) -> CaptureReceipt:
    if old.capture_id != new.capture_id:
        raise ValueError("CAPTURE_ID_CONFLICT")
    from dataclasses import replace
    candidates = tuple(sorted(set(old.candidate_ids) | set(new.candidate_ids)))
    covered = tuple(sorted(set(old.covered_target_ids) | set(new.covered_target_ids)))
    if old.reason_code == "PENDING_EXPIRED" or new.reason_code == "PENDING_EXPIRED":
        return replace(old, state="UNAVAILABLE", reason_code="PENDING_EXPIRED",
                       candidate_ids=candidates, covered_target_ids=covered,
                       updated_at=max(old.updated_at, new.updated_at))
    state = "SECURED" if candidates else old.state if new.state == "WAITING" else new.state
    return replace(new, state=state, candidate_ids=candidates,
                   covered_target_ids=covered, updated_at=max(old.updated_at, new.updated_at))
```

- [ ] このmergeは同一の候補世代についてだけ使用する。異なるcontent hashを同一candidate IDとして受付ける要求は`CAPTURE_CONTENT_CONFLICT`で拒否する。本文dedupは既存の処理を使い、受付の同一性と混同しない。
- [ ] ID不明時は新しいlocal receipt IDを発行して`UNKNOWN`を保存し、dedup・網羅率の分母へ入れない。NOは明示的な評価済みreceiptと理由codeがある場合だけ`EVALUATED_NONE`へ変更する。payload未着・空ファイル・非対応HostはNOにしない。
- [ ] Hookの終了時は対象登録を行う。後続Task 8までは旧queue経路を維持し、移行中のreceipt二重化を意味上の完了にしない。`record_agent_observation`はtrusted contextのidentityがある時だけevent IDを関連付け、既存の直接保存とprivacy gateを壊さない。candidate_idsは既存のqueue IDまたはdurableなobservation event IDを指す。後続の未整理件数は参照先の実際の処理状態から数え、event関連付けだけで未整理queueが存在すると扱わない。
- [ ] trusted identityのない旧Hook終了もlocal UNKNOWN receiptを残すが、無相関のqueue候補をそのreceiptへ結び付けない。scopeを含むidempotency keyへ更新する場合、旧keyのeventを再利用できるのは、永続済みcwd fingerprintとdomainが今回に一致すると確認できた場合だけ。旧eventの書換えはせず、scope違い・scope証拠欠落を同一replayと推測しない。
- [ ] trusted identityがあっても、本文なしのHook metadata queue IDを`candidate_ids`へ入れたり`SECURED`にしたりしない。初回targetは`WAITING`のまま、移行用の旧queueを独立して維持する。既存の実候補receiptがある場合も、遅いmetadata Hookで状態を戻したり、候補のないqueue IDを追加したりしない。
- [ ] 同じsessionの複数turn、候補先着、Hook先着、同時2プロセス、同じ本文の別scope、台帳破損・書込不可のテストを追加する。後者では成功ACKを返さずHook自体はfail-openにする。
- [ ] 対象3モジュール`tests.unit.test_capture_ledger`、`tests.unit.test_capture`、`tests.integration.test_capture_fallback`と全体を検証し、`feat: track collection targets and receipts`でcommitする。

### Task 3: 未整理候補の耐障害受付と期限

**Files:**

- Create: `src/ei/pending_capture.py`
- Create: `tests/unit/test_pending_capture.py`
- Create: `tests/integration/test_pending_capture_recovery.py`
- Modify: `src/ei/spool.py`、`src/ei/queue.py`、`src/ei/crypto.py`、`schemas/queue-item.schema.json`
- Modify: `schemas/spool-envelope.schema.json`、`schemas/spool-item.schema.json`
- Modify: `src/ei/capture_ledger.py`
- Modify: `tests/unit/test_crypto.py`
- Modify: `tests/unit/test_spool.py`、`tests/unit/test_queue.py`（受付で使用する既存lockの権限拒否・stat失敗が有界に終了する回帰検証）
- Modify: `src/ei/journal.py`（queue・spoolの手書きvalidatorと新規fieldの整合）

**Interfaces:** `accept_candidate(settings: Settings, identity: CaptureIdentity, observation: ObservationInput, *, now: datetime, key_provider: KeyProvider | None = None) -> CaptureReceipt`、`reconcile_pending(settings: Settings, *, now: datetime) -> dict[str, int]`をproduce。前者の`SECURED`だけが成功ACK。queueへ任意の`capture_id`、`validated_result_ref`を追加し、旧形式は`None`。`SpoolRef`へ`purpose: str = "legacy"`を追加し、旧暗号文のAADと読込互換を維持する。`write_spool`には任意keyword `capture_id: str | None = None`も追加し、pending/resultのAADと容量集計で使う。

- [ ] 以下を追加し、`python -m unittest tests.unit.test_pending_capture -v`で失敗を確認する。

```python
import tempfile
import unittest
from pathlib import Path
from ei.key_provider import InMemoryKeyProvider
from ei.models import ObservationInput
from ei.pending_capture import accept_candidate
from ei.queue import list_queue_items
from tests.unattended_helpers import NOW, identity, make_settings

class PendingCaptureTests(unittest.TestCase):
    def test_repeated_delivery_has_one_durable_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            key = InMemoryKeyProvider("test-key", b"s" * 32)
            item = ObservationInput("検証", "書込後には対象範囲を再読込し結果を検証する",
                "agent_direct", "structured-test", "", "general", "success",
                "reduced_rework", "private-reusable", source_host_id="codex-cli",
                source_host_family="codex-compatible")
            first = accept_candidate(settings, identity(), item, now=NOW, key_provider=key)
            second = accept_candidate(settings, identity(), item, now=NOW, key_provider=key)
            self.assertEqual(first.state, "SECURED")
            self.assertEqual(first.candidate_ids, second.candidate_ids)
            self.assertEqual(len(list_queue_items(settings)), 1)
```

- [ ] 受付順序はprivacy/schema検証 → durable PREPARED intent → 暗号化spool → 既存queue → capture receipt → COMMITTED intent → ACKとする。intentはID・hash・SpoolRef・固定codeだけ。候補本文は暗号化spoolだけに置く。spool/queue IDをcapture IDと内容hashから決定的に生成する。

```python
import hashlib

def pending_id(capture_id: str, content_hash: str) -> str:
    raw = (capture_id + "\n" + content_hash).encode("ascii")
    return "pending_" + hashlib.sha256(raw).hexdigest()
```

- [ ] `write_spool`へ任意keyword `purpose: str = "legacy"`と`retention: PendingPolicy | None = None`を追加し、同じspool機構のpurpose別集計をlock内で行う。`pending`候補と`validated-result`の合計が保持容量を消費する。legacyの上限を変更せず、新規pendingの既定上限は1,000件・64MiB。候補は1件、結果用暗号文はバイトのみ加算し、同一候補を二重に件数計上しない。衝突時は既存暗号文を上書きしない。
- [ ] 新規pending暗号文のenvelopeに`aad_version: 2`、`purpose`、`capture_id`を追加しAADへ含める。`encrypt_payload`と`canonical_aad`には後方互換の任意keywordを追加し、旧envelopeは従来AADのまま復号する。version/purposeを書き換えてlegacy容量へ逃がす改ざんは復号失敗とし、未知version・purposeは拒否する。queue内SpoolRefのpurposeと認証済みenvelopeの一致を確認する。
- [ ] `reconcile_pending`でPREPARED intentとspool・queue・receiptを照合する。queueが既にあれば再enqueueしない。本文未保存のintentは待機のまま、本文保存済みなら同じqueueを完成させる。勝手に新しい候補本文を生成しない。ACK前クラッシュ後の再送も同じreceiptへ収束させる。
- [ ] TTL処理はreceiptへstate `UNAVAILABLE`と`PENDING_EXPIRED`を先に記録してから本文を削除する。削除に失敗したらcleanup incidentへ`EXPIRY_CLEANUP_FAILED`を記録して再試行し、receiptのexpiry事実を消さない。期限経過後は推論に渡さず、同一source versionの再走査で期限を自動延長しない。関連queueは`FAILED_NEEDS_ATTENTION`にし、`DONE`やNOへ変えない。保存済み・NO・privacy拒否時は既存のcleanup方針と整合させる。
- [ ] Task 6のincident機構が未実装の間も、期限切れcapture IDとcleanup失敗の固定codeを本文なしのdurable intent/receipt metadataへ残す。Task 8はこれを有界に集約し、`HealthInput.expired_capture_ids` / `cleanup_failed_capture_ids`へ引き渡す。別のprovider成功でcleanup失敗を解消せず、該当本文の削除確認が解消証拠となる。
- [ ] 容量超過、disk full、鍵不可、暗号文破損、各永続化境界の中断、TTL境界、legacy spoolの読込を障害注入する。どれもACK・cursor前進・本文の診断出力が起こらないことを確認する。
- [ ] 既存spool/queue lockの権限拒否・stat失敗時も全retry分岐で期限を確認し、恒久的な書込拒否は速やかに固定codeで返す。受付が無期限に止まらないことをfake clockの回帰テストで検証し、Task 2のcapture lockと同じ有界失敗契約にする。
- [ ] atomic writer内部のwrite/fsync失敗では自分が作ったtmpを掃除し、replace前の実プロセス中断で残った管理tmpも容量・TTLから漏らさない。回収はspool lock下で管理された厳密な命名のtmpだけ、書込PIDの終了を確認して安全なunlinkで行う。生存・判定不能は保持し、新受付成功を返さない。Windowsは読取り専用のprocess handle照会、POSIXだけsignal 0を使い、権限昇格やプロセス終了は行わない。未知名・reparse・既存本体を消さず、掃除失敗は固定codeと期限切れcleanup記録を保って再試行する。
- [ ] 対象`tests.unit.test_pending_capture tests.unit.test_spool tests.unit.test_crypto tests.unit.test_queue tests.integration.test_pending_capture_recovery tests.integration.test_emergency_spool_recovery`と全体を検証し、`feat: retain and recover pending candidates`でcommitする。

### Task 4: 構造化取得元の差分回収

**Files:**

- Create: `src/ei/capture_recovery.py`
- Create: `tests/unit/test_capture_recovery.py`
- Create: `tests/integration/test_capture_catchup.py`
- Modify: `src/ei/adapters/base.py`、`src/ei/ingest.py`
- Modify: `src/ei/adapters/codex_memory.py`、`src/ei/adapters/rollout_summary.py`、`src/ei/adapters/claude.py`、`src/ei/adapters/gemini.py`、`src/ei/adapters/qwen.py`（検証済みbytesを再openせず既存parserへ渡す境界）
- Modify: `src/ei/host_profiles.py`、`schemas/host-profile.schema.json`
- Modify: `tests/unit/test_host_source_adapters.py`
- Modify: `tests/unit/test_codex_memory_adapter.py`、`tests/unit/test_rollout_adapter.py`（既存read互換とbytes入力の同等性）
- Modify: `src/ei/pending_capture.py`、`tests/unit/test_pending_capture.py`（既存observation schemaに沿うbenefit値の互換受付）

**Interfaces:** `RecoverySource`と`RecoveryPage`を定義する。`recover_page(settings: Settings, source: RecoverySource, *, now: datetime, max_records: int = 100, max_bytes: int = 2_097_152, max_ms: int = 5000) -> RecoveryPage`をproduce。`SourceAdapter`、`SourceRecord`は既存型を使う。既定値の変更理由は末尾の先行運用向け判定更新を参照。

```python
from dataclasses import dataclass
from pathlib import Path
from ei.adapters.base import SourceAdapter

@dataclass(frozen=True)
class RecoverySource:
    source_id: str
    host_id: str
    instance_hash: str
    store_id: str
    root: Path
    adapter: SourceAdapter
    enumeration_verified: bool = False

@dataclass(frozen=True)
class RecoveryPage:
    scanned: int
    secured: int
    rejected: int
    coverage: str
    cursor_committed: bool
    reason_code: str
```

- [ ] 非対応の場合にファイルを読まない失敗テストを追加する。

```python
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from ei.capture_recovery import RecoverySource, recover_page
from tests.unattended_helpers import NOW, identity, make_settings

class CaptureRecoveryTests(unittest.TestCase):
    def test_unverified_source_is_not_claimed_as_covered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = identity()
            adapter = Mock()
            source = RecoverySource("test", key.host_id, key.instance_hash,
                                    key.store_id, root / "source", adapter)
            result = recover_page(make_settings(root), source, now=NOW)
            self.assertEqual(result.coverage, "UNKNOWN")
            self.assertFalse(result.cursor_committed)
            adapter.assert_not_called()
            self.assertEqual(adapter.mock_calls, [])
```

- [ ] `python -m unittest tests.unit.test_capture_recovery -v`で失敗を確認後、非対応の早期returnを実装する。

```python
def unsupported_page() -> RecoveryPage:
    return RecoveryPage(0, 0, 0, "UNKNOWN", False, "SOURCE_ENUMERATION_UNVERIFIED")
```

- [ ] Host profileの任意`capture_capabilities`を、lifecycle / candidate_input / source_enumeration / receipt_correlation / direct_user_displayの5項目で定義する。値は`SUPPORTED`、`UNSUPPORTED`、`UNKNOWN`。profileの宣言は能力の主張であり実証ではない。version・bindingに一致するTask 9の証拠があるものだけverifiedにする。OllamaなどのProvider設定でHost能力を上書きしない。
- [ ] 列挙可能なadapterは既存の構造化記憶・要約だけ。Hostの承認済みroot以外、raw transcript、任意Hookパスは読まない。走査前・open直前・open後にroot包含、全親要素のreparse、ファイルidentity・size・mtimeを検証する。大きいファイルは全read前に拒否し、stream中も上限を守る。`rglob`で全件materializeせずページ継続位置を持つ。
- [ ] 巨大directoryのoffset再生が毎回時間切れとなる方式は避け、1 directoryずつ有界な相対名・typeのfrontierをruntimeへ保持する。candidate数上限`max_records`をdirectory全entry数の対応上限にはしない。frontier全体はJSON/path overheadを含むserialized metadataの`max_bytes`以内とし、全treeをmaterializeしない。各操作の前後で時間を確認する協調的予算とし、単一OS syscallのhard real-time期限を主張しない。listingを完了できない場合は明示的UNKNOWN/limitとし、未処理entryを飛ばさない。既存frontierの再読込と新しいsource本文のbyte accountingを区別し、状態の再読込だけで永久に本文へ進めない設計にしない。
- [ ] 既存adapterの`read(path)`は各parser内でpathを再openするため、新回収経路はそのまま呼ばない。安全に有界読込したbytesと検証済みfile metadataを既存parserへ渡す明示境界を設け、同じparserロジックを再利用する。旧read呼出しの互換は維持する。bytes入力境界を持たないadapterはUNKNOWNとし、危険な再open、temporary plaintext copy、parserロジックの複製で迂回しない。
- [ ] 既存adapterの`reduced_search`や明示された再利用効果の文言を、別の効果へ推測変換しない。pending受付のbenefitだけにある独自の列挙制限を既存observationの必須文字列・privacy検証へ統一し、safeな既存値が保持されること、秘密を含む値など既存拒否条件が維持されることをテストする。他の分類・outcome・privacy条件はこの互換修正で広げない。
- [ ] adapter由来のstable record IDがある場合だけtrusted identityを組む。session/turn対応がないmemoryファイルは候補として回収できても、そのturnの網羅率には足さない。receiptと関連付けできなければ`UNKNOWN`を併記する。
- [ ] 各recordをTask 3の`accept_candidate`へ渡し、durable ACK済み位置だけcursorを進める。privacy拒否は本文なしの拒否receipt後に進めるが、容量・一時読込失敗では止める。ファイル差替えはversion hashを変更して再走査し、同じIDに別本文を黙って上書きしない。入力の命令文でroot/provider/通知設定を変更しない。
- [ ] 例外として、既存ingestが同じ適用範囲の候補を既に永続化している場合は、実eventと内容・scopeを検証してからそのeventを参照するreceiptを保存し、同じ本文をpendingへ再保存しない。従来ingestの直接event保存APIは維持する。両経路の排他・metadataのみのbindingは既存runtime内で共有してよいが、trusted RecoverySourceだけを登録元とし、本文から設定を変更しない。新規ingestの決定的IDにはparser version/source scopeを含め、event/ACK後・補助metadata前の中断を照合で回復する。旧eventは書換えず、旧cursorのfingerprintだけでACKを推定しない。直接参照から予算内で証拠を確認できなければUNKNOWN/保留とし、pageごとの全journal走査や新しいDBを追加しない。
- [ ] Hookなし＋構造化候補ありで回収成功、Hookなし＋取得元なしでunknown、途中満杯からの再開、sort前提で新規ファイルがcursor前方に追加された場合の次巡回、リンク差替え、privacy拒否、全件上限を追加テストする。既存のingest経路と新回収経路の同時実行でも既存content dedupと受付IDで重複保存しない。
- [ ] 対象`tests.unit.test_capture_recovery tests.unit.test_host_source_adapters tests.integration.test_capture_catchup`と全体を検証し、`feat: recover authorized structured capture gaps`でcommitする。

### Task 5: 単一整理AIの再試行・呼出し前予算・結果再利用

**Files:**

- Create: `src/ei/organizer_recovery.py`
- Create: `tests/unit/test_organizer_recovery.py`
- Create: `tests/integration/test_organizer_restart.py`
- Modify: `src/ei/inference/budget.py`、`src/ei/inference/router.py`、`src/ei/inference/base.py`
- Modify: `src/ei/inference/errors.py`、`src/ei/maintainer.py`、`src/ei/queue.py`
- Modify: `tests/unit/test_budget.py`、`tests/unit/test_maintainer.py`
- Modify: `tests/unit/test_inference_router.py`（既存generate fixtureに一時的な永続budget ledgerを渡し、単一Providerと事前予算検証を両立）
- Modify: `tests/acceptance/test_single_intelligence_multi_cli.py`（一時的な永続budget ledgerと明示的な既知使用量の模擬Providerを用い、6候補・単一整理AI・recall・privacyの既存検証を維持）
- Modify: `tests/integration/test_single_organizer.py`（台帳と上限内の要求をfixtureへ接続し、malformedの段階的待機・有限呼出し・永続要対応・候補保持を既存の単一整理AI検証と両立）
- Modify: `src/ei/spool.py`、`tests/unit/test_spool.py`（検証済み結果を元candidateへ認証済みcapture IDで照合する後方互換の読取境界）
- Modify: `src/ei/inference/local_openai.py`（予約済みattempt内の未予約repair呼出しを止め、出力上限をrequestへ反映）

**Interfaces:** `next_retry(now: datetime, attempt: int, provider_deadline: datetime | None = None) -> datetime`。`BudgetLedger.reserve(attempt_id: str, provider_id: str, budget: InferenceBudget, now: datetime) -> BudgetResult`と`settle(attempt_id: str, result: ProviderResult, now: datetime) -> None`を追加する。`InferenceBudget`へ`run_id: str = ""`、`attempt_id: str = ""`を追加し、1 maintenance runで同じrun_idを使う。

- [ ] 再試行の固定テストを追加し、`python -m unittest tests.unit.test_organizer_recovery -v`で失敗を確認する。

```python
import unittest
from datetime import timedelta
from ei.organizer_recovery import next_retry
from tests.unattended_helpers import NOW

class OrganizerRecoveryTests(unittest.TestCase):
    def test_longer_provider_deadline_wins(self):
        deadline = NOW + timedelta(days=1)
        self.assertEqual(next_retry(NOW, 1, deadline), deadline)
        self.assertEqual(next_retry(NOW, 1), NOW + timedelta(seconds=300))
        self.assertEqual(next_retry(NOW, 50), NOW + timedelta(seconds=21600))
```

- [ ] 再試行計算を実装する。

```python
from datetime import timedelta
from ei.inference.base import require_aware

def next_retry(now, attempt, provider_deadline=None):
    now = require_aware(now)
    if type(attempt) is not int or attempt < 1:
        raise ValueError("RETRY_ATTEMPT_INVALID")
    due = now + timedelta(seconds=(300, 900, 3600, 21600)[min(attempt - 1, 3)])
    return max(due, require_aware(provider_deadline)) if provider_deadline else due
```

- [ ] `reserve`は既存budget ledgerの同じ排他区間で、日/run/candidate/providerの上限を確認してからattemptと入力・最大出力・費用の予約を永続化する。同じattemptの再reserveは再実行許可にせず`ATTEMPT_ALREADY_RESERVED`。未確定予約はプロセス終了で消さない。`settle`は実測との差分を1回だけ調整し、失敗・応答不明の費用を無条件に返却しない。異なるpurposeへ分割して日上限を回避できない集計にする。
- [ ] `ProviderRouter.generate`はreserve成功後のみ選択Providerを呼ぶ。既存の事後`consume`を重ねて二重計上しない。予約・精算でdisk fullなら新しい推論を開始しない。料金換算できない外部有料Providerは費用上限を保証できないため実行を許可しない。利用枠はtoken/attempt上限も併用し、追加購入はしない。
- [ ] 現在の`cloud` Providerには上限料金の契約がないため、`max_cost`の指定や成功応答の既定`cost=0`を既知料金とみなさず、呼出し前に固定codeで保留する。`local`と`subscription`は既存の従量追加課金なしの契約を維持する。精算は明示的に確認できた使用量・費用だけを一度反映し、未知値や失敗応答で予約を返却しない。内部`ProviderResult`に任意の既知値フラグが必要なら後方互換の既定値とし、現providerのgate→changesetが予算内で進むことも検証する。
- [ ] routerが設定する非空`attempt_id`を予約済み管理呼出しの境界とし、local-openai Providerはその呼出し内で追加repair推論をしない。不正応答は次の予約済みattemptで再試行する。`attempt_id`なしの旧direct Provider呼出しの互換は維持する。HTTP requestへ出力上限を明示し、0を無制限へ読み替えない。管理呼出しの実transport回数・同じ期限・送信した上限値をテストし、一般のCLI/モデルの正確な実token消費が証明されたとは主張しない。
- [ ] 予算拒否時に`Mock`のprovider.generateが0回、失敗応答もattemptを消費、再起動後の未精算予約保持、2候補がrun上限を共有、UTC日境界、未知実費、並行reserve競合を`test_budget.py`へ追加する。
- [ ] Organizer状態をruntimeのprovider単位で集約する。authは即保留＋要操作、quota/rateは期限保留、local停止/timeoutはbackoff、malformedは有限回後に要対応。empty queueで推論probeしない。公式の低コスト認証状態や設定変更が確認できれば再開し、それ以外は有界な同一Provider再試行のみ。候補数分のauth probeを出さない。
- [ ] auth/malformed保留解除はtrusted制御層の内部APIに限定し、同じProviderへの確認済み認証回復、または新しい有効な設定fingerprintだけを根拠にする。同一fingerprint、単なる`available()`、候補本文の主張では解除しない。設定変更は有界な再試行を許す兆候であり、障害解消の証明とはしない。既存subscription Providerの`AUTH_DISABLED`と新organizer状態を整合させ、片方だけ解除される永久保留を防ぐ。明示disable、認証情報自体、OS承認は変更しない。
- [ ] 数値が既にあるattempt上限は`BudgetPolicy.retry_limit`を候補ごと・UTC日ごとの全purpose合算へ適用し、失敗・結果不明も数える。0は新規呼出し不可。新しい未指定の日/run attempt上限は作らず、既存の日/run/candidate token・cost上限を併用する。上限到達では候補を捨てず、TTL内の翌UTC日には予算に応じた回復機会を残す。
- [ ] `_process_claimed`は`min(BudgetPolicy.deadline_ms, maintenance_remaining_ms)`を使う。Hookの1000msを推論へ流さない。残時間が足りなければ呼ばず保留する。retry回数上限到達を候補破棄に結び付けず、TTL中は回復機会を残す。
- [ ] 検証済みgate/changesetを既存spoolの`validated-result`として保存し、queueの`validated_result_ref`へ結ぶ。内容hash・Provider・schema/version・source hash一致時だけ再利用する。結果の期限は元候補の期限以下。同じchangeset/event IDがjournalにあれば再推論・二重保存せずprojectionと完了処理だけ行う。結果永続化前のクラッシュは推論が再度必要になり得るため、外部課金のexactly-onceを主張しない。
- [ ] `read_spool`へ任意keyword引数`expected_capture_id: str | None = None`を加え、指定時は形式を検証し、認証対象envelopeのcapture ID一致と復号成功の両方を確認してから本文を返す。Task 5の結果再利用はtrusted queue/candidate IDを必ず渡す。任意本文内のIDだけやspool内部private helperへの依存で代替しない。既存呼出しは互換、期限は不変。不一致を成功とせず、別候補の正当なspoolを削除・更新しないことをテストする。
- [ ] 対象`tests.unit.test_organizer_recovery tests.unit.test_budget tests.unit.test_maintainer tests.unit.test_inference_router tests.unit.test_spool tests.integration.test_organizer_restart tests.integration.test_queue_recovery`と全体を検証し、`feat: bound organizer retries and reserve inference budgets`でcommitする。

### Task 6: 純粋なhealth判定と永続incident

**Files:**

- Create: `src/ei/operation_health.py`、`src/ei/incidents.py`
- Create: `schemas/operation-incident.schema.json`
- Create: `tests/unit/test_operation_health.py`、`tests/unit/test_incidents.py`

**Interfaces:** `HealthInput`、`HealthIssue`を定義し、`evaluate_health(snapshot: HealthInput, *, now: datetime) -> tuple[HealthIssue, ...]`をproduceする。I/O、AI、時計読取りはしない。`update_incidents(settings: Settings, issues: tuple[HealthIssue, ...], *, now: datetime, verified_resolutions: tuple[str, ...] = ()) -> tuple[dict, ...]`、`notification_due(incident: dict, *, channel: str, session_hash: str | None, now: datetime) -> bool`をproduceする。

```python
from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class HealthInput:
    pending_count: int = 0
    pending_bytes: int = 0
    max_items: int = 1000
    max_bytes: int = 67108864
    oldest_pending_at: datetime | None = None
    earliest_expiry: datetime | None = None
    last_progress_at: datetime | None = None
    last_attempt_at: datetime | None = None
    provider_code: str | None = None
    provider_needs_action: bool = False
    provider_id: str = ""
    host_id: str = ""
    scheduler_requested: bool = True
    missed_eligible_runs: int | None = None
    source_missing_count: int = 0
    source_missing_ids: tuple[str, ...] = ()
    expired_capture_ids: tuple[str, ...] = ()
    cleanup_failed_capture_ids: tuple[str, ...] = ()

@dataclass(frozen=True)
class HealthIssue:
    reason_code: str
    component_id: str
    severity: str
    pending_count: int
```

- [ ] 次を追加し、`python -m unittest tests.unit.test_operation_health -v`で失敗を確認する。

```python
import unittest
from dataclasses import replace
from datetime import timedelta
from ei.operation_health import HealthInput, evaluate_health
from tests.unattended_helpers import NOW

class OperationHealthTests(unittest.TestCase):
    def test_heartbeat_is_not_progress_and_empty_queue_is_not_stalled(self):
        item = HealthInput(pending_count=1, oldest_pending_at=NOW-timedelta(days=2),
                           last_attempt_at=NOW, provider_code="RATE_LIMITED")
        self.assertIn("ACCUMULATION_STALLED", {i.reason_code for i in evaluate_health(item, now=NOW)})
        self.assertNotIn("ACCUMULATION_STALLED", {i.reason_code for i in evaluate_health(replace(item, pending_count=0), now=NOW)})
    def test_offline_time_is_not_two_eligible_runs(self):
        self.assertFalse(evaluate_health(HealthInput(missed_eligible_runs=None), now=NOW))
```

- [ ] 停滞の核を次で実装する。併せてauth/permission、source消失、容量80%、期限24h、schedulerの2回実行機会逸失を個別codeへ分離する。

```python
def stalled(snapshot: HealthInput, now: datetime) -> bool:
    if snapshot.pending_count == 0:
        return False
    baseline = snapshot.last_progress_at or snapshot.oldest_pending_at
    return baseline is not None and (now - baseline).total_seconds() >= 86400
```

- [ ] incident IDは固定reason family + component IDのhash。runtimeに検出時刻、最終観測、重大度、send attempt、送信結果、解消を安全に保存する。任意エラー本文・秘密・取得元パスは保存しない。既知code以外は`OPERATION_FAILED`。初回要操作/喪失リスクは即通知対象、短時間の一時障害は静かに保留する。
- [ ] 後続の通知・runtimeと合わせ、定期処理の確定停止は`SCHEDULER_STOPPED`、取得元消失は`SOURCE_UNAVAILABLE`を使う。容量と期限の予兆は`CAPACITY_RISK`、`EXPIRY_RISK`へ分ける。`HealthIssue.pending_count`は取得不能・喪失件数ではなく、確認済み保持候補の`snapshot.pending_count`だけを渡す。
- [ ] `provider_needs_action`はtrusted organizer snapshotの永続要対応状態を表す。`MALFORMED_RESPONSE`だけで初回から要対応通知せず、有限回上限後の要対応を判定する。認証・権限の確定障害は従来どおり初回から判定し、heartbeatを進捗や復旧の根拠にしない。
- [ ] `expired_capture_ids`は`PENDING_EXPIRED`の喪失履歴、`cleanup_failed_capture_ids`は`EXPIRY_CLEANUP_FAILED`の継続障害としてcaptureごとに区別する。期限切れだけで継続中のcleanup障害を消さない。喪失履歴は同じ事実の反復通知や永続的な未整理件数にせず、新しい喪失と区別して保持する。
- [ ] 「現snapshotにない」だけで解消しない。該当原因について検証された回復IDだけ`verified_resolutions`へ渡す。別sourceの成功やauth回復でsource喪失を解消しない。喪失の歴史記録は残し、継続中の障害とは分ける。
- [ ] 後方互換の任意`occurrence_generation`で今回の発生範囲を識別し、前回の通知成功から未通知の再発に復旧通知を出さない。既存の送信時刻・結果・失敗制限は保持する。旧形式はcurrent generationを基に保守的に扱い、再発時の通知証拠を推測しない。
- [ ] `notification_due`はOS成功から24h、失敗attemptから1h、CLIはsessionごと1回。同じincidentの重大化・新しい喪失は成功cooldownを越えて通知対象にするが、送信失敗時の1h上限は維持する。成功した通知のみ成功時刻を更新する。通知を閉じた操作は解消扱いにしない。
- [ ] fake clockで24h/1h境界、restart、同時呼出し、重大化、復旧通知1回、未通知incidentの復旧は静か、別sourceの失敗保持をテストする。
- [ ] 対象`tests.unit.test_operation_health tests.unit.test_incidents`と全体を検証し、`feat: persist actionable operation incidents`でcommitする。

### Task 7: 非対話のOS通知とCLI表示adapter

**Files:**

- Create: `src/ei/notifications/__init__.py`、`src/ei/notifications/base.py`
- Create: `src/ei/notifications/windows.py`、`src/ei/notifications/macos.py`、`src/ei/notifications/linux.py`、`src/ei/notifications/cli.py`
- Create: `scripts/notifications/windows-toast.ps1`
- Create: `tests/unit/test_notifications.py`、`tests/integration/test_notification_delivery.py`
- Modify: `src/ei/hooks/base.py`
- Verify compatibility (modify only if needed): `src/ei/hooks/codex.py`、`src/ei/hooks/claude.py`、`src/ei/hooks/gemini.py`、`src/ei/hooks/qwen.py`（未検証noticeを既に出力しない場合はテストで確認し、形式合わせの変更はしない）
- Modify: `src/ei/incidents.py`
- Modify: `schemas/operation-incident.schema.json`（送信leaseと結果不明状態の後方互換な保存契約）

**Interfaces:** `NotificationMessage(title: str, body: str)`、`DeliveryResult(status: str, reason_code: str, delivery_id: str | None = None)`をfrozen dataclassで定義する。statusは`SENT` / `UNAVAILABLE` / `DENIED` / `FAILED`。`render_notification(reason_code: str, pending_count: int, *, recovered: bool = False) -> NotificationMessage`。各OSに`send_notification(message: NotificationMessage, *, timeout_seconds: float = 2.0) -> DeliveryResult`。CLIは`encode_user_notice(host_id: str, message: NotificationMessage, *, verified: bool) -> dict | None`。

- [ ] 次の失敗テストを追加する。

```python
import unittest
from ei.notifications.base import render_notification
from ei.notifications.cli import encode_user_notice

class NotificationTests(unittest.TestCase):
    def test_unknown_error_is_not_printed(self):
        text = "private source content should never be displayed"
        message = render_notification(text, 3)
        self.assertNotIn(text, message.body)
        self.assertIn("3", message.body)
        self.assertIsNone(encode_user_notice("codex-cli", message, verified=False))
```

- [ ] `python -m unittest tests.unit.test_notifications -v`で失敗を確認し、fixed template rendererを実装する。

```python
def render_notification(reason_code, pending_count, *, recovered=False):
    if type(pending_count) is not int or pending_count < 0:
        raise ValueError("NOTIFICATION_COUNT_INVALID")
    actions = {
        "AUTH_FAILED": "設定した整理AIに再ログインしてください。",
        "ACCUMULATION_STALLED": "整理処理が停止しています。利用枠と接続を確認してください。",
        "PENDING_LOSS_RISK": "未整理候補の保持期限または容量に近づいています。",
        "SOURCE_UNAVAILABLE": "取得元を利用できず、未取得の内容は保持できていません。",
        "SCHEDULER_STOPPED": "定期処理の停止を検出しました。OSの設定を確認してください。",
    }
    action = "整理処理の復旧を確認しました。" if recovered else actions.get(reason_code, "自動蓄積で確認が必要な問題が発生しました。")
    return NotificationMessage("External Intelligence", f"{action} 保持済み未整理候補: {pending_count}件。")
```

- [ ] Task 6の`CAPACITY_RISK`、`EXPIRY_RISK`は保持リスクの定型案内へ、`SOURCE_UNAVAILABLE`、`SCHEDULER_STOPPED`は各原因の案内へ対応付ける。表示件数はincidentの確認済み保持候補数だけを使い、喪失・未取得数から増やさない。
- [ ] OS機構は以下の一次資料に基づく。送信受付と画面表示を別に記録する。仕様やAPIの存在だけでは対応実証にならない。

  - Windows: [Microsoftのdesktop toast / AppUserModelID](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh802762%28v%3Dvs.85%29)。固定AppUserModelID `MiyaIF.ExternalIntelligence`と所有権のあるユーザー単位shortcutをsetup時だけ登録する。他アプリのIDを借りない。PowerShellスクリプトは固定XMLテンプレートのtext nodeへ入力し、実行コードに連結しない。登録できない環境はUNAVAILABLE。
  - macOS: [Appleのdisplay notification](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/DisplayNotifications.html)。固定AppleScriptの`on run argv`へtitle/bodyをargvとして渡す。標準`/usr/bin/osascript`を使い、集中モード・許可設定は変えない。
  - Linux: [freedesktop Desktop Notifications](https://specifications.freedesktop.org/notification/latest-single/)。既存の`gdbus`でsession busの`org.freedesktop.Notifications.Notify`を利用できる場合に送る。client/bus/desktop serviceがなければUNAVAILABLE。追加パッケージを自動導入しない。

- [ ] 固定実行ファイル、argv配列、`shell=False`、短いtimeout、Windowsの非表示起動を使う。PowerShell実行時にユーザー全体の実行policyを変更しない。Provider由来の文字列をコマンド・XML属性・AppleScriptソースへ埋め込まない。通知actionに任意URL/commandを入れない。
- [ ] `HookResult`へ任意`user_notice`を追加するが、各Hostの公式user-visible fieldと実CLI表示の両方を確認するまでencoderは`None`を返す。既存JSON stdoutに別行を混ぜない。stderr、モデルcontext、モデル発話は通知経路として認定しない。4 Hostのserializerで互換テストを行う。
- [ ] `send`前にincident delivery leaseとattempt時刻を永続化し、同時Hook/保守からの二重通知を防ぐ。送信後・結果保存前の中断はdelivery unknownとし、1h後に有界再試行できる。OS APIにidempotencyがない場合、クラッシュを跨ぐexactly-once表示は保証しない。
- [ ] Task 6の`occurrence_generation`を保持し、leaseの送信結果が別の再発の通知証拠へ混入しないよう、対象incident・通知generation・発生範囲を照合する。
- [ ] 呼出し前の予算切れなど、送信関数を一度も呼んでいないことを制御フローで確認できる場合だけ、`abort_notification(settings, lease)`で送信権を取り消せるようにする。leaseには直前の本文なしdelivery metadataを保存し、incident・token・generation・発生範囲が一致する場合だけ復元する。既存failed/unknownの制限を消さず、クラッシュ・送信開始後・別leaseには適用しない。既存incidentを未実行intentとして残す。
- [ ] OS API成功/拒否/timeout/未導入/headlessをmockし、プロセスargvとstdout非汚染を検証する。実画面確認はTask 10に別記録する。通知失敗を`SENT`にせず、利用可能な検証済みCLI経路へ落とす。両方不可は通知非対応として残す。
- [ ] 対象`tests.unit.test_notifications tests.unit.test_incidents tests.integration.test_notification_delivery`と全体を検証し、`feat: notify actionable failures through native channels`でcommitする。

### Task 8: Hook・定期処理・statusへの接続

**Files:**

- Create: `src/ei/operation_runtime.py`
- Create: `src/ei/runtime_catalog.py`、`tests/unit/test_runtime_catalog.py`（本文を持たないruntime索引と再開可能な管理entry移行）
- Create: `tests/integration/test_unattended_operation.py`
- Create: `tests/unit/test_scheduler_opportunities.py`
- Modify (R82): `tests/acceptance/test_single_intelligence_multi_cli.py`、`tests/integration/test_capture_fallback.py`、`tests/integration/test_maintenance.py`、`tests/integration/test_organizer_restart.py`（8C全体gateの既存fixture整合。旧保証を維持し、詳細はtask-8CのR82を参照）
- Modify: `src/ei/hook_entry.py`、`src/ei/capture.py`、`src/ei/maintainer.py`、`src/ei/task_scheduler.py`、`src/ei/cli.py`
- Modify: `src/ei/pending_capture.py`、`tests/integration/test_pending_capture_recovery.py`（Task 3の照合へ残予算と継続位置を接続）
- Modify: `src/ei/capture_recovery.py`、`tests/unit/test_capture_recovery.py`（回収pageの残予算を受付処理内へ伝播）
- Modify: `src/ei/ingest.py`（Task 4の共有`coordinate_record`を経由する残予算伝播のみ）
- Modify: `src/ei/capture_ledger.py`、`tests/unit/test_capture_ledger.py`（受付台帳のlock待機・再試行にも後方互換の残予算を接続）
- Modify: `src/ei/organizer_recovery.py`、`src/ei/inference/budget.py`、`tests/unit/test_organizer_recovery.py`、`tests/unit/test_budget.py`（整理状態と予算台帳のlock・読書きへ同じ残予算を接続。料金・予約・再試行policyは変更しない）
- Modify: `src/ei/incidents.py`、`tests/unit/test_incidents.py`（incident cacheの読書き・lock待機にも残予算を接続）
- Modify: `src/ei/spool.py`、`src/ei/queue.py`、`tests/unit/test_spool.py`、`tests/unit/test_queue.py`（既存内部走査・lock待機にも呼出し元の残予算を適用）
- Modify: `tests/integration/test_multi_host_lifecycle.py`

**8B互換性の追加対象（R46）:** `src/ei/doctor.py`、新規`tests/unit/test_doctor_spool.py`（新旧spool配置の診断だけ）、`tests/unit/test_crypto.py`、`tests/unit/test_pending_capture.py`、`tests/integration/test_hook_canary.py`、`tests/integration/test_emergency_spool_recovery.py`、`tests/integration/test_capture_fallback.py`（内部flat pathを直接参照するfixture/assertionの整合。privacy/crypto/削除検査は弱めない）。

**Interfaces:** `operation_snapshot(settings: Settings, *, now: datetime) -> HealthInput`はread-only。`service_operation(settings: Settings, *, now: datetime, channel: str, session_hash: str | None = None, max_ms: int = 200) -> dict`がhealth/incident/通知を接続する。`inspect_scheduler_opportunities(settings: Settings, *, now: datetime) -> dict`は`requested: bool`、`missed_eligible_runs: int | None`、`next_run_at: str | None`、`reason_code: str`を返す。

**Task 9と共有する通知設定契約:** `runtime/automatic-operation.json`は64KiB以内の`{"schema_version":1,"settings":{"notifications":{"enabled":bool,"channel":"os"},"initial_test":{"allow_model_test":bool,"allow_notification_test":bool}},"evidence":{...}}`。Task 8は検証済みのsettings.notificationsだけを日常通知の設定として読み、initial_testやevidenceから有効化・表示確認を推測しない。欠落・不正・未対応形式は設定unknownかつ送信なし、明示falseは維持する。scheduler選択・Provider・rootを複製せず既存設定を参照する。読み取りはファイル作成・更新なし。evidenceの詳細な結び付けと初回同意の保存はTask 9が担当する。

- [ ] 日常経路が入力待ちしないテストを追加する。

```python
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ei.operation_runtime import service_operation
from tests.unattended_helpers import NOW, make_settings

class UnattendedOperationTests(unittest.TestCase):
    def test_normal_empty_runtime_does_not_ask_or_run_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("builtins.input", side_effect=AssertionError("daily prompt")):
                with patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("empty probe")):
                    result = service_operation(make_settings(Path(tmp)), now=NOW,
                                               channel="maintenance", max_ms=200)
            self.assertEqual(result["notifications_sent"], 0)
```

- [ ] `python -m unittest tests.integration.test_unattended_operation -v`で失敗を確認後、`service_operation`からTask 6の純粋関数を呼ぶ。戻り値の共通形を固定する。

```python
def operation_result(issues, notifications_sent, reason_code="OK"):
    return {"issues": [item.reason_code for item in issues],
            "notifications_sent": notifications_sent,
            "reason_code": reason_code}
```

- [ ] Hook開始/終了時に軽量snapshotとserviceを呼ぶ。新規メタデータだけのturnは追跡台帳へ送り、推論queueには入れない。旧メタデータqueueは本文/確定済みeventがなければ追跡待ちへ扱いを移し、AIでNO判定しない。新経路のSkill/adapter由来候補はTask 3へ渡す。既にjournalへ記録された旧observationは既存event IDでqueue照合し、再受付・再推論のために一括書換えしない。trusted identityを渡せない旧Skill呼出しは既存保存を継続できるが、turn coverageはunknownのままにする。
- [ ] Hookの総時間予算を守る。OS送信timeoutも残予算以内、時間不足ならattempt未実行の通知intentを残し、次回Hook/定期処理で送る。大量source走査・AI・全journal走査はしない。state集計をキャッシュし更新に失敗したらunknownを返す。
- [ ] claim後に時間不足となっても送信関数を未呼出しと確認できる経路はTask 7の`abort_notification`へ接続する。取消しにも同じ残予算を渡し、送信前に同じdeadline内で取消し用の余裕を確保する。全体deadlineが尽きてから予算なしの読取り・照合・保存を開始しない。呼出し済み・クラッシュ・結果不明の状態を未実行へ戻さず、残予算不足を含め取消しの照合・保存ができない場合は保守的なunknownを保持する。
- [ ] Task 3の期限切れ・cleanup失敗metadataも有界に集約し、同じcapture IDを維持してhealth snapshotへ渡す。Hookはその軽量cacheを使い、削除成功など原因に一致する証拠だけをincident解消へ渡す。
- [ ] Task 5のtrusted organizer snapshotから固定理由codeと`needs_action`をそれぞれ`provider_code`、`provider_needs_action`へ渡す。不正形式の一時再試行と有限回上限後の要対応を区別し、候補本文の主張から要対応・解消状態を作らない。
- [ ] `READY`など正常状態のcodeを障害入力として渡さず、`provider_code=None`とする。incidentの更新・delivery leaseで待つ時間も呼出し元の残予算以内にし、全体cacheが有界でも1回のHookで無制限に処理しない。予算不足は成功した更新・通知として記録せず、次の有効な実行へ持ち越す。
- [ ] Task 7の`read_incidents`はincidentを書き換えないが、現在はstate directoryとlock fileを作る。read-onlyのsnapshot/statusにはそのまま使わず、未作成runtimeでもファイル作成・更新がない読み取り経路を用意し、欠落・不正・予算切れを完全な正常状態として表示しない。
- [ ] trustedな設定fingerprintの初期登録と変更比較、または同じProviderの確認済み認証回復をTask 5の`OrganizerRecovery.recover()`へ接続する。単なる初期値不明・同じfingerprint・`available()`を回復とみなさず、設定変更は再試行の兆候とする。実Providerは`router.selected()`から渡して既存認証ラッチも整合させ、明示disable・認証情報を変更しない。maintenance内の追加phaseにも同じ`run_id`を渡す。
- [ ] `OrganizerRecovery`のsnapshot/run/recoverと`BudgetLedger`のlock・読書きにも後方互換の任意実行予算を渡す。maintenanceの予約・精算にも同じ残予算を使い、固定lock待ちで期限を超えない。予算切れ・結果不明を予約返金や実呼出しなしの証拠にしない。Hookのsnapshotはlockを作るsnapshot APIに依存せず、有界の検証済みcacheを読む。
- [ ] `run_maintenance`を、pending crash照合 → 有界source回収 → 単一organizer drain → journal/projection照合 → health/incident/通知の順につなぐ。各フェーズに残時間・件数上限を渡す。maintenanceの早期例外時も可能ならsanitized失敗incidentを残す。停止中でも既存recallは利用できる。
- [ ] Task 3の`reconcile_pending`に後方互換の任意予算引数と安全な継続位置を加え、完了・期限切れintent履歴が増えても各実行が有界で、待機候補を巡回できるようにする。全履歴のmaterialize、毎回先頭だけ再処理して後続を飢餓状態にする方式、途中までのsnapshotを完全な集計として表示する方式は避ける。小さな既存呼出しの意味は変えず、maintenanceから残予算を渡す。
- [ ] flatな旧runtime entryは同じroot内のID-addressableな`managed/<ID-prefix>/<ID>.json`へ有界に移し、未移行集合を減らして再起動時のprefix再走査による飢餓を避ける。標準sqlite3のruntime-local catalogはID・状態・順序などmetadataだけを持ち、keyset page/巡回とbusy timeoutに残予算を適用する。prepared記録→同一root内の安全な移動→registered記録の順で中断復旧できるようにし、両位置の不一致はunknownとして虚偽ACKしない。ID lookupはmanaged優先とflat fallbackを保ち、本文・TTL・外部ID・journalを変更しない。部分inventoryや破損catalogは完全な容量・coverageと扱わず、リンク/不正pathを拒否する。実DB/WAL等をリポジトリへ追加せず、実利用環境の移行はこの実装作業では実行しない。
- [ ] 呼出し元だけに時間制限を置かず、spool容量照合・tmp回収・queue claim内部の走査/待機にも残予算を伝える。未完了の容量確認や部分走査を成功ACK・正常な完全snapshotとして扱わず、安全な継続/キャッシュで後続の飢餓を避ける。既存APIは後方互換の任意引数で保ち、通常legacy呼出しを破壊しない。
- [ ] `recover_page`から共有`ingest.coordinate_record`を経由して`accept_candidate`へも残時間を渡し、Task 4の操作前確認だけで内部の同期受付・lock待機まで有界になったと扱わない。新しい任意予算引数を連携し、予算切れはcursorを進めず次回へ持ち越す。通常の旧呼出しとTask 4のprivacy/route ownershipを保つ。
- [ ] scheduler登録receiptだけで稼働を判定しない。OS状態・予定・実行結果と、同一bootの実行可能な観測区間を突合する。Windowsはtask状態/結果と稼働情報、Linuxはuser timer/serviceとboot/suspend情報、macOSはlaunchd状態と稼働情報をread-onlyで取得する。sleep/offを除外できないOSでは`None`を返す。2回以上の確認済み機会逸失だけ`SCHEDULER_STOPPED`にする。明示disableは`requested=False`で、再登録も停止警告もしない。
- [ ] scheduler自身が止まっていても次のCLI起動で判定できること、両経路停止時は検知不能であることをテスト・statusに反映する。最終attemptと最終progressを別表示し、legacy-only runtimeは進捗unknown。`status --json`は読取りだけでAI・OS通知・状態更新をしない。
- [ ] 対象`tests.integration.test_unattended_operation tests.unit.test_scheduler_opportunities tests.unit.test_task_scheduler tests.integration.test_multi_host_lifecycle tests.unit.test_maintainer`と全体を検証し、`feat: wire unattended capture recovery and health checks`でcommitする。

#### Task 8A: 時間予算・読取り・通知設定の基盤

Task 8を8A→8B→8Cの順に実施する内部チェックポイント。要件は上記Task 8から削除せず、8Cの統合検証とreviewまでTask 8全体を完了としない。各段階は自己review・対象テスト・production audit・固定snapshotのcomplete unittest suite・限定commit・独立reviewを行う。コードの担当は下記Filesのみ。計画・仕様・進行記録はcontrollerが担当する。

**Files:** `src/ei/operation_runtime.py`、`tests/integration/test_unattended_operation.py`、`src/ei/incidents.py`、`tests/unit/test_incidents.py`、`src/ei/capture_ledger.py`、`tests/unit/test_capture_ledger.py`、`src/ei/organizer_recovery.py`、`tests/unit/test_organizer_recovery.py`、`src/ei/inference/budget.py`、`tests/unit/test_budget.py`。

- [ ] 同じmonotonic残予算を使える最小primitiveと後方互換の任意予算引数を実装し、incident・受付台帳・organizer・予約/精算のlock待ち、再試行、読書き、内部loopへ伝播する。既存の料金・予約・返金・retry policyを変えない。予算切れや結果不明を「AI未呼出し」や返金の証拠にしない。ProviderRouterの既存budget_ledger注入を使える構成にする。
- [ ] runtime未作成でも作成・更新なしの有界incident/cache読取りを用意し、欠落・破損・予算不足はunknownとする。8Cでmaintenance側cache生成とstatus/Hookを接続するまでは、実稼働snapshotの完成と扱わない。
- [ ] R40の64KiB以内のautomatic-operation.json設定を読取り、欠落/不正/未対応はunknownで送信なし、明示falseを保持する。initial_testやevidenceを日常通知の許可へ転用しない。
- [ ] service_operationの共通result形、空runtimeで入力/AI呼出しなし、zero budgetで状態変更なしを検証する。通知claim/send/settleは共有残予算を使い、確実な未送信だけR37abortへ渡す。呼出し済み/unknown/取消し失敗を未実行へ戻さない。
- [ ] OS/FS同期syscallはpreemptできないためhard200ms保証を主張しない。8Bのcatalog/移行、8CのHook/maintenance/scheduler配線を実装しない。
- [ ] R45: 通知取消しも元の共有deadline内だけで行う。送信前の余裕を同じ予算内に確保し、abortにも同じbudgetを渡す。完全に尽きた場合は新たな全cache読取り・検証・保存を開始せずUNKNOWNを保持する。別の猶予予算やdeadline延長を足さず、取消し不能時の保守的な1時間の再試行制限は維持する。
- [ ] 対象は`tests.integration.test_unattended_operation tests.unit.test_incidents tests.unit.test_capture_ledger tests.unit.test_organizer_recovery tests.unit.test_budget`。全体成功後`feat: bound unattended operation state work`で上記の実変更filesのみcommitする。

#### Task 8B: 再開可能なruntime索引と有界受付

8Aに続く独立実装・review単位。Task 8全体の同じ制約に従い、8Cの配線完了まで運用完成を主張しない。

R52: 実装途中で保存protocolと呼出し側の同時変更が広すぎると判明したため、8B内部を保存protocol安定化→呼出し側統合の順に分ける。最初の担当は部分差分とテスト・未解決点を保存して編集を止め、fresh担当が`runtime_catalog.py` / `test_runtime_catalog.py` / `spool.py` / `test_spool.py`の4ファイルだけでprotocolと暗号化再送境界を安定化する。その引継ぎ後に元担当が残りを統合する。同時編集・部分完成のcommitはせず、8B全体の固定snapshot gate・commit・独立reviewは統合後に行う。要件・所有ファイル数・実利用環境への適用範囲は増やさない。

**Files:** `src/ei/runtime_catalog.py`、`tests/unit/test_runtime_catalog.py`、`src/ei/pending_capture.py`、`tests/integration/test_pending_capture_recovery.py`、`src/ei/spool.py`、`tests/unit/test_spool.py`、`src/ei/queue.py`、`tests/unit/test_queue.py`、`src/ei/capture_recovery.py`、`tests/unit/test_capture_recovery.py`、`src/ei/ingest.py`。

**Additional Files（R46）:** `src/ei/doctor.py`、新規`tests/unit/test_doctor_spool.py`、`tests/unit/test_crypto.py`、`tests/unit/test_pending_capture.py`、`tests/integration/test_hook_canary.py`、`tests/integration/test_emergency_spool_recovery.py`、`tests/integration/test_capture_fallback.py`。計18ファイル。doctorの変更はspool診断の新旧配置対応だけ。

**安全な全体検証の追加対象（R53）:** `src/ei/sync.py`の`FileLock`生存確認と古いlockの判定、および`tests/acceptance/test_semantic_conflict.py`の該当試験。8B全体の所有は計20ファイルとなるが、R52の先行protocol担当4ファイルは増やさない。Windowsの生存確認で`os.kill(pid, 0)`を実行せず、既存の安全なread-only OS生存確認と同じ三値判断を用いる。確認済み死亡だけを回収対象とし、live/unknownや経過時間だけでlockを奪わない。試験の任意PIDへ実シグナルを送らず、対象判定を制御した回帰テストで確認する。既存同期フローの改造は行わず、呼出し側統合段階で修正してからcomplete suiteを実行する。

**既定予算での進捗に必要な追加対象（R55）:** `src/ei/safe_fs.py`の`_is_reparse` / `_reparse_components`と`tests/unit/test_safe_fs.py`。8B所有は計22ファイル。各componentのno-follow stat一回からsymlink mode・reparse属性・tagを判定し、重複probeだけを除く。FileNotFoundError以外の不明・アクセス拒否はfail-closed、cacheなし、canonical containmentと変更直前の再検証は維持する。実link/dangling/junction、拒否・未知属性・probe回数の回帰、および既定500ms反復と既存20候補の予算で前進を確認する。既定予算を増やしたり安全確認を省略したりしない。最終対象は既存15modulesに`tests.unit.test_safe_fs`と`tests.integration.test_reparse_safety`を追加する。

- [ ] Task 8のR42契約どおり、本文なしruntime-local SQLite catalog、keyset page/巡回、prepared→same-root managed shardへの移動→registered、両位置照合による中断復旧を実装する。旧flat entryの未移行集合を減らし、再起動時のprefix飢餓を避ける。ID/本文/TTL/journalは保持し、リンク・不正path・不一致duplicateは安全にunknownとする。実DB/WALをGitへ追加せず、live移行しない。
- [ ] R46: 新規書込みは予算引数の有無で分岐せず、managed配置とcatalogへ統一する。旧flatの読取り・移行を残し、外部ID・API返却の意味は保つ。旧配置を意図するfixtureは維持し、暗号文改ざん・削除後・件数の検査は新配置も実際に対象とする。doctorがmanaged entryを見落として正常/鍵不要と報告しないようにする。
- [ ] R47: catalogはengineの保守的な受付予約・容量会計の台帳とし、全ファイルの現在の保有を暗号的に再実証した一覧と呼ばない。登録/移行時にpurposeを認証し、本文を使う時は必ず再認証する。engineの全書込み・置換・削除は台帳と協調し、PREPARED/未確定の予約も容量に残す。削除のdurable intentと実ファイル削除の対応が確認できるまでchargeを解放せず、単なる欠落・stat変化・cache値からpurpose変更や返金をしない。root/shardの予期しない構成変化、部分移行、破損、不整合はunknownで新規容量ACKを止め、継続可能な再照合へ渡す。stat/directory signatureは認証の代わりではない。本文の外部変更は使用時の認証と有界の再検証で検出するが、悪意ある同一利用者がサイズ・時刻等を復元した改変の即時検出までは保証しない。予約数をそのまま「保持確認済み候補数」やcoverageに使わず、保持の証拠と集計完全性を区別して8Cへ渡す。
- [ ] R47: 移動できないリンク・不正entry等に遭遇した場合は、元データを保持して固定理由のactionable UNKNOWNを残す。安全を証明できないものを自動削除・root外へ追跡・勝手にquarantineしない。この明示的停止は正常entry巡回の無言のprefix飢餓とは分け、同じ無限先頭走査を毎回繰り返す実装にしない。既に安全にcatalog化されたentryのID読取りと既存knowledge recallは妨げない。
- [ ] R57: 検出済み破損は本文・予約を保持してdurable UNKNOWNへ反映する一方、KeyProviderErrorによる鍵取得不能だけで恒久破損を断定しない。復号/開示/保持確認は失敗させ、正しい鍵での後続再認証と通常の容量検証を許す。呼出し側の参照/capture不一致と通常expiryも区別する。8B fix round1の対象に既存所有の`tests/unit/test_crypto.py`内`test_wrong_key_id_fails_without_returning_payload`を加え、非開示・本文/charge/TTL保持と鍵復旧後の再開を検証する。実認証不一致や改ざんの拒否を弱めない。
- [ ] R48: 設計の「別データベース禁止」は別のknowledge/候補本文の保管庫を指し、R42の本文なしruntime索引を明示的な例外として区別する。managed entryが既にあるのにcatalogが欠落・破損した場合は、固定理由の要対応UNKNOWN・新規容量受付停止・既知IDの安全な読取り維持とする。空catalogへ黙って初期化して容量を解放しない。通常のprepared中断復旧は実装するが、破損済み索引から全managed treeを自動再構築する第2の巡回機構は初版に追加しない。この制約と固定理由を8C/10へ引き渡し、正常・自動復旧済みと表示しない。
- [ ] R49: 中断した書込み/移動がdirectory stampを変えた場合、当該IDだけの修復でstampを更新せず、影響したshardのdirect membershipとcatalog/prepared IDを元の残予算内で照合する。照合未完了は`RUNTIME_SHARD_INVENTORY_UNKNOWN`・データ保持・容量ACK拒否であり、復旧済みとしない。通常サイズのshardは自動復旧を検証する。非常に大きなshardについて新たな深い分割方式は追加せず、未完了のsanitized証拠を保持して同じ状態・同じか小さい許容量での無意味な先頭走査を繰り返さない。既に許可された十分に大きい呼出し側予算、または関係する状態変化では再検証できるが、利用者の上限やdeadlineを増やさない。検証開始時の許容量と失敗時の残時間を混同しない。未完了記録も保存できなければ既存prepared/未確定状態を保つ。巨大shardの中断で要対応となり得る制約を8C/10へ引き渡す。
- [ ] R50: 本文作成前の`writing`予約は、同じID・purposeと、本文hash・classification・capture ID・元created/expiryへdomain-separatedな非空tagで結び付ける。対象未作成と意味上の一致を確認した再送だけ、再暗号化で変わるcipher digestを更新して既存予約の範囲内で再開できる。予約bytesを超える場合は拒否し、別候補・分類・用途・期限延長は許可しない。既存ファイルがある場合は先に実内容を照合・復旧し、未確認の上書きへ転用しない。他の破損・halted・予期しないmembershipを迂回せず、当該予約自身の未確定を再開するだけでinventory全体の完全性を主張しない。durable `deleting`後、unlinkと計上確定の間の中断で対象が欠落した場合は`RUNTIME_DELETE_UNCONFIRMED`・charge保持・要対応UNKNOWNとし、欠落だけで返金しない。対象実在・digest一致の削除前中断は再試行できる。新しいtombstone方式は追加せず、この削除後中断の自動復旧限界を8C/10へ渡す。
- [ ] 新規受付・lookup・削除・容量照合・pending照合・queue claim・tmp回収が新旧配置に整合し、8Aの残予算を内部のlock/loopまで受け取るようにする。部分inventoryを完全な容量・coverage・成功ACKとして扱わない。小さなlegacy API呼出しの意味を保持する。
- [ ] R54: 既存queue/intent更新のpre-file中断は、root lock内でwritingの非空old_digestと実在旧本文・関連metadata・他のphase/halt/accounting・全関連membershipを検証し、未適用更新を原子的に取消して旧状態から再試行する。既存のmetadata不変契約または旧本文の検証から関連を確認できない場合は拒否する。新digestが実在すれば通常確定し、旧状態へ戻さない。欠落・不一致はUNKNOWNのまま。registered sizeが実本文サイズも表す現schemaでは、証明済み未適用更新の増分予約に限り旧実sizeへ精算できる。これは削除後欠落の返金ではなく、元本文・ID・TTL・attemptを勝手に更新しない。新sidecar/本文catalog化はせず、old版復帰の中断・新本文保存済み・不一致・別shard異常・後続claimを実体テストする。
- [ ] R56: 期限切れreceiptを先に記録した対象の既知本文削除では、同じshardに残るengine所有・終了確認済みwriterの一時ファイルを、既存cleanup callbackと同一残予算で再照合・回収できるようにする。他shardのmembership照合、当該shardの双方向直接照合、本文digest/size一致、削除後の原子的計上を保持する。live/unknown owner、不正名、未知entry、不一致、別shard異常、予算切れでは削除成功や返金にしない。途中中断で本文が欠落したR50の制約は維持する。無関係のtmp失敗を当該captureのcleanup失敗へ混ぜず、同一候補の実temp失敗→復旧、危険/未知entry、別shard異常、中断、charge保持を回帰検証する。
- [ ] recover_page→ingest.coordinate_record→accept_candidateにも同じ残予算を伝播し、未ACK/期限切れでcursorを進めない。receipt・expiry/cleanup ID・元TTL・privacy/route ownershipを保持する。全履歴materializeや毎回先頭だけの処理で後続を飢餓状態にしない。
- [ ] 対象は`tests.unit.test_runtime_catalog tests.integration.test_pending_capture_recovery tests.unit.test_spool tests.unit.test_queue tests.unit.test_capture_recovery`と共有ingest/受付の既存integration。自己review・audit・固定snapshot全体成功後`feat: resume bounded runtime inventory and capture intake`で上記実変更filesのみcommitし、独立reviewを行う。

#### Task 8C: Hook・maintenance・status・schedulerの統合

8A/8Bを利用して上記Task 8の残りを完成させる。母Task 8のチェックリスト全体が受入条件であり、ここで未接続の項目を残さない。

**Files:** `src/ei/hook_entry.py`、`src/ei/capture.py`、`src/ei/maintainer.py`、`src/ei/task_scheduler.py`、`src/ei/cli.py`、`tests/unit/test_scheduler_opportunities.py`、`tests/integration/test_multi_host_lifecycle.py`、`src/ei/operation_runtime.py`、`tests/integration/test_unattended_operation.py`。

**R58追加対象:** `src/ei/organizer_recovery.py`、`tests/unit/test_organizer_recovery.py`、`src/ei/gate.py`、`tests/unit/test_gate.py`。validated-result保存/読取りとgate適用の内部I/O・queue遷移へ後方互換の`budget=None`を渡し、同じ残予算を守る。初回fingerprint保存が既存holdを解除しない小さなtrusted baseline APIをOrganizerRecoveryへ置けるが、認証・retry・料金・暗号化policyは変更しない。

**R59追加対象:** `src/ei/operation_health.py`、`src/ei/incidents.py`、`src/ei/notifications/base.py`、`schemas/operation-incident.schema.json`、`tests/unit/test_operation_health.py`、`tests/unit/test_incidents.py`、`tests/unit/test_notifications.py`。8C所有は計20ファイル。固定codeのstorage障害をProviderと別の型・incident familyで扱う。保持件数はCOMPLETE/PARTIAL/UNKNOWNとし、UNKNOWNはnull、PARTIALは確認できた範囲と明記する。容量予約数は別の証拠として80%判定に用い、保持件数に転用しない。旧in-memory APIの互換defaultと旧persisted情報の信頼度を区別する。

- [ ] R59: health cacheはschema v2・262144bytes以内・正確な型・非秘密のbinding・作成/失効時刻を検証する。有効期間はscheduler intervalから決め最大1時間。旧v1 cacheは保持証拠として再利用しない。新しい障害の証拠は部分件数と独立に扱い、cache不明や対象消失だけで既存incidentを解消しない。COMPLETEには単一の有界な全件認証と変更されていない対象/索引bindingが必要。PARTIALでも確認済みの容量/期限/障害リスクを示す。既存incidentに件数statusが無ければ読取り時だけUNKNOWN/nullへ正規化し、ID・通知制限・generationは保持し、読取りで保存しない。新記録のstatus/件数の組合せは厳密に検証する。

- [ ] R58: 上記helper内部のlock・暗号spool・queue遷移・集計I/Oへ元deadlineを渡す。初期fingerprint不明/同値は回復とせず、実Providerの確認済み回復または既知設定の変更だけを既存recoverへ渡す。変更後の再試行許可を障害解消の証明にしない。対象unit2modulesを最終focused検証へ追加する。

**R60追加対象:** `tests/unit/test_task_scheduler.py`。8C所有は計21ファイル。Linuxの新規生成timerは既存`OnBootSec=2min`と`OnUnitActiveSec=Nmin`を保ち、同じ最終activation基準の`OnUnitActiveSec=2Nmin`を1つ追加する。正常にN時点で起動すれば双方が新activationへ再設定され、通常間隔は変えない。2つ目は最初の起動逸失時のOS側再機会とし、timer配列・許容遅延・実行条件・同一bootの連続稼働を照合して数える。単なるelapsed/Nや最小NextElapseから二度目を捏造しない。旧単一triggerを読む場合は二度目の証拠不足を明示し、Hook/status/maintenanceから再登録しない。OnCalendar変更、毎分wake、暗黙のinterval丸め、実OS設定変更は行わない。safe数値範囲を超える倍算を有効triggerとして表示しない。

**R61追加対象:** `src/ei/journal.py`、`src/ei/changeset.py`、`src/ei/project.py`、`src/ei/index.py`、`src/ei/doctor.py`、`tests/unit/test_journal.py`、`tests/unit/test_changeset.py`、`tests/unit/test_index.py`、`tests/integration/test_projection.py`。8C所有は計30ファイル。doctorはprojectionの存在・参照先・鮮度診断だけを変更し、対応試験は所有するprojection integrationへ置く。

- [ ] R61: journalの任意budgetを読取り・重複検証・append直前とchangeset内部まで伝播する。budgetあり経路は50,000 events、raw合計64MiB、単一raw8MiB、filesystem entries60,000、depth8で有界にし、no-follow確認と元deadlineを保つ。既存1MiB payload契約を256KiBの新制限で狭めない。未完集合を返さず、時間切れ・固定容量上限・破損を区別する。固定上限は時間予算の増加や通常再試行で解消すると説明しない。budgetなしの旧API互換を維持し、実用にならないcheckpointや新しい本文DBを増やさない。
- [ ] R61: projectionは既存knowledge内の不変な派生generationを完全生成・検証してから、従来の全index fieldsと検証済み相対generation path/hashを持つroot/index.jsonを一度だけatomic replaceする。これを機械側の公開点とし、Markdownを機械の正本にしない。旧index/子ファイルを途中結果で上書きせず、KnowledgeIndexを検証済みgenerationへ束縛する。root/index.mdは完成generationへの可読リンクとして更新し、期限切れで遅れた場合はmirror-pendingを表示して次回maintenanceの新generation開始前に修復する。欠落・不正pointerを古い索引への暗黙fallbackにしない。Hook/CLI/maintainer/doctorの存在確認と鮮度照合も解決後のindexへ合わせる。
- [ ] R61: 派生generationはcurrent・previous・preparingの最大3つ、1つ64MiB/120,000 files、合計192MiB以内。元deadlineのlock内で、公開参照されないengine-owned対象だけを有界に片付け、確認できなければ新世代を追加しない。未知path/link/非所有物は削除しない。中断stagingを名前だけで完成扱いせず再検証し、currentの本文を上書きしない。2回以上の新しい公開後に古いhandleが失効し得る場合はINDEX_GENERATION_EXPIREDで拒否し、次回のfresh recallはcurrentを使う。未確認の混合読取りを成功にしない。旧budgetなしのmirror再構築互換を残す。
- [ ] R61: 1,000件を超える通常履歴と256KiBを超える正当eventの進行、zero/途中予算切れ、公開前後crash、旧読取りの保持、mirror修復、世代数/bytes上限・非所有/unsafe cleanup拒否・古いhandle失効、doctorの新旧鮮度を実体テストする。journal記録済み/索引未更新では保存済み推論結果を再利用し、索引の確定前にqueue/spool完了を偽装しない。

**R62追加対象:** `tests/unit/test_capture.py`。8C所有は計31ファイル。新trusted Skill経路を直接journal保存から暗号化pending受付へ移すため、既存の2試験を更新する。receipt関連付け失敗は既存legacy eventを先に作り、再関連付けで重複・書換えがない検証を保つ。別scopeは隔離InMemoryKeyProviderを使い、別queue/ciphertext/receiptへの対応を確認する。新pending受付の失敗/再送試験も維持し、成功期待だけを緩めない。

**R64追加対象:** `src/ei/reconciliation.py`、`tests/unit/test_reconciliation.py`、`tests/unit/test_maintainer.py`。8C所有は計34ファイル。reconcile_lifecycleと内部のcluster/event/recordループ・候補診断・journal appendへ後方互換の任意budgetを伝播し、昇格・廃止・dedup policyは変更しない。予算切れは部分集合を完全結果として返さず、追加の書込みや完了表示を開始しない。maintainer既存2試験はgenerationの解決後pathとbudget対応project callbackに整合させ、保存済みjournal保全・queue失敗後の索引更新・並行追記のSTALE検出という元の検証を維持する。

**R65追加対象:** `src/ei/metrics.py`、`tests/unit/test_metrics.py`、`src/ei/team_outbox.py`、`src/ei/team_projection.py`、`src/ei/team_store.py`、`tests/unit/test_team_outbox.py`、`tests/unit/test_team_projection.py`、`tests/unit/test_team_store.py`、`src/ei/sync.py`、`tests/unit/test_sync_plan.py`、`tests/integration/test_git_sync.py`、`src/ei/recovery.py`、`tests/integration/test_queue_recovery.py`。追加13、8C所有は計47ファイル。既存で選択済みのteam/syncと通常metricsを無断停止せず、後方互換の任意budgetを内部走査・読書き・子processまで伝播する。recovery.pyはreconcile_orphansとそのprivate helpersだけを対象とし、setup/root-migration復旧を変更しない。

- [ ] R65: metricsのno-follow探索・chunk hash・SQLite schema/rows/集計に同じdeadlineを渡し、残予算に収まる接続timeoutとprogress handlerを使う。中断を全件ゼロ/成功としてsnapshotへ保存せず、外部記事値を利用者の実測へ混ぜない。teamのscan/冪等確認・spool・receipt・projection/cursorも同じdeadlineと既存の安全制限を保ち、中断scanを全件と見なしてeventを重複作成したり、既存cacheを部分集合で上書きしたりしない。
- [ ] R65: syncは実GitRunner・内部runner・再試行・copy/journal/projection/state/cleanupまで同じdeadlineを使い、元のprivacy/allowlist/remote assurance/所有worktree/append-only規則を保つ。開始済みpushのtimeoutを未送信の証明にしない。期限後は追加のGit・rebase abort・cleanup・state writeを開始せず、所有情報を残して次回の既存復旧へ渡す。認証対話は非対話のprocess限定設定で抑止し、利用者の恒久Git/OS設定を変えない。orphanの明示API呼出しも同じbudgetで読み取り・append・診断保存を扱い、旧budgetなし互換を維持する。
- [ ] R65: zero/途中期限切れと次回再実行、選択済team/syncの継続、SQLite中断と旧snapshot保持、team既存event再送非重複、sync期限後の追加副作用なし・ownership保持を隔離fixtureで検証する。全既存対象modulesも実行する。実ネットワーク、利用者repoへのGit操作、live DB/共有フォルダ/OS登録には触れない。OS syscall自体を厳密なwall-clock内に中断できる保証や、同期timeoutによるremote未変更保証はしない。

**R66 Windows停止検知の境界:** native queryは登録/action XML・enabled/running・LastRunTime/LastTaskResult/NextRunTime・NumberOfMissedRuns・boot/awakeを有界read-onlyで独立観測する。NumberOfMissedRunsはOS停止等による逸失を含むため、実行可能な逸失回数へ加算しない。予定から当時のlogon/battery条件や登録の連続性も証明しない。初版はeligible count=null、`SCHEDULER_OPPORTUNITY_EVIDENCE_UNAVAILABLE`とし、query自体の非対応を別理由にする。独立した実attempt receiptを将来採用するには、固有ID・時刻・原因・同actionとの結び付けの一次契約が必要で、初版の実装済み機能とはしない。Task9のscheduler_monitorは未確認、全体もUNVERIFIEDとする。認証障害など別の確認済み障害を消したり、登録/通常実行を未観測扱いにしたりはしない。

**R67 capture namespace:** boundedで完全検証したinstall manifestと現在設定のroots・選択work host/homeが一致する場合だけ共通helperからidentityを作る。instanceはcanonical UTF-8 JSON `{domain:'ei-capture-instance-v1',host_id,host_home}`、personal storeは`{domain:'ei-capture-personal-store-v1',personal_root}`のSHA256（sha256: prefix）。pathはabsolute canonical resolve+normcaseで比較し、同じdeadline/no-follow制約を守る。Hook record domainは`ei-hook-target-v1`でhost/session/turn hash・event kind、Skillは`ei-agent-record-v1`でsession/turn hash・normalized candidate hashを入力とする。sourceの既存parser/version/relative-path/stable-record-id由来hashは維持し、metadataとsourceの等値/coverageを推定しない。移動/renameでnamespaceは変わるが旧receiptやpendingを自動書換え/成功化せず、legacy event ID再関連付けを保つ。raw pathや本文を新たな公開記録へ保存しない。canonical同値・別host/home/store・不正manifest・移動時の旧receipt保全を隔離fixtureで検証する。追加所有filesなし。

**R68 portable projection ownership:** generation ownerの初公開形式はschema_version=1、閉じたowner kindと全expected path/size/hash map、`generation_binding=SHA256(canonical JSON {domain:'ei-projection-generation-v1',manifest_sha256:<generation basename>})`とする。絶対rootに結び付けず、basename=manifest hash、manifest/index/全file bytes・root pointer・no-follow・未知entry拒否・3世代/bytes制限で完成/所有を確認する。copy/clone/専用同期worktreeでも検証できる派生物とする。先行中のroot_binding形式は未commit/未release・live未適用なので移行機能を作らず、遭遇した未知markerは保持してUNOWNEDとする。既存公開済みlegacy mirror/budgetなしAPIの互換は維持する。別pathコピー後の旧recall→有界再projection→安全な世代保持と、改ざん/未知marker/余分file/link保持をprojection/git_syncの隔離fixtureで検証する。追加所有filesなし。

**R69追加対象:** `src/ei/remote_assurance.py`、`tests/unit/test_remote_assurance.py`、`src/ei/safe_fs.py`、`tests/unit/test_safe_fs.py`。追加4、8C所有は計51ファイル。sync内に同じgh probe・tree digest・削除処理を複製せず、既存helperへ後方互換の任意budgetを渡す。remoteはassure_remote/classify_remote/_probe_github_visibilityの伝播と元残時間以下のtimeoutだけを対象とし、visibility分類・attestation・remote fingerprint・engine remote再利用禁止のpolicyを変えない。safe_fsはtree_digest/_file_digest/_tree_entries/safe_remove_treeのchunk読取り・loop・変更直前の予算確認だけを対象とする。ownership、no-follow、包含、digest形式/byte順序/モード、削除直前の再検証を保つ。他のsetup/移行用APIを改造しない。zero/途中budget、legacy digest同一、途中cleanup後の所有情報保持と安全な次回再試行、unsafe/link/unknown拒否と既存2modulesを検証する。期限切れを正常な確認済みvisibilityや成功cleanupに変換せず、既存の明示許可を拡張しない。実ネットワーク・利用者ファイル削除・OS変更はしない。

**R70 source reconciliation:** 同期後にsourceの未追跡event/generationを消してからfetch/mergeする順序を廃止する。fresh status/preflightでscope外の変更を保持して拒否し、既送commit:pathのblobとsourceのraw `hash-object --no-filters`を照合したexact managed pathsだけstageする。target commit/ancestorを検証し、既送の固定SHAへff-onlyで合わせる。途中で進んだ別remote HEADを無断採用せず、期限切れでは追加Gitを開始しない。stageとmergeの間で止まっても本文・current recall・所有情報を保持し、worktree側NO_ENGINE_CHANGESでも次回source照合へ進める。remoteへ送信済みかとsource反映完了を分離し、未反映は`SYNC_SOURCE_RECONCILIATION_PENDING`として完了を偽装しない。budget=Noneも同じ非削除手順を使い、任意budget/APIの後方互換を保つ。reset/stash/force操作、任意source file削除は追加しない。既存owned git_syncに成功・途中停止・再試行・同時/既存変更保全の隔離実体試験を置く。

**R71追加対象:** `src/ei/sync_policy.py`。8C所有は計52ファイル。最初のbounded generation準備前にknowledge rootの`.gitattributes`を固定内容 `.projection-generations/** -text\n` で原子的に作成/検証する。属性ファイル自身はCRLF→LFの同値だけ許容し、空白や追加rule/別内容・link等は保持してPROJECTION_ATTRIBUTES_CONFLICT等で拒否する。zero budgetでは作らない。sync allowlistへ追加するのはexact `knowledge/.gitattributes`だけで、sync.pyは固定内容を検証する。他の属性pathや任意ルールを許可せず、repo/global Git設定は変更しない。通常の`core.autocrlf=true` clone/専用worktreeでraw generation hash・recall・再projection・保持数を実体試験し、clone fixtureをautocrlf=falseにして問題を隠さない。変換済みgenerationのhash不一致を黙って許容/書換えず、未知file/既存属性を保持する。root index.jsonは既存の意味比較、index.md改行差分は既存mirror修復契約を維持する。test_sync_plan・git_sync・projectionの既存ownershipで試験する。

**R72追加対象:** `src/ei/curator.py`、`tests/unit/test_curator.py`。8C所有は計54ファイル。既存第4引数budgetは昇格policy用のまま保ち、別のkeyword-only `operation_budget=None`を追加して、元deadlineを索引読取り・各形式のpattern列挙・適合/類似走査・ChangeSet返却前へ渡す。時間切れの部分走査からNO_CHANGEや候補を返さず、既存のmatching・tie-break・promotion・privacy・host-scope規則とbudgetなし互換を維持する。maintainerは同じobjectを渡し、期限切れ時は保存済み推論結果/queueの既存再試行契約を保つ。zero/索引内部/候補ループ途中の期限切れと通常結果同値を実体fixtureで検証し、既存curator module全体をfocused検証に含める。新しいAI呼出し・料金policy・永続状態や所有範囲外の変更は追加しない。

**R73追加対象:** `src/ei/ingest.py`、`tests/integration/test_ingest_cursor.py`。8C所有は計56ファイル。coordinate_recordのevent routeにあるappend_eventと_planned_eventのread_eventへ、既に引数で受け取る同じbudgetを渡す。R61以前はjournal APIが未対応だった接続の補完に限定し、legacy ingest_sources全体・route/identity/cursor/重複規則は改造しない。zero/内部期限切れでevent・receipt・cursorの完了を偽装せず、次回の同一event再利用と旧budgetなし動作を確認する。実在する既存ingest_cursor module全体をfocused検証へ追加する。

**R74追加対象:** `src/ei/capture_recovery.py`、`tests/unit/test_capture_recovery.py`。8C所有は計58ファイル。RecoverySourceのinstance_hash/store_idは両方Noneの場合だけlegacy namespace不明として許可し、片方欠落・不正present値・不正hostは拒否する。identityを捏造せず既存coordinate_recordへNoneを渡し、保存済みroute/bindingを尊重して、確かなeventまたは既存receiptの永続結果の後だけsecured/cursorを進める。coverageはUNKNOWNのまま。None経路でも旧ingestと同等のprivacy/classification検査を必ず本文保存前に行い、拒否本文はcoordinatorへ渡さずsanitized拒否metadataのみとする。rootは従来dirに加え明示exact fileを受け入れられるが、no-follow/is_readable_metadata_pathと対応read_verified parserを必須とし、親は包含anchorのみ、frontierはその1fileだけ、保存cursorも選択外pathを拒否し、source_keyへ元の選択fileを含めて親や兄弟を列挙しない。これにより明示valid.md等の既存利用を保ち、自動dir探索は既存accepts_path/denied-directory規則を維持する。未確認adapterをverifiedへ昇格せず、whole-source fallbackや新selector/本文store/永続protocolを追加しない。zero/内部中断/同event再試行、namespace不正、秘密・機密拒否、exact file隣接対象と改ざんcursor/linkの拒否、既存trusted/legacy結果を実体fixtureで検証し、既存capture_recovery module全体をfocused検証へ含める。

**R75出力互換:** R74の既存所有内でRecoveryPage末尾へ後方互換defaultの`created_events: int = 0`を追加できる。coordinate_recordのwas_createdと永続eventの確認、元budgetの検査後だけ加算し、securedや新pending件数を作成event数へ転用しない。再送eventは新規0、trusted pending受付もevent作成0とする。既存6位置引数の構築を保ち、未完了pageを全件集計と表示せず、既存skipped等の意味も別種の件数で代用しない。実体fixtureで新規legacy event・replay・pending・期限切れと旧構築互換を検証する。所有file追加なし、計58のまま。

**R76追加対象:** `src/ei/retrieve.py`、`tests/unit/test_retrieve.py`、`src/ei/experiment.py`、`tests/unit/test_experiment.py`、`src/ei/measurement_events.py`、`tests/integration/test_host_neutral_measurement.py`。追加6、8C所有は計64ファイル。rank_patterns/_rank_patterns/search_indexとrecord_retrieval_exposure、prepare_exposure/_append_legacy_exposure、およびそのsettings経路のrecord_exposure/_append_unique/_exclusive_lockへ後方互換keyword-only budget=Noneで同じdeadlineを渡す。索引read・eligible/token/date/score/dedup/sort-key/result各loop・返却前とlogのno-follow/chunk読取り・重複scan・append前を確認する。lockは残時間内の非blocking待機、取得したlockのみ解放する。途中scanやtimeoutを不存在・検索hitゼロ・記録成功へ変換せず、旧rank順位/policy/tie-break/experiment割当・schema・重複identity/計測意味を維持する。新しいlog store/cacheやランキング複製は追加しない。build_context・他の集計/分析は対象外。zero/内部期限切れ・lock競合・no-follow・重複scan中断と再試行・正常結果同値を実体検証し、既存3 test modules全体をfocusedに含める。Hookは既存index予算APIとこれらを使い、期限後に新しいlog/state処理を開始しない。閉じるべきdescriptor/取得済みlockの解放は維持する。

**R77追加対象:** `src/ei/canary.py`、`tests/unit/test_canary.py`。追加2、8C所有は計66ファイル。Hook到達経路のbuild_canary_receipt_from_event/from_event→template hash、record_canary→receipt重複scan/appendへ同じ任意budgetを渡し、no-follow/chunk読取り・scan・書込み前に確認する。未完scanを重複なしとしてappendせず、TimeoutErrorを通常OSErrorの空結果へ落とさない。既存receipt形式・hash・TTL・重複identityを維持し、Hookのためにsource tree全走査や新証拠storeを追加しない。read_hook_statusには後方互換keyword-only persist=Trueを追加し、CLI statusのみFalseでsnapshot保存を抑止する。通常setup/certificationの既存保存は維持し、全static-canary解析の改造はしない。zero/内部deadline・unsafe path・重複retry・status未作成runtimeの全file不変・旧persist既定動作を既存moduleとowned integrationで検証する。

**R78追加fixture:** 所有済みtests/unit/test_maintainer.pyのtest_maintenance_continues_after_independent_source_failure_and_gcs_expired_spoolも、R64の2fixtureと同じくbuild_index(...).index_path.parent/manifest.jsonを確認する。個別source失敗後の他source継続、期限切れGC、personal/team結果、読める完成projectionという元の主張を維持し、期待の削除や成功条件の緩和で回避しない。所有file追加なし、計66のまま。

**R79 maintenance外枠:** 所有済みcli/maintainer/syncと対応testsだけで、CLIはsource探索・lock取得前に1つのOperationBudgetを作り、run_maintenanceの後方互換keyword-only budget=Noneへ同じobjectを渡す。明示sourceはexact file/directory rootsとして有界recoveryへ渡し、_source_pathsの全rglobを通さず、許可範囲とparser/privacy/no-follow契約を維持する。log rotation/appendとFileLockの取得・stale判定も元deadlineで有界にし、期限後の通常log/state/Git/cleanupを開始しない。取得済みlockの解放だけはresource-release例外とし、新しい猶予deadlineなしで当該1pathを最大4096bytes/no-followで確認し、取得時file identityとtokenが両方一致する場合だけ解放する。巨大・破損・link・置換・他token・確認不能は保存し、読取り失敗を所有の証明にしない。descriptorは常に閉じる。例外は他のstale lockやscratch削除、scan/retryへ広げない。zero/途中deadlineで後続呼出し・log mutationなし、正常同object伝播、期限切れ後の同一process再取得、置換/不正lock保存、既存budgetなし互換を実体fixtureで確認する。OS syscallそのものの厳密wall-clock中断は保証しない。新fileなし、計66。

**R80互換fixture追加:** `tests/unit/test_hook_entry.py`、`tests/integration/test_hook_canary.py`、`tests/unit/test_cli.py`を追加し、8C所有を計69ファイル、最終focusedを35 test modulesとする。deadline fixtureの有限2値clockは0→1の後も1を返すfakeへ替え、期限切れ/空context/fail-open/秘密非出力の主張を維持する。metadataのみのHookはdurable UNKNOWN receipt・空candidate・queueなしを検証し、既存canaryの3event/instance対応を維持する。status fixtureは実Settingsを使い、古いqueue_health mock成功ではなくread-only custody cacheが欠けた場合のUNKNOWN/nullを確認する。整理AI1つ/work_hosts複数の分離と無書込み/Provider probeなしの主張を保つ。budget=Noneの旧callback互換と欠落templateの旧empty-hash receipt互換は所有済みproduction内で直し、unsafe/linkやdeadlineの拒否は緩和しない。テストの期待を削除して回避せず、追加3modules全体を最終GREENに含める。

**R81 Skill件数上限の保持:** `src/ei/pending_capture.py`、`src/ei/runtime_catalog.py`、`tests/unit/test_pending_capture.py`、`tests/unit/test_runtime_catalog.py`、`tests/integration/test_pending_capture_recovery.py`を追加し、8C所有は計74ファイル、最終focusedは38 modules。既存pending intentに非本文admission metadata `{origin: AGENT_SKILL|NATIVE_SOURCE|UNKNOWN, session_hash: sha256|null, agent_key: 既存_capture_key|null}`を保存し、同時に既存catalog.tagへorigin/sessionを索引化する。欠落・public API既定はUNKNOWN、record_agent_observationのみAGENT_SKILL、coordinate_recordのみNATIVE_SOURCEを明示する。sessionは既存identityと照合し、Skill keyは既存形式・意味を保つ。本文・外部ID・TTL・capture_max_per_session値を変えず、native/metadataをSkill上限へ混ぜない。新DB・receipt identityの捏造・新backfill/checkpointは追加しない。catalogの追加APIは同budgetのbounded tagged_paths(tag,limit,budget)だけで、完全inventory/未tagなしと返却entryのdigest・派生tag一致を検証する。走査中断・上限による部分集合・未知の実験intent/未tag旧catalogを件数0や不存在にせずSESSION_CAPTURE_HISTORY_UNKNOWN/期限切れで新受付を拒否し、元データは保持する。既に正当にtag付けされたUNKNOWN originは同sessionだけに影響させ、別session/nativeへ一律拡張しない。公開前の旧formatだけのための自動tag移行は不要。

R81 atomic admission: record_agent_observationのjournal再読取り・既存event/intent replay・件数照合・legacy appendまたはpending PREPARED作成を、既存capture ledger同lock内で直列化する。pendingはprivate _accept_candidate_lockedへ切り出し、public lock/APIを保持する。legacy receipt関連付けはunlock後に既存修復経路を使う。件数は同sessionのlegacy events＋AGENT_SKILL intentのdistinct agent_keyとし、旧eventの同capture_idempotency_key重複を除外する。exact replayは上限に先行し同候補を再利用する。PREPAREDを保守的な受付枠予約として扱い、COMMITTED/terminal/EXPIRED後も旧append-only履歴同様に枠を保持する。失敗PREPAREDは同候補で再試行でき、未保存の確証なく枠を返さない。この予約は保持済み件数ではない。trusted4件目・legacy合算/重複・full replay・残1枠で同時2受付・NO/DONE/expired・native独立・UNKNOWNの適用範囲・破損/tag不一致/deadline/partialでno ACKを実体検証し、追加3test modules全体も実行する。既存pending/journalの上限・プライバシー・暗号化・安全な再試行規則は変更しない。

**R82 全体gate回帰修正:** `tests/acceptance/test_single_intelligence_multi_cli.py`、`tests/integration/test_capture_fallback.py`、`tests/integration/test_maintenance.py`、`tests/integration/test_organizer_restart.py`を追加し、8C所有を計78ファイルとする。42所有test modulesに未変更の`tests.integration.test_single_organizer`も加え、最終focusedは43 modules。全体gateの7失敗moduleを個別processでも実行し、Windows非UTF-8既定とimport順依存を隠さない。multi-CLI fixtureはtrusted pending受付のqueue/暗号化本文を確認し、organizer後のevent保存・単一整理AI・scope別recall・rerun/update/uninstallの知識保持を維持する。metadata Hookはqueueなし、late secured fixtureは実session/turn hashと隔離鍵を使い、同候補/hash・queue非増加を検証する。maintenanceは毎回build_indexで解決した世代manifestを比較し、冪等性・partial・personal READY/team DISABLEDを維持する。restartでは正当な初回config fingerprintを別assertionにし、残り全fieldと他候補の許可を維持する。partial append mockは同budgetを受渡し、2回目の意図した失敗・1 operation保存・commit marker未公開を確認する。既存owned capture.py/test_capture.pyで認証済みSECUREDかつ新規作成なしの再送理由IDEMPOTENT_REPLAYを保ち、UNKNOWN/失敗を成功へ変換しない。既存owned maintainer.py/testsでbounded config読取りとProvider構築の例外境界を分離し、構造不正はINFERENCE_PROVIDER_CONFIG_INVALID、構文/読取/欠落はINFERENCE_PROVIDER_CONFIG_READ_FAILED、構築不正はORGANIZER_PROVIDER_CONFIG_INVALIDとし、期限切れは伝播する。projection fixtureはUTF-8を明示し、unattended fixtureのpatch前に依存moduleを読み込み実OperationBudgetの同一性を検証してmockの残留を防ぐ。元の件数/progress/独立source継続条件は削除しない。新機能・実環境変更・無関係なfixture整理は含めない。

**R83 後続回帰の原因修正:** 既存owned curator.py/test_curator.pyで、candidateの正当なfull SHA256 cwd_fingerprintをCREATE_OBSERVATIONへ引継ぎ、欠ける場合は非空stringのraw cwdから既存ids.fingerprintを導出する。raw文字列を勝手にtrim/resolve/大文字小文字変換せず、旧直接観測と同じhash意味を保つ。欠落/空は空、無効な既存hashは正当な既存hashとして保存せず、raw pathをjournalへ保存しない。必要な既存candidate normalizer内の伝播だけを行い、Provider出力から案件証拠を捏造しない。異なる/同じcwd・既存hash・空/不正値と秘密path非保存を先にREDで検証し、multi-CLIで6観測の正確なhash・3昇格・元の全scope別recall/知識保持を確認する。promotion閾値・lifecycle・host applicability・dedup policyは変えない。既存owned capture_recovery.py/test_capture_recovery.pyではparser呼出し/iterator進行だけの狭い境界でUnicodeError/ValueErrorをprivate parse例外へ分類する。TimeoutErrorは伝播し、外側のcursor/state/FS/unsafe/storage失敗はparse失敗へ変換しない。parse失敗は既存SOURCE_PARTIALとparse_skippedへ反映し、frontier/未ACK offset・coverage UNKNOWNを維持する。maintenanceのSOURCE_PARTIAL/exit0/以前のreadable projectionという既存契約を復元するだけで、他の失敗を成功化しない。invalid UTF-8・iterator途中失敗・state破損・deadlineを実体検証し、CLIや公開API/新reasonは増やさない。所有78paths/最終43modulesは不変、新しい機能・live変更はない。

- [ ] metadata-only Hookの追跡台帳化、legacy observation再利用、bounded cache生成/読取り、原因一致の解消証拠、provider needs_action/READY、trusted fingerprint/auth回復、同じrun_idと残予算を接続する。旧journal書換え・実AI呼出し・live設定変更なし。
- [ ] maintenanceをpending照合→有界source回収→単一organizer→journal/projection→health/incident/通知の順で接続し、早期例外もfail-open/sanitizedとする。日常入力なし、正常通知なし、HookでAI/全履歴走査なし、statusは読取専用。
- [ ] scheduler登録ではなく実行可能機会をOS予定/結果/同一boot/suspend証拠で判定し、証拠不足はunknown、2回以上の確認済み逸失だけ停止警告とする。明示disableを保持し、両経路停止時の検知不能も表示・検証する。
- [ ] R63: macOSは現在確認できるnative情報からjob再登録世代を証明できないため、plist/action・state/last_exit/runs・boot/awakeを有界read-onlyで別々に観測し、逸失数はnull・SCHEDULER_GENERATION_EVIDENCE_UNAVAILABLEとする。読取り自体が非対応ならSCHEDULER_QUERY_UNSUPPORTED。同じexit状態の再読取りを別の失敗へ数えず、plist/runsの両端一致を世代証拠にしない。これは初版macOSの停止検知上の制約であり、Task9/10へ引継ぎ、無操作運用準備や停止検知を確認済みにしない。新常駐監視・実OS設定変更は追加しない。
- [ ] 対象`tests.integration.test_unattended_operation tests.unit.test_scheduler_opportunities tests.unit.test_task_scheduler tests.integration.test_multi_host_lifecycle tests.unit.test_maintainer`と全体を検証し、`feat: wire unattended capture recovery and health checks`で上記実変更filesのみcommitする。独立reviewで母Task 8との接続も確認後、Task 8全体を完了にする。

### Task 9: setup・updateと初回の運用証拠

**R92承認済み範囲:** 初版の実CLI自動テストdriverを保留し、未実証項目を`UNVERIFIED`として、設定・証拠・通知・scheduler・公開CLIの接続を完成させる。保留機能の実装完了や実運用確認を宣言しない。認証復旧を判別できないCLIの再ログイン後の1回の再開操作も承認済みで、最終修正waveに含める。

**R93追加対象:** `src/ei/certification.py`、`tests/certification/test_receipt_contract.py`（R91までの17と合わせ計19）。`certify_host`に厳密boolの`allow_version_probe=True`を追加し、falseで既存receiptのみを分類できるようにする。`verify_operation`はfalseで呼び、保留中のnativeテストの代わりに既存CLIを起動しない。返却値は`automatic_operation`、当該呼出しの`notification_send`（未実施は`NOT_ATTEMPTED`）、`reason_codes`、`evidence`を持ち、Task10との型・キー契約を合わせる。

**R87追加対象:** `src/ei/task_scheduler.py`、`tests/unit/test_task_scheduler.py`。明示setup/updateでのみowned旧Linux timer定義を新定義へ整合させ、installerとregister_scheduler両方のALREADY_CURRENT条件を確認する。明示disable/check-only/所有hash/競合保持を維持し、unregister-firstを避ける。Windows登録のExecutionPolicy Bypass引数は除去して既存policy拒否を尊重する。計14ファイル、実OS操作は別承認境界。

**R89追加対象:** `scripts/setup.ps1`、`scripts/setup.sh`（計16ファイル）。公開setupの入口からも検証・モデル利用・通知テストの3フラグを個別に渡せるようにする。PowerShellは`-VerifyOperation`、`-AllowModelTest`、`-AllowNotificationTest`、shは同じ意味のkebab-caseとする。既定false、引数の安全な転送、check-only最優先、依存ソフト導入への同意との分離を維持し、所有する`tests/integration/test_unattended_setup.py`内で検証する。

**R91追加対象:** Create `scripts/notifications/register-windows-notification.ps1`（計17ファイル）。AUMID付きShellLink生成・実体検証を限定されたhelperへ分ける。installerの所有transactionと一体で扱い、衝突時・途中失敗時・uninstall時に他者のファイルを変更しない。既存ExecutionPolicyに従い、fake runnerの合格を実OS登録の実証に流用しない。

**R95所有権記録:** 既存の閉じたinstall-manifest schemaを拡張せず、機械ローカル`runtime/windows-notification-ownership.json`を限定所有権receipt（schema1、8KiB以内）として使う。通知設定は複製しない。固定OS対象を信頼済み環境から計算し、installerのtarget、実AUMID/TargetPath、shortcut/登録記録のhashと照合する。所有記録なしに既存ファイルを取得・上書きしない。作成とreceipt保存、後続失敗のrollbackを整合させ、当該操作が作成した未変更ファイルのみ後片付けする。保存失敗や所有不明を成功にせず、他者・改変済みファイルを保持する。対象ファイル数は19のまま。

**R96: Task9レビュー後の限定修正。** 既存テストが新しいWindows通知処理を実環境から隔離していなかったため全体検証を中断。テスト側だけの共通stateful fakeと子プロセスbootstrapを導入し、`-I` wrapperには隔離を維持するテスト用Python shimを用いる。bootstrap失敗時も実入口へ進めず、許可したhelper argv以外を拒否する。本体のTEST分岐や成功stub、Windows経路の省略は行わない。実setup/receipt/journal/CLIを保持してdirect・child・初期化失敗のguardを検証してから全体試験を再開する。併せてPROPVARIANTをx86/64のABIへ合わせ、実COMを使わないlayout試験を追加する。副作用のないPREPARED失敗だけを保守的に復旧し、不確実な部分作成は保持。所有記録8KiB/shortcut64KiBを読む前から有界にする。

R96の変更対象は次の21ファイル（既存Task9の変更は保持、追加範囲の目的は上記指摘だけ）。

- `src/ei/installer.py`
- `scripts/notifications/register-windows-notification.ps1`
- 新規 `tests/support/sitecustomize.py`
- `tests/acceptance/test_cross_platform_setup.py`
- `tests/acceptance/test_fresh_pc_restore.py`
- `tests/acceptance/test_public_setup_journey.py`
- `tests/acceptance/test_rollback.py`
- `tests/acceptance/test_setup_rerun_reconciliation.py`
- `tests/acceptance/test_single_intelligence_multi_cli.py`
- `tests/acceptance/test_two_machine_sync.py`
- `tests/acceptance/test_setup_prerequisites.py`
- `tests/integration/test_manifest_restart.py`
- `tests/integration/test_multi_host_lifecycle.py`
- `tests/integration/test_one_shot_local_setup.py`
- `tests/integration/test_personal_team_setup.py`
- `tests/integration/test_team_update_uninstall.py`
- `tests/integration/test_unattended_setup.py`
- `tests/integration/test_install_scripts.py`
- `tests/unit/test_cli.py`
- `tests/unit/test_scheduler_installer_production_defects.py`
- `tests/unit/test_setup_onboarding.py`

**R97: 旧install wrapperの限定修正。** `scripts/install.ps1`が内部の`setup.ps1`起動へ渡している`-ExecutionPolicy Bypass`だけを除去するため、同ファイルをTask9 fix1の所有範囲へ追加する（R96と合わせて22ファイル）。既存policyを尊重し、policy変更・迂回・未実行を成功扱いする代替は追加しない。引数転送とexit codeを維持し、既に所有している`tests/integration/test_install_scripts.py`で迂回引数がないこととwrapper動作を検証する。この経路が修正・隔離されるまでは実行しない。他のwrapper一般化や範囲拡張は行わない。

**Files:**

- Create: `src/ei/operation_activation.py`
- Create: `schemas/operation-activation.schema.json`
- Create: `tests/unit/test_operation_activation.py`
- Create: `tests/integration/test_unattended_setup.py`
- Modify: `src/ei/setup_activation.py`、`src/ei/setup_ui.py`、`src/ei/setup_reconciliation.py`
- Modify: `src/ei/installer.py`、`src/ei/cli.py`、`src/ei/config.py`
- Modify: `tests/unit/test_setup_onboarding.py`、`tests/acceptance/test_setup_rerun_reconciliation.py`

**Interfaces:** `activation_readiness(evidence: dict) -> str`、`load_operation_evidence(settings: Settings) -> dict`、`invalidate_operation_evidence(evidence: dict, current_binding: dict) -> dict`、`verify_operation(settings: Settings, *, allow_model_test: bool, allow_notification_test: bool, confirmed_notification_seen: bool = False) -> dict`。readinessは`VERIFIED` / `UNVERIFIED` / `DISABLED`。

**Task 8との保存契約:** `runtime/automatic-operation.json`は64KiB以内で`schema_version:1`、`settings.notifications={enabled:bool,channel:"os"}`、`settings.initial_test={allow_model_test:bool,allow_notification_test:bool}`、独立した`evidence` objectを持つ。日常通知のenabledと初回テストの2種類の同意を混同しない。既存scheduler選択を参照し、requestedやProvider/root選択を重複保存しない。evidenceはHost/version/binding等を結び付けた詳細記録にし、単純なaccepted/visible文字列を根拠なくverifiedへ転用しない。既存falseを保持し、check-onlyはこのファイルも変更しない。

- [ ] 次を追加し、`python -m unittest tests.unit.test_operation_activation -v`で失敗を確認する。

```python
import unittest
from ei.operation_activation import activation_readiness

class OperationActivationTests(unittest.TestCase):
    def test_api_acceptance_is_not_display_confirmation(self):
        evidence = dict(binding="VERIFIED", hook="VERIFIED", accumulation="VERIFIED",
                        recall="VERIFIED", scheduler_run="VERIFIED", scheduler_monitor="VERIFIED",
                        notification_send="SENT",
                        notification_display="UNVERIFIED", scheduler_requested=True)
        self.assertEqual(activation_readiness(evidence), "UNVERIFIED")
        evidence["notification_display"] = "VERIFIED"
        self.assertEqual(activation_readiness(evidence), "VERIFIED")
```

- [ ] readinessの核を実装する。各work Hostの結果は別に評価し、総合は全対象が満たした場合だけVERIFIEDにする。

```python
def activation_readiness(evidence):
    if evidence.get("scheduler_requested") is False:
        return "DISABLED"
    fields = ("binding", "hook", "accumulation", "recall", "scheduler_run", "scheduler_monitor", "notification_display")
    return "VERIFIED" if all(evidence.get(key) == "VERIFIED" for key in fields) else "UNVERIFIED"
```

- [ ] 機械ローカル`runtime/automatic-operation.json`に設定と証拠を分離したschema v1を保存する。設定は通知のenabled/channel、initial-testの同意、既存scheduler選択への参照だけ。root/provider選択を複製しない。証拠はengine code hash、Host/version、profile/binding hash、OS/channel、テスト時刻、観測種別。通知の権限・確認結果はknowledge同期へ入れない。
- [ ] `verify_operation`は事前許可のあるsynthetic testだけ実行する。既存certificationの実Host・Hook確認を再利用し、実CLI → 安全な構造化候補 → maintenance → event保存 → 次回実CLI recallを関連IDで追う。Hookへ手作りpayloadを送った結果を実CLI証拠へ転用しない。実CLIの隔離home/rootが使えなければ実環境を黙って差替えず、未確認で設定を保持する。
- [ ] OS schedulerは登録と実際のテスト実行を分離。通知もAPI送信と初回表示確認を分離。利用者の回答だけでHook受信や蓄積をverifiedにしない。初回画面確認は一度だけ、既存証拠が有効ならsetup再実行で再質問しない。version/channel/binding変更時は該当証拠だけ無効化する。
- [ ] R63/R66: 初版Windows/macOSのnative停止検知は履歴上の実行可能機会を確証できず、scheduler_monitor=UNVERIFIED、総合もUNVERIFIEDとする。WindowsのNumberOfMissedRunsや現在の予定/設定、macOSの同じplist/runsを証拠に変換しない。通常実行や蓄積・通知の確認済み項目は独立して残し、何が未確認かを説明する。実機での正常な1回の実行を、停止監視能力の確認済みへ昇格させない。
- [ ] setupには次の説明を一つの流れで表示する。選択項目を増やすより既定値と影響を説明する。

```text
自動蓄積: 設定したCLIの再利用候補を自動で保存・整理します。
通常の作業中に保存や再試行の確認は表示しません。
異常時: OS通知、対応が確認できたCLIでは画面にも案内します。
候補の保持: 既定30日、1,000件または64MiB。満杯・期限前に警告します。
取得対象: 許可した構造化記憶・要約・再利用候補。生の会話履歴は取得しません。
最初の確認: CLI/OS側の必要な許可と、蓄積・取得・通知のテストを行います。
AIのテストには選択した整理AIと作業CLIの利用枠を使う場合があります。
```

- [ ] noninteractiveは明示`--verify-operation`、`--allow-model-test`、`--allow-notification-test`を新設し、不足時にstdin待ちしない。表示確認はinteractive時か別途明示確認済みreceiptのみ。`--check-only`はこれらflagsと同時でも副作用を抑止し、AI/通知/OS登録/knowledge書込みゼロをmockで確認する。
- [ ] Windows通知shortcutの登録はinstallerの所有権記録に含め、他アプリのファイルと衝突したら保持してUNAVAILABLE。uninstallは自分が登録しhash一致するものだけ削除する。macOS/Linuxの通知拒否をsetupが解除しない。既存個人/team knowledge、identity、organizer、`--no-scheduler`、通知disableをrerun/updateで保持する。
- [ ] Task 7のWindows送信契約を使用する。shortcutは`%APPDATA%/Microsoft/Windows/Start Menu/Programs/External Intelligence.lnk`、登録記録は`%LOCALAPPDATA%/MiyaIF/ExternalIntelligence/notification-registration.json`。記録は`schema_version: 1`、`app_id: "MiyaIF.ExternalIntelligence"`、`shortcut_sha256`（64桁小文字hex）、`target`（絶対path）を持ち、実際に作成したowned shortcutのhash・System.AppUserModel.ID・TargetPathと照合する。記録8,192 bytes、shortcut65,536 bytesを上限とし、setupの安全な所有権記録・衝突保持・uninstall照合と整合させる。既存ExecutionPolicyで拒否された環境は迂回せずDENIED/UNVERIFIEDのままにする。
- [ ] 対象`tests.unit.test_operation_activation tests.integration.test_unattended_setup tests.unit.test_setup_onboarding tests.acceptance.test_setup_rerun_reconciliation`と全体を検証し、`feat: verify unattended operation during setup`でcommitする。

### Task 10: 障害注入・実OS/CLI検証・利用者文書

**Files:**

- Create: `tests/acceptance/test_reliable_automatic_accumulation.py`
- Create: `docs/unattended-operation.md`
- Modify: `README.md`、`docs/architecture.md`、`docs/certification-runbook.md`、`CHANGELOG.md`
- Modify: `.github/workflows/compatibility.yml`（R51: 既存の3 OS matrixへ障害注入テストを追加。Windows中心のci.ymlへ重複matrixを作らない）
- Modify: `tests/acceptance/test_package_metadata.py`（共有repo直下へbuild scratchを作らないfixture分離）
- Modify: `docs/specs/2026-09-18-reliable-automatic-accumulation-design.md`
- Modify: `docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`
- Modify: `tests/acceptance/test_release_contract.py` (R107: positive attestation fixture time is fixed to avoid wall-clock expiry; expiration behavior and the stale-negative case remain unchanged.)

**Additional Files（Task10 offline certifier notification isolation）:** `scripts/certify-public-clone.py`、`tests/acceptance/test_clean_clone_lifecycle.py`。fixtureが所有する一時runtime内だけ通知policyをsetup前にdisabledへ固定し、setup/update後もその値が変わらずfake senderが呼ばれないことを検証する。本体の通常setup既定値は変更しない。focused 2 testsとclean-clone lifecycle 18 testsはPASS。これはこの隔離境界だけの証拠であり、native/COM通知、全clean-clone gate、実AI/CLIは未検証。

**Interfaces:** 新APIを増やさない。Task 1〜9の公開API、既存release validation、既存certification receiptをconsumeする。新規実行証拠は機械ローカルに保存し、公開文書には秘密や固有パスを転記しない。

- [ ] 受入テストには少なくとも次のprivacy境界の実コードを置く。

```python
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ei.operation_activation import verify_operation
from tests.unattended_helpers import make_settings

class ReliableAutomaticAccumulationTests(unittest.TestCase):
    def test_unapproved_initial_test_never_calls_ai_or_notifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("AI used")):
                result = verify_operation(make_settings(Path(tmp)),
                    allow_model_test=False, allow_notification_test=False)
            self.assertEqual(result["automatic_operation"], "UNVERIFIED")
            self.assertEqual(result["notification_send"], "NOT_ATTEMPTED")
```

- [ ] `tests.acceptance.test_reliable_automatic_accumulation`と既存Task1〜9 testsの実行証拠を下表の観測単位で対応付ける。実エンジンAPIを一時rootとfake provider/notification boundaryで検証し、`input()`を通常処理中に禁止する。表の各IDは同じ観測を既にassertする既存named testまたは追加acceptance testである。変更候補での未実行・失敗はPASSに数えず、immutable final suite実行後に更新する。
- [ ] 以下のpublic coverage mappingをレビューし、各行の実観測・fake boundary・未解決点を維持する。Hookless sourceから次回recallまでのnamed acceptance caseは修正後にPASSした。表の既存Task1〜9 test IDsはimmutable combined suiteでの実行結果が揃うまでTask10全体の完了扱いにしない。

Source lifecycle RCA（修正済み）: failureは`/operations/0/payload/source_ref`へraw absolute locatorを渡し、既存persistable validatorが`ABSOLUTE_PATH_FORBIDDEN`で拒否する境界に限定された。別workerが承認範囲の`src/ei/curator.py`と`tests/unit/test_curator.py`のみを変更し、既存`domain_hash(ref, "source-ref")`によるidentity維持、既存event conversionのhash保持、privacy/changeset validator不変更を確認した。worker報告はcurator module 12/12とnamed hookless E2E 1/1 PASS。Task10のfresh acceptance moduleもこの修正を含むworktreeでPASSした。

| 必須matrix行 | 実行テストID（shipped source） | executable assertion / current evidence | 境界・未検証 |
| --- | --- | --- | --- |
| spool / queue / receipt interruption | [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_capture_ack_requires_durable_spool_queue_and_receipt`, `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_structured_recovery_ack_failure_keeps_cursor_uncommitted_until_retry`; [`test_pending_capture_recovery.py`](../../tests/integration/test_pending_capture_recovery.py): `tests.integration.test_pending_capture_recovery.PendingRecoveryTests.test_process_death_at_each_persistence_boundary_converges` | durable ACK前はSECURED/queueなし、ACK failureではcursor未commit。再開後は同一候補1件。各永続化境界でのsimulated power loss後も1 candidate IDへ収束。ACK新規case targeted 1/1 PASS。 | Temporary filesystem + injected exceptions/power-loss; no real OS power loss. |
| budget reservation / before-result / after-result interruption | [`test_budget.py`](../../tests/unit/test_budget.py): `tests.unit.test_budget.BudgetTests.test_process_exit_keeps_reservation_and_releases_os_lock`, `tests.unit.test_budget.BudgetTests.test_reservation_survives_restart_and_cannot_be_replayed`, `tests.unit.test_budget.BudgetTests.test_failure_and_unknown_usage_retain_reserved_capacity`; [`test_organizer_restart.py`](../../tests/integration/test_organizer_restart.py): `tests.integration.test_organizer_restart.OrganizerRestartTests.test_validated_result_survives_failure_without_second_inference`, `tests.integration.test_organizer_restart.OrganizerRestartTests.test_explicit_resume_retries_same_router_organizer_through_real_budget_ledger`; new [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_inference_before_result_persistence_failure_retains_budget_and_retry_cap` | The new actual maintainer→router→real ledger case injects failure after successful fake inference but before result persistence. No saved result is available; early retry is blocked by backoff; same selected `ollama` provider gets a second separately reserved attempt; both unknown-usage cost/token reservations remain charged; a third paid call is refused at the real candidate retry cap. Existing after-result case still proves reuse without another inference. | Fake provider and isolated real ledger; no live AI, cloud usage or billing. |
| journal / projection / before-completion | [`test_organizer_restart.py`](../../tests/integration/test_organizer_restart.py): `tests.integration.test_organizer_restart.OrganizerRestartTests.test_journal_commit_before_projection_replays_without_another_event`, `tests.integration.test_organizer_restart.OrganizerRestartTests.test_partial_operation_append_reuses_saved_changeset`; [`test_pending_capture_recovery.py`](../../tests/integration/test_pending_capture_recovery.py): `tests.integration.test_pending_capture_recovery.PendingRecoveryTests.test_done_cleanup_retries_after_each_interruption_at_day31_without_reinference`; new source-to-recall case in [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_hookless_candidates_link_maintenance_projection_and_next_recall_by_id` | Existing cases assert event replay without duplicate, saved changeset reuse and expiry cleanup recovery. New case joins source candidate hash → applied event → observation/provenance → active projected pattern ID → next search hit by that ID, without pre-seeding index. Fresh Task10 acceptance module after the approved source-reference fix: 11/11 PASS, including this full chain. | Fake provider; real structured adapter with temporary source. No real user/CLI recall. |
| quota / auth / local stop / malformed | [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_provider_failures_keep_one_candidate_and_distinguish_local_stop`; [`test_organizer_recovery.py`](../../tests/unit/test_organizer_recovery.py): `tests.unit.test_organizer_recovery.OrganizerRecoveryTests.test_timeout_has_bounded_retry_and_malformed_needs_action`, `tests.unit.test_organizer_recovery.OrganizerRecoveryTests.test_explicit_auth_retry_cannot_repeat_after_failure`, `tests.unit.test_organizer_recovery.OrganizerRecoveryTests.test_interrupted_resume_requires_a_new_explicit_request`; [`test_maintainer.py`](../../tests/unit/test_maintainer.py): `tests.unit.test_maintainer.MaintainerTests.test_malformed_response_retries_then_requires_attention`; [`test_queue.py`](../../tests/unit/test_queue.py): `tests.unit.test_queue.QueueTests.test_quota_transition_retains_spool_reference` | Reason-coded defer, bounded retry/action threshold, local stop without provider call, explicit auth permission consumed once (new request after failure/interruption), and retained encrypted spool reference/body for quota case. | Fake organizer/provider and isolated queue; no live provider or credential recovery. |
| missing source / key / full capacity / TTL | [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_missing_structured_source_and_unavailable_key_never_become_no`; [`test_capture_recovery.py`](../../tests/unit/test_capture_recovery.py): `tests.unit.test_capture_recovery.CaptureRecoveryTests.test_no_source_does_not_imply_covered`; [`test_pending_capture.py`](../../tests/unit/test_pending_capture.py): `tests.unit.test_pending_capture.PendingCaptureTests.test_full_capacity_has_no_success_receipt`, `tests.unit.test_pending_capture.PendingCaptureTests.test_key_unavailable_never_acknowledges_or_writes_body`, `tests.unit.test_pending_capture.PendingCaptureTests.test_ttl_is_terminal_and_cleanup_failure_is_retried` | Missing source stays UNKNOWN/no cursor commit; key and full capacity cannot produce SECURED; TTL is terminal and body is removed only after durable expiry receipt/cleanup confirmation. | Temporary source, in-memory key provider and controlled clock; no real OS keystore. |
| no Hook + structured source / no source | [`test_capture_recovery.py`](../../tests/unit/test_capture_recovery.py): `tests.unit.test_capture_recovery.CaptureRecoveryTests.test_hookless_candidate_is_secured_without_claiming_turn_coverage`, `tests.unit.test_capture_recovery.CaptureRecoveryTests.test_no_source_does_not_imply_covered`; source → maintenance → next recall acceptance is `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_hookless_candidates_link_maintenance_projection_and_next_recall_by_id` above | Existing cases assert real adapter candidate secured without turn coverage and absent source is not semantic NO. After the source-reference fix, the new candidate-to-applied-event/projection/next-recall case passes by joined IDs; candidate listing or search-only is not a substitute. | Temp structured adapter only; no real Hook/CLI. |
| concurrent Hosts / turns / closeout / same content in different scopes | [`test_capture.py`](../../tests/unit/test_capture.py): `tests.unit.test_capture.CaptureTests.test_skill_legacy_and_pending_share_limit_and_concurrent_last_slot`, `tests.unit.test_capture.CaptureTests.test_same_turn_and_claim_is_idempotent`, `tests.unit.test_capture.CaptureTests.test_fourth_observation_hits_session_limit`, `tests.unit.test_capture.CaptureTests.test_same_claim_in_different_scopes_creates_distinct_observations_and_receipts`; [`test_multi_host_lifecycle.py`](../../tests/integration/test_multi_host_lifecycle.py): `tests.integration.test_multi_host_lifecycle.MultiHostLifecycleTests.test_receipt_for_one_instance_does_not_verify_another_host`; [`test_skill_runtime_boundary.py`](../../tests/integration/test_skill_runtime_boundary.py): `tests.integration.test_skill_runtime_boundary.SkillRuntimeBoundaryTests.test_closeout_accepts_one_utf8_object_with_surrounding_whitespace` | Existing capture tests cover concurrent admission, same-turn replay, session cap, scope association and host receipt separation. The named closeout test only proves single-object CLI payload parsing. **Required multi-turn/session-to-closeout association is not implemented or covered:** `src/ei/cli.py::_closeout` accepts one candidate/gate decision, but no trusted capture identity, target-turn IDs, or closeout-to-capture association. This remains an implementation gap, not a PASS inferred from ordinary capture tests. | Temporary roots and simulated host identities; no real multi-CLI session. Session closeout cannot be truthfully acceptance-tested until its API/association is designed and implemented; no such feature was added in this test-only fix. |
| repeated incident / failed notification / recovery / other-source loss | [`test_incidents.py`](../../tests/unit/test_incidents.py): `tests.unit.test_incidents.IncidentTests.test_notification_boundaries_escalation_and_cli_session`, `tests.unit.test_incidents.IncidentTests.test_recovery_notifies_once_only_when_the_open_incident_was_notified`, `tests.unit.test_incidents.IncidentTests.test_retained_count_growth_is_quiet_but_new_source_identity_is_due`; [`test_unattended_operation.py`](../../tests/integration/test_unattended_operation.py): `tests.integration.test_unattended_operation.UnattendedOperationTests.test_invoked_unknown_delivery_retains_hour_throttle`, `tests.integration.test_unattended_operation.UnattendedOperationTests.test_missing_selected_source_does_not_block_other_source_and_only_same_source_resolves` | Controlled-time assertions cover 24h success cooldown, 1h failed/unknown send throttle, per-session CLI delivery, recovery notification generation, quiet repeated count and resolution only for the same recovered source. | Fake native sender and clock; no actual desktop display, focus mode, reboot or delivery visibility. |
| scheduler stop / explicit disable / sleep / both paths stopped | [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_scheduler_stop_requires_observed_missed_runs_and_disable_stays_disabled`; [`test_unattended_operation.py`](../../tests/integration/test_unattended_operation.py): `tests.integration.test_unattended_operation.UnattendedOperationTests.test_only_verified_scheduler_resumption_resolves_stop_and_not_provider_fault`, `tests.integration.test_unattended_operation.UnattendedOperationTests.test_explicit_disable_silences_old_stop_without_resolving_it`, `tests.integration.test_unattended_operation.UnattendedOperationTests.test_cli_status_is_read_only_and_never_probes_provider_or_notifies`, `tests.integration.test_unattended_operation.UnattendedOperationTests.test_next_cli_query_detects_two_native_misses_without_scheduler_or_custody_cache` | Unobserved/sleep and explicit disable do not become false stop; disable is not undone; only verified recovery resolves stop; status is read-only; both Hook and scheduler stopped is explicitly reported as not self-detecting until a later CLI query. | Fake scheduler/CLI state. Actual OS registration/execution and native stop monitoring unverified. |
| raw key / link substitution / instruction-like data | [`test_pending_capture.py`](../../tests/unit/test_pending_capture.py): `tests.unit.test_pending_capture.PendingCaptureTests.test_privacy_and_schema_rejection_write_no_body_or_queue`; [`test_capture_recovery.py`](../../tests/unit/test_capture_recovery.py): `tests.unit.test_capture_recovery.CaptureRecoveryTests.test_parent_link_is_rejected_before_content_read`; [`test_privacy_gate.py`](../../tests/integration/test_privacy_gate.py): `tests.integration.test_privacy_gate.PrivacyGateIntegrationTests.test_rejected_secret_has_no_event_path`; new [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_instruction_like_candidate_cannot_rewrite_roots_provider_or_notification_policy` | Secret/schema rejection creates no body/queue/event; symlink parent is rejected before bytes are read; adversarial-looking source text cannot change configured roots, organizer/provider order, defaults or disabled notification policy, and cannot invoke native send. New case targeted 1/1 PASS. | Fake provider sees structured candidate data; tests do not establish real-model resistance to prompt injection or OS notification behavior. |
| setup rerun / update / check-only | [`test_setup_rerun_reconciliation.py`](../../tests/acceptance/test_setup_rerun_reconciliation.py): `tests.acceptance.test_setup_rerun_reconciliation.SetupRerunReconciliationTests.test_identical_second_setup_changes_only_append_only_receipt`, `tests.acceptance.test_setup_rerun_reconciliation.SetupRerunReconciliationTests.test_team_member_change_keeps_store_identity_and_reports_continuity`, `tests.acceptance.test_setup_rerun_reconciliation.SetupRerunReconciliationTests.test_already_current_setup_reconciles_requested_scheduler`; [`test_fresh_pc_restore.py`](../../tests/acceptance/test_fresh_pc_restore.py): `tests.acceptance.test_fresh_pc_restore.FreshPcRestoreTests.test_update_preserves_knowledge_commit_digest_and_remote_fingerprint`; new [`test_reliable_automatic_accumulation.py`](../../tests/acceptance/test_reliable_automatic_accumulation.py): `tests.acceptance.test_reliable_automatic_accumulation.ReliableAutomaticAccumulationTests.test_update_preserves_preexisting_knowledge_and_explicit_disabled_settings`; [`test_setup_onboarding.py`](../../tests/unit/test_setup_onboarding.py): `tests.unit.test_setup_onboarding.SetupOnboardingTests.test_explicit_no_scheduler_is_retained_in_legacy_wizard`, `tests.unit.test_setup_onboarding.SetupOnboardingTests.test_check_only_suppresses_explicit_operation_verification_and_all_test_boundaries`; [`test_public_setup_journey.py`](../../tests/acceptance/test_public_setup_journey.py): `tests.acceptance.test_public_setup_journey.PublicSetupJourneyTests.test_check_only_then_apply_uses_only_four_cli_hosts` | Actual `update()` case retains remote fingerprint/mode, knowledge digest and commit identity; the new case retains preexisting knowledge and exact knowledge-manifest and disabled notification-policy bytes, plus explicit disabled sync/experiment/scheduler values. Existing check-only and public setup cases remain separately mapped. | Temporary setup roots; fake Windows notification helper, no native sender, model, scheduler registration or real installation/knowledge sync. |

- [x] 既存3-OS/Python matrixへacceptanceとpackage metadata moduleの明示実行stepを追加し、matrix重複は作らない。headless/fake backendは実通知表示の証明として扱わない。
- [x] package wheel/sdistはtemp source/outputからbuildする。元repoのallowlisted package-input digestとrepository-local build/dist/egg-info inventoryを前後比較し、artifact内のlocal path、wheel/sdistの存在・サイズ、ignore契約を維持する。package moduleは3 tests/6.166s PASS。最初のcombined runはfixture全体のhashが長時間化して中断（test failureではない）し、allowlisted inputsに絞ってrerunした。
- [ ] 実機検証を対応を宣言するOS/Host/versionごとに行う。synthetic workから次回recall、実scheduler実行、OS通知実表示、CLI直接表示の有無、通知拒否、集中モード、再起動後復旧を個別に記録する。新規setupの許可内で実施し、既存環境の認証破壊・生データ削除を障害注入に使わない。auth/source障害は隔離環境で再現する。
- [x] 実機・CIで検証できないOS/CLIを`UNVERIFIED`とし、全環境の完成を宣言しない。OS/CLI表示と送信APIを分離する5項目の利用者ガイドを追加した。個別matrix receiptや公開CI結果は未取得。
- [x] `docs/unattended-operation.md`に正常時無操作、保存済みknowledge/未整理spool/診断state、通知理由と対応、30日/容量/自動回復限界、対応Host/OSと証拠範囲を記載した。
- [x] README/CHANGELOG/設計statusを設計・実装・隔離テスト・実運用証拠で区別した。installed Skillの指示だけを根拠にしていない。
- [ ] 全新規対象テスト、既存全体、3 OSのCI結果、公開source監査を確認する。`docs: document verified unattended operation`で正確な変更ファイルだけcommitする。installed Skill更新・既存索引再生成・public export/pushは、実装レビュー完了後に範囲と未検証点を示して別の実行として扱う。

Task10 execution note: 最終逐次target `tests.acceptance.test_reliable_automatic_accumulation tests.acceptance.test_package_metadata` は10/10 PASS、21.164s。source auditは165 paths/0 violations。controllerがimmutable candidateに対するcomplete suiteを別途実行するまで全体合格・commit可能とは扱わない。直近のR106 local sequential 1,502-test runは約1,499.7秒で、既存25分CI budgetにsetup/build余裕を残しにくい。古い公開Windows jobsは13分/17分だったため、既存job timeoutを有限の35分へ広げた。今回の6 OS/Python公開CIは未実行。

Parallel offline notification isolation result: 2 focused tests PASS、`test_clean_clone_lifecycle` module 18/18 PASS・skip 0、source audit 165 paths/0 violations、scoped diffcheck clean。reportはfixture runtimeの通知disable境界だけを証明し、native/COM送信・全clone gate・実AI/CLIは未検証と記載する。

I2 residual acceptance update (2026-09-30): the final captured run of `tests.acceptance.test_reliable_automatic_accumulation` is 13/13 PASS in 40.853s (stdin closed; finite timeout). It includes exact before-result persistence failure/budget/backoff coverage and a real `update()` case retaining preexisting knowledge and explicit disabled state. Session closeout association remains NOT IMPLEMENTED / NOT VERIFIED: the current single-candidate `closeout` API has no trusted session/turn-target association. The initial module run's exit/stdout was not captured and is treated as outcome unknown; the bounded module was rerun once with captured output. The R107 release-contract fixture-time correction is documented above; the parent reports `test_release_contract` 17/17 PASS, with expiry semantics and its stale-negative case unchanged.

## 設計カバレッジ・自己レビュー

### R94: 最終レビューで確定した修正wave

Task9の安定化後、Task10の受入文書を確定する前に、DONE後の一時本文/予約の有界cleanup再試行と、承認済みの`resume-organizer`（同一整理AIの待機候補1件への一度限りの再試行許可）を実装する。認証成功の推定、定期有償probe、期限/予算/backoffの初期化はしない。明示disabledを守り、失敗/中断後に許可を再利用せず、実処理成功までincidentを解消しない。確認できないCLIの再ログイン自動検出は約束しない。

**Files（17）:** `src/ei/queue.py`、`src/ei/pending_capture.py`、`src/ei/maintainer.py`、`src/ei/organizer_recovery.py`、`src/ei/cli.py`。`tests/unit/test_queue.py`、`tests/unit/test_organizer_recovery.py`、`tests/unit/test_cli.py`、`tests/unit/test_inference_router.py`、`tests/unit/test_crypto.py`、`tests/unit/test_pending_capture.py`。`tests/integration/test_pending_capture_recovery.py`、`tests/integration/test_organizer_restart.py`、`tests/integration/test_hook_canary.py`、`tests/integration/test_maintenance.py`、`tests/integration/test_capture_fallback.py`、`tests/integration/test_emergency_spool_recovery.py`。

testのみの末尾import、所有temp外fixture、残deadline assertionの3指摘も同じwaveで処理する。正常時・crash時・削除失敗・期限後・再開成功/失敗・wrong provider・disabled・空queue・dry-run・budget拒否を実入口で確認し、対象テスト/監査/immutable全体テストとAstraの指摘単位再レビューをcommit条件にする。

| 設計節 | 実装Task | 完了に必要な証拠 |
| --- | --- | --- |
| 1〜2: 無操作、privacy、単一AI、既存保持 | 全Task、特に3/5/9/10 | 日常inputゼロ、privacy拒否、rerun互換 |
| 3〜4: 取得・ID・ACK・回収可能性 | 1〜4/8 | 追跡状態、前後逆順、ACK前crash、有界回収 |
| 5: 保持・TTL・再開 | 3/5 | 暗号化・容量・期限・journal/projection照合 |
| 6: 原因別再試行・予算 | 5 | 呼出し前予約、restart保持、Provider非切替 |
| 7: health・通知・scheduler検知 | 6〜8 | 純粋判定、送信結果、実表示、停止の独立検知 |
| 8: setup・証拠・互換 | 9 | check-only無変更、初回のみ確認、証拠の選択的失効 |
| 9〜11: 分割・合格・完成境界 | 10 | 全体テスト、OS/Host実証、未確認の明示 |

計画レビュー時には、Filesの存在/新規区分、後続TaskのAPI名・引数・戻り値の整合、秘密/固有パスの混入、相対リンクを確認する。実装時は各Taskのデータ型・返却codeをこの計画と合わせ、変更する場合は後続Taskとテストも同時更新する。

**引継ぎ時の状態:** 設計承認済み、実装計画作成。新機能のコード実装、利用環境への適用、commit/push、実OS/CLI検証はこの文書作成だけでは実施済みにならない。

**R98 検証範囲の承認:** Windows PowerShell 5.1の実行ポリシーに拒否される旧インストーラーの成功経路は、制限を変更せずUNVERIFIEDとして保留し、独立した修正・検証を継続する。環境によるskipは成功証拠に数えない。R96/R97の変更対象と二重のテスト隔離を維持し、実helperを許可する変更、ポリシー迂回、別ホストの結果による代替証明は行わない。wrapperの成功経路を再試行するには、外側PowerShellの起動条件と子プロセスの不活性な実行先・最終guardを両立する設計確認を先に行う。

**R99 wrapper試験の隔離:** 外側PowerShellの起動にだけ実SystemRootを使う。既存のテスト専用Python shimは許可済みargvと所有temp内のSystemRoot・不活性な実行先を検証し、子Python起動前にそのprivate値を渡す。外側環境はfinallyで復元し、入出力・終了コード・Pythonの隔離オプションを維持する。子の最終argv guardと不活性な実行先を独立に残す。不明argv・不正root・bootstrap失敗を拒否する回帰を先に確認する。同じ5.1ポリシー拒否となる既存setup/check-only/error経路も未検証として区別し、CLR・fixture・不明エラーはskipにしない。本番wrapper、実行ポリシー、許可範囲は変更しない。

**R100 テスト用実行先の対応付け:** 本体は.ps1をPython実行先として保存することを拒否するため、テスト専用shimに限り、受け取った--python-exeが当該shimと完全一致し1個だけであることを検証した後、その値だけを検証済み実Pythonへ対応付ける。元のwrapper引数、対応付け後の値、他の全引数が不変であることを別々に試験し、不明・重複・欠落は拒否する。二重隔離を維持し、本番変更や新規依存は追加しない。この証拠はテストアダプター経由の結合確認であり、引数の完全同一性や実5.1互換性の証明ではない。

**R101 安全対策の限定再開:** 承認に基づき、既存22ファイルに`tests/integration/test_scheduled_task_scripts.py`を追加し、修正対象を23ファイルとする。まずwrapper呼出し元を静的に再点検し、rollbackとscheduled-task試験に残った実行制限の迂回指定を除去する。共有テスト補助でrunとPopenの起動前に禁止指定を拒否し、下流をsentinelに置き換えた純粋テストで確認する。実プロセスで危険な指定を再現しない。静的点検・回帰結果の確認まではwrapper、呼出し元一括テスト、全体検証を再開しない。制限自体や本番の挙動は変更せず、未検証を成功扱いしない。

R101のguardは試験済みの分割argv形式用であり、Windowsの単一文字列commandや任意の難読化を防ぐ一般sandboxではない。呼出し元の静的点検・明示的なテスト隔離は引き続き必要。限定レビュー後のR102では、既存所有の`tests/unit/test_cli.py`と`tests/unit/test_scheduler_installer_production_defects.py`だけで、check-only準備1件とmocked systemd2件を診断する。本体の厳密な所有権検査を弱めず、wrapper・全体検証は別の再開判定まで保留する。
**R85 lock公開修正:** 完全な所有記録を排他的に公開する。公開先lockは従来どおりtokenと取得identity両方で解放を検証する。未公開の当該取得が自作した一意tempだけは、排他的openで保持するfdのfstatとno-follow path.statで同じregular-file identityを証明し、1回だけunlinkできる。descriptorは必ず閉じ、置換/link/確認不能は保持する。期限後の新しい予算・scan・一般cleanupは追加しない。短いwrite・途中失敗・公開競合・期限切れ・temp置換を試験する。

## 承認済みcloseout接続の追加実行書（2026-10-01）

設計12節の文書承認を受領した。Task 11 → 12 → 13を順次実施する。Task 1〜9の受理済みレビューを再実施しない。Task 10のcloseout不足と最終combined gateは、この追加が終わるまで未完了のままとする。

各TaskはLuna maxが実装し、Astraがその固定差分をレビューする。週間残量40%を割りそうなら停止して引継ぎを残す。各Taskの対象テスト後は未commitの固定snapshotでレビューできるが、commitは追加全体の対象テストとcomplete unittest suiteの成功後だけ。元checkout、installed Skill、実knowledge/runtime、OS設定、認証へ変更しない。模擬試験に実AIを使わない。

共通の追加制約: 明示対象は最大64、metadata recordは16KiB、未完了intentは64件/1MiB。capture namespace、session、work scopeの一致が必要。任意JSONや環境変数、自由なtarget CLI引数を制御metadataとして採用しない。生本文の追加保存方式・queue・整理AI・scheduler・通常の承認質問を作らない。runtime metadataは未知field拒否、safe_fs、共通OperationBudgetを使用する。旧receiptの意味を変えず、context不足はUNKNOWNとする。

### Task 11: Host由来のtarget bindingとcloseout context検証

**Files:**

- Create: `src/ei/closeout_context.py`
- Create: `schemas/closeout-target-binding.schema.json`
- Create: `tests/unit/test_closeout_context.py`
- Modify: `src/ei/hooks/base.py`、`src/ei/hook_entry.py`、`src/ei/journal.py`
- Modify: `tests/unit/test_capture_ledger.py`、`tests/integration/test_hook_canary.py`

**責務:** このTaskは出所・対象の検証だけ。changeset適用、spool、receiptのSECURED化、maintenanceを実装しない。既存HookのWAITING登録を維持し、十分なmetadataを提供する登録adapterに限って対象bindingを追加保存する。

**Interfaces（Task 12/13も同じ型をconsumeする）:**

```python
@dataclass(frozen=True)
class CloseoutScope:
    cwd_hash: str
    domain_hash: str
    # fingerprint property = ids.fingerprint of both hashes with
    # domain separator "ei-closeout-work-scope-v1".

@dataclass(frozen=True)
class CloseoutContext:
    identity: CaptureIdentity  # native closeout record; turn_hash=None
    target_ids: tuple[str, ...]
    scope: CloseoutScope

@dataclass(frozen=True)
class ContextValidation:
    context: CloseoutContext | None
    target_binding_digest: str | None
    reason_code: str
    # valid property iff context and digest exist and reason_code == "OK"

# closeout_context.py
def register_adapter_target(settings, event: NormalizedHookEvent, *, now: datetime,
                            budget: OperationBudget) -> bool: ...
def validate_adapter_context(settings, host_id: str, control: Mapping[str, Any], *,
                             budget: OperationBudget) -> ContextValidation: ...

# HookAdapter protocol and BaseHookAdapter, default unsupported.
supports_closeout_context: bool = False
def capture_work_scope(self, event: NormalizedHookEvent, spec: HostSpec) -> CloseoutScope | None: ...
def closeout_context(self, control: Mapping[str, Any], spec: HostSpec) -> CloseoutContext | None: ...
```

既存public adapterの能力はFalse、両methodはNone。protocol型だけを根拠に許可しない。ProfiledHookAdapterも既定Falseのまま、delegateの能力を暗黙継承させない。generic normalizerはpayloadのdomain/trusted/target_idsからscopeを生成しない。将来のadapterがnative契約からdomainを得るため、`NormalizedHookEvent`末尾にoptional `work_domain_hash: str | None = None`だけ追加してよい（generic正常化はNone）。scopeを返す登録adapterのコード自身が出所の境界であり、同一OSユーザーの悪意あるPythonコードを防ぐ機構ではない。

Hash互換契約: cwd_hashは既存Hookの完全SHA256と同じ`ids.fingerprint(native_cwd)`、domain_hashは`ids.fingerprint(native_domain)`。どちらも非空のnative文字列をそのままhash化し、trim/lower/default補完をしない。scope fingerprintは`ids.fingerprint({"domain": "ei-closeout-work-scope-v1", "cwd_hash": cwd_hash, "domain_hash": domain_hash})`。binding digestはsorted bindingのcapture_id/identity/scope_hashだけを使い、updated_atと将来のcloseout_proofsを除外する。Task12/13のevent照合もこの規則をconsumeする。

- [ ] RED: 既存make_hook_settingsとmanifest生成fixtureの構造を利用し、新規テスト内に一時root/real install manifestのinstalled_adapter_fixtureを定義する。以下のnamed casesを作り、未実装APIで失敗することを保存する。fake adapterだけをregistryの既存Hostスロットに限定patchし、namespace検証・ledger・safe_fsは実処理を通す。

```python
def test_explicit_two_targets_excludes_third_turn(self):
    settings, adapter, events = self.installed_adapter_fixture(turns=3)
    for event in events:
        handle_normalized_hook(event, settings, budget=OperationBudget(5000))
    result = validate_adapter_context(settings, adapter.host_id,
        adapter.control_for(events[:2]), budget=OperationBudget(5000))
    self.assertTrue(result.valid)
    self.assertEqual(result.context.target_ids,
        tuple(sorted(capture_key(e.capture_identity) for e in events[:2])))
    self.assertEqual(read_receipt(settings, capture_key(events[2].capture_identity)).state, "WAITING")
```

- [ ] 同じfixtureでmissing context/capability/domain/cwd、invalid hash、duplicate/empty/65 targets、unknown target、wrong Host/instance/store/session/scope、target binding corruption/extra field/link、manifest missing/changed、deadlineを試験する。欠けたdomainをcandidate等から補う経路は存在させない。既存WAITING/UNKNOWN/期限切れreceiptは再分類しない。
- [ ] GREEN: `closeout_context.py`で共通hash/型/最大件数検証を実装。bindingは`runtime/state/capture/target-bindings/<capture digest>.json`へ置く。schema version、capture ID、CaptureIdentity、scope fingerprint、updated_atだけを初期fieldとして許可し、追加digest欄はTask 12が後方互換に拡張する。1record16KiB以内で、raw domain/cwdは保存しない。未知field拒否はJSON schemaと`journal.validate_schema`の実validator双方で実施する。
- [ ] `register_adapter_target`はregistry.get_adapter(event.host_id, settings)と実HostSpecを取得し、登録adapterの能力・scope、`capture_namespace`、完全なsession/turn/record hash、capture_keyを照合する。既存`register_target`後、capture lockの下で当該receiptの存在とidentityを確認し、同一bindingの再送だけを許可。違うidentity/scopeの既存bindingを上書きしない。bindingなしの旧receiptを再実行時に候補から補完しない。
- [ ] Hook `turn.stop`で既存登録の直後に上記を呼ぶ。不足/未対応はFalseで従来のHook動作を継続し、失敗は既存fail-openの固定codeにする。保存失敗からSECURED/成功関連付けを出さない。binding登録はregistry経由の実call pathでテストし、testがJSONを手書きしただけの成功を作らない。
- [ ] `validate_adapter_context`は登録adapterのmethodを呼んだ結果だけを受け取る。identityは現在のnamespaceと一致し、session/record必須・turnはNone。target IDsは完全hash、重複なし、1〜64でsort。各bindingとreceiptをcapture lock内で読み、同namespace/session/work-scope、identityから再計算したcapture IDを照合する。digestはsorted bindingのsemantic fieldsから生成し、updated_atを除外する。UNKNOWN、expired receiptは成功にしない。通常の候補Mappingをこの入口へ流用する呼出しは禁止する。
- [ ] reason codes: 不足/未対応`CLOSEOUT_CONTEXT_UNVERIFIED`、不正な構造`CLOSEOUT_CONTEXT_INVALID`、namespace差`CLOSEOUT_NAMESPACE_MISMATCH`、scope/session差`CLOSEOUT_SCOPE_MISMATCH`、未知対象`CLOSEOUT_TARGET_UNKNOWN`、binding不整合`CLOSEOUT_TARGET_CONFLICT`。タイムアウトは既存TimeoutErrorを保持する。例外本文/パスをdiagnosticへ保存しない。
- [ ] Run: `python -B -X utf8 -m unittest tests.unit.test_closeout_context tests.unit.test_capture_ledger tests.integration.test_hook_canary`。stdin閉鎖・有限timeout、correct checkout import、safe fixtureのRED/GREEN証拠をreportへ残す。自己レビュー/差分check後に凍結し、commitせずTask-scoped Astra reviewへ渡す。

### Task 12A: 既存適用結果から元marker参照を渡す

**Files:** Modify `src/ei/changeset.py`, `tests/unit/test_changeset.py` のみ。public spec/planはcontroller所有。

**責務:** 既存applyが既に取得したmarkerから本文なしの参照を返す。参照は未検証のlocatorであり保存証明ではない。新しい索引、追加journal探索、provider、receipt、ファイル書込み経路を作らない。Task12/13はこの後に実施し、本taskだけでassociation完了を宣言しない。

**Interfaces:**

```python
@dataclass(frozen=True)
class AppliedMarkerRef:
    marker_id: str
    occurred_at: str
    changeset_hash: str

# ApplyResult末尾へ後方互換defaultで追加する。
application_ref: AppliedMarkerRef | None = None
```

参照のmarker_idは `^evt_changeset_[0-9a-f]{32}$`、hashは既存full SHA256形式、occurred_atは既存_timestampで検証できるtimezone付き値。参照はmarker実値をそのまま保持し、時刻正規化・入力changesetの新timestamp/hashによる置換をしない。invalid markerの参照生成はNoneとし、従来のApplyResult項目を変えない。公開型/適用成功/参照の存在だけでreceiptを成功化しない。

- [ ] RED: real apply/journalをtemporary rootで使用し、新規APPLIEDと同ID別日時ALREADY_APPLIEDから同じ元参照を得るテストを書く。新要求のfingerprintが元と違うこと、月を跨いでも参照が元partitionを指すことをassertする。

```python
first = apply_changeset(original, configured)
later = replace(original, generated_at="2026-09-01T00:00:00+00:00")
second = apply_changeset(later, configured)
self.assertNotEqual(original.fingerprint, later.fingerprint)
self.assertEqual(second.event_ids, ())
self.assertTrue(second.already_applied)
self.assertEqual(first.application_ref, second.application_ref)
self.assertEqual(second.application_ref.changeset_hash, original.fingerprint)
```

- [ ] GREEN: 既存_markerの戻り値を一度保持して参照を生成し、ALREADY_APPLIEDへ追加する。新規APPLIEDでは全append成功後の既存built markerから作る。失敗経路はNone。既存位置引数6個の互換性、ok/validation/reason/event_idsを維持する。参照だけのためにread/scanを増やさない。helperはchangeset.py内の小さいpure functionとする。
- [ ] 追加テスト: source operationは実CREATE_OBSERVATIONを含め、NO_CHANGEのみのprobeで代替しない。実保存markerと参照の3値一致、同時刻再送、different content/same IDでも参照を入力由来にすり替えない（厳密拒否はTask12検証側）、invalid/missing marker hash/time/IDはNone、schema/validation/append失敗はNone、旧位置引数constructorはNone、_eventsの呼出し回数を既存1回から増やさない。zero budget例外契約維持。
- [ ] Run: `python -B -X utf8 -m unittest tests.unit.test_changeset`。stdinDEVNULL、timeout180秒、worktree srcのimportを確認。RED/GREEN command/output、2file SHA256、自己reviewをreportへ記録。全体suite/commit/push/live環境変更はしない。独立Astra reviewへ渡す。

### Task 12: validated-resultの一度だけ保存と耐障害association

**実行状態（2026-10-05）:** Task12Aの元marker受け渡しとread-only検証処理は実装・限定レビュー済みで、既存applyが返すoptional AppliedMarkerRefをconsumeする。耐障害associationは未完了。利用者は、知識検索索引を増やさず、中断復旧用の本文なし未完了一覧（最大64件）だけを追加することを明示承認した。以下の有界intent index/cursorはこの一覧に限定し、changesetからmarkerへの新しい逆引き索引やjournal探索の索引は作らない。旧briefの「API不変更」や既に解消した承認待ちを再利用しない。Task13とcommit/public gateは依存task完了後。

**Files:**

- Create: `src/ei/closeout_association.py`、`src/ei/closeout_store.py`
- Create: `schemas/closeout-association.schema.json`
- Create: `tests/unit/test_closeout_association.py`、`tests/integration/test_closeout_recovery.py`
- Modify: `src/ei/closeout_context.py`、`schemas/closeout-target-binding.schema.json`
- Modify: `src/ei/changeset.py`、`src/ei/capture_contract.py`、`src/ei/capture_ledger.py`、`src/ei/journal.py`、`schemas/capture-receipt.schema.json`
- Modify: `tests/unit/test_changeset.py`、`tests/unit/test_capture_ledger.py`

**責務:** association moduleは適用/receipt/再開の状態機械、store moduleはruntime metadata・容量予約・index/cursor・safe I/Oだけを持つ。既存queue/curator/providerの動作を変更しない。

**Interfaces:** Task 11の`CloseoutContext`, `ContextValidation`, binding schemaをconsumeする。次のresult/builderはmodule内のdataclass/Protocolとして定義する。

```python
@dataclass(frozen=True)
class PreparedCloseout:
    candidate_id: str
    content_hash: str
    decision: str  # YES or explicit NO; never inferred from failure
    changeset: ChangeSet | None

@dataclass(frozen=True)
class AssociationResult:
    knowledge: str  # APPLIED / EVALUATED_NONE / NOT_APPLIED / UNKNOWN
    association: str  # COMMITTED / PENDING / REJECTED / UNKNOWN
    reason_code: str
    acknowledged: bool
    event_ids: tuple[str, ...] = ()
    changeset_hash: str | None = None  # verified YES proof; preserves existing team routing

# changeset.py: read-only proof, never an apply substitute.
def read_application_proof(changeset: ChangeSet, settings, *,
    application_ref: AppliedMarkerRef, budget=None) -> ApplyResult: ...
# closeout_association.py: prepare() uses the shared validated closeout path in Task 13.
def apply_associated_closeout(settings, validation: ContextValidation, *,
    content_hash: str, prepare: Callable[[], PreparedCloseout], now: datetime,
    budget: OperationBudget) -> AssociationResult: ...
def recover_closeout_associations(settings, *, now: datetime, budget: OperationBudget,
    max_records: int = 64) -> dict[str, Any]: ...
```

`prepare`は検証済み新規受付にだけ呼ぶ。既存cache/marker/COMMITTED再送では呼ばない。Task 13は意味的入力からcontent_hashを先に生成し、Task 12がtarget-set/content conflictを検出した後に初回prepareする。prepareの例外/DEFERRED等をNOへ変換しない。公開typed APIを直接呼んだことを認証としない。適用直前・再開時にもcurrent namespaceとpersisted binding digestを検証する。

成功YESのchangeset_hashは照合済みmarker/intentから返し、cache cleanup後のCOMMITTED replayでも同じ値を維持する。NO/未適用/未検証の結果ではNone。Task13は既存team routingへ元の構造化candidate、event_ids、このhashを渡せるために必要な結果fieldであり、再curationや本文metadata保存の理由にはしない。

- [ ] RED: `test_two_target_commit_requires_real_marker`、`test_explicit_no_has_durable_evaluation_proof`、`test_replay_calls_prepare_once`を一時rootで作る。Task 11の実adapter/binding経路を使い、curator/changeset/journal/receiptは実処理。最小確認コード:

```python
first = apply_associated_closeout(settings, validation, content_hash=digest,
    prepare=prepare_once, now=now, budget=OperationBudget(5000))
second = apply_associated_closeout(settings, validation, content_hash=digest,
    prepare=lambda: self.fail("replay prepared a second result"), now=later,
    budget=OperationBudget(5000))
self.assertEqual((first.knowledge, second.association), ("APPLIED", "COMMITTED"))
self.assertTrue(second.acknowledged)
self.assertTrue(second.event_ids)
```

- [ ] store実装: `runtime/state/closeout-associations/`配下でrecord identity由来の名前だけを使う。schemasにexact fields、version、status、namespace/scope hashes、target IDs/set hash/binding digest、content hash、固定original time/expiry、changeset id/hash・marker参照、SpoolRef、reasonを定義する。識別子/参照はschema検証し、パスを入力で指定できない。record≤16KiB、active intent≤64件かつ≤1MiB、index/cursorも有界とする。capture lock下でindexとreservationを照合し、不一致/破損/incomplete inventoryはUNKNOWNで保持、新規予約禁止。全directory scanをrepairの前提にしない。
- [ ] PREPARING→PREPARED: process generation/recordから決定するspool IDを先に予約する。初回の検証済みchangeset/NO、candidate ID/content hash、generated_atを既存`write_spool(..., purpose="validated-result", capture_id=closeout_capture_id, spool_id=planned_id, ...)`へ保存し、同じAADでread backしたSpoolRefをatomic保存する。既存key provider/retention/capacity/TTL/safe_fsを使用。新queue項目は作らない。PREPARING回収は予定spoolだけを照合し、存在する暗号文を上書き・二重課金しない。本文不在なら再送待ちPENDING。過去のcreated/expiryを再送で延長しない。
- [ ] YES適用前後: saved ChangeSetのschema/privacyを検証して`apply_changeset`を呼ぶ。lifecycle検証は同関数の既存順序を使い、既に適用済みの操作を現在状態へ再検証して誤拒否しない。Task12Aのapplication_refを既存intentへatomic保存してから`read_application_proof`へ渡す。元markerのoccurred_atをpartitionに使い、要求changesetのgenerated_atだけを一時的に置換してfingerprint一致を確認する。他のsemantic fieldの差は拒否する。元markerのID/hash、candidate id、operation count、全参照event IDsと実payload/Host/scopeを検証する。一般event history scan、任意path、空event_ids、参照の存在だけを証明にしない。event不在/partial append/hash差は非成功。ref永続化前のcrashだけは認証済みcacheの同じchangesetを既存applyへ再送してrefを回収でき、curatorは呼ばない。ref保存後は直接lookup。結果hashは元の実保存hashとする。cache/要求fingerprintを元値に書換えない。
- [ ] 完全検証後、receipt更新前に、要求hash/元hash/target binding digestと、実証した各eventのID・occurred_at・journal integrity digestだけのwitnessを既存intentへ保存する（本文なし、16KiB上限内）。cache喪失後の復旧はこの検証済みwitnessを現在のmarker・全event・bindingへ再照合する。単なるlocatorしかない状態では本文不在を成功へ変えずPENDING/喪失のまま保持する。要求changeset本文をmetadataへ平文複製しない。witness保存前後のcrashと、witnessあり/なしのcache喪失を別々に検証する。
- [ ] NO適用: sanitized評価完了proofを同じruntime metadata schema内でatomic保存して再読込する。decision、content hash、context/set/binding digestsだけで本文を含めない。privacy拒否や候補不在をNOにしない。
- [ ] receipt連結: 結果proof確定後、capture lock下でnamespace/bindingを再照合して各対象を冪等mergeする。YESはSECURED、NOはEVALUATED_NONE。ただし旧UNKNOWN/期限切れ/content conflictは維持しnoACK。各receiptの新規coverageは自分のtarget IDだけ。新optional `closeout_proofs`へrecord ID/set hash/content hash/binding digest/result digestを保存し、旧schemaは空tuple相当で互換。bindingにも同じ世代/digestを残す。異なるproofの上書き・無制限record肥大は拒否、16KiB超過でPENDINGにする。全receipt/bindingの再読込が完了するまでCOMMITTED/ACKを返さない。
- [ ] COMMITTED後は暗号文とactive reservationをcleanup可能。record IDで直接引ける本文なしのcompact committed witnessを同じmetadata protocolに残す（最小locator/digestsだけ、active inventory外）。それとreceipt/binding proofを突合し、target setが全て別IDになった再送も検出する。新しいqueueではない。既存証拠を欠く旧metadataからwitnessを捏造しない。cleanup failureはAPPLIEDを失敗適用へ戻さずPENDING診断を残す。
- [ ] recoveryはindex/cursorから最大64件、呼出し元の同じOperationBudgetで処理する。cursorは実際に確定した処理位置のみ進める。metadata破損やdeadline時に未処理を完了扱いにしない。cacheがなくても完全journal proofがあればmetadata完了を再開するため、markerの決定可能なlocatorと期待digestをintentへ残す。未適用cache喪失/期限切れは先に喪失状態を永続化して既存cleanupし、NoProvider/NOへの変換はしない。再開時のprepare/curator/provider呼出しゼロをassertする。
- [ ] 故障注入: reservation前後、spool write後/ref前、PREPARED後、event途中、marker後、receipt途中、COMMITTED直前、ACK直前。全てで再送/recovery後のjournal一重・providerゼロ・receipt未完了noACK・元の期限をassert。wrong content/set、same content different record、concurrency、capacity、expired/no cache、corrupt index/metadata、links/replacement、deadlineも対象。capture→spool→queue順を逆転させず、知識apply lock解放後だけreceipt lockを取る。
- [ ] Run: `python -B -X utf8 -m unittest tests.unit.test_closeout_context tests.unit.test_closeout_association tests.integration.test_closeout_recovery tests.unit.test_changeset tests.unit.test_capture_ledger`。stdin閉鎖/有限timeout。RED/GREEN・固定hash・自己レビューをreportへ残し、commitせずAstraへ渡す。

### Task 13: adapter・共通closeout・maintenanceの実接続と受入

**Files:**

- Create: `src/ei/closeout_service.py`
- Create: `tests/integration/test_adapter_closeout.py`
- Modify: `src/ei/hooks/registry.py`、`src/ei/cli.py`、`src/ei/maintainer.py`、`src/ei/operation_runtime.py`、`src/ei/operation_health.py`
- Task13統合回帰で必要となった親承認済みの限定delta: `src/ei/closeout_association.py`の初回record照合のみsemantic content不一致を`CLOSEOUT_CONTENT_CONFLICT`、target/binding不一致を`CLOSEOUT_TARGET_CONFLICT`に分ける。Task12 store/getter/recovery contractは変更しない。
- Modify: `tests/unit/test_cli.py`、`tests/unit/test_operation_health.py`、`tests/integration/test_maintenance.py`
- Modify: `tests/acceptance/test_reliable_automatic_accumulation.py`
- Modify: `docs/unattended-operation.md`、`docs/architecture.md`、`README.md`、`CHANGELOG.md`
- Modify: `docs/specs/2026-09-18-reliable-automatic-accumulation-design.md`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`

**Interfaces:** Task 11/12の公開APIをconsumeする。`closeout_service.py`へ既存CLIの処理を限定抽出し、重複gate/curator実装を作らない。

```python
@dataclass(frozen=True)
class CloseoutResult:
    payload: dict[str, Any]
    exit_code: int

def process_closeout(payload: Mapping[str, Any], settings, *,
    validation: ContextValidation | None = None, now: datetime | None = None,
    budget: OperationBudget | None = None) -> CloseoutResult: ...

# hooks/registry.py; this is an internal Host-adapter ingress, not a new CLI flag.
def run_adapter_closeout(host_id: str, control: Mapping[str, Any],
    payload: Mapping[str, Any], settings, *, now: datetime,
    budget: OperationBudget) -> CloseoutResult: ...
```

controlはnative Host連携の別引数、payloadは候補/評価。registry入口が`validate_adapter_context`を呼び、その結果とpayloadを共通serviceに渡す。candidate/Skill/gateからcontrolを組み立てる処理は作らない。登録adapterのメソッド呼出しから共通入口へ至る実経路を使い、架空の対応済みpublic Hostを追加しない。

- [ ] RED: `test_registered_adapter_closeout_applies_and_covers_only_explicit_turns`を一時root・登録fake adapterで作る。入力は既存形式のstructured YES/NO、ProviderRouter.generateとinputを例外sentinelに置く。real namespace、Hook binding、service、journal、receiptを通し、最初から最後の証拠を同じtestでassertする。

```python
result = run_adapter_closeout(host_id, control_for_two_turns, structured_yes,
    settings, now=now, budget=OperationBudget(10000))
self.assertEqual(result.payload["knowledge"], "APPLIED")
self.assertEqual(result.payload["association"]["status"], "COMMITTED")
self.assertTrue(result.payload["association"]["acknowledged"])
self.assertEqual(read_receipt(settings, unrelated_target).state, "WAITING")
```

- [ ] service抽出: 既存payload/gate validation、privacy、audit、curator、changeset validation/apply、team routing、exit codesを保持する。cli `_closeout`は入力を読みserviceを呼びemitする薄いwrapperとする。通常CLIの評価未指定時の既存Provider動作は保持。trusted入口は構造化評価がないなら`CLOSEOUT_EVALUATION_REQUIRED`でUNKNOWN/noACK、追加gate推論ゼロとする。機能のためのfresh Provider/curator再実行は作らない。
- [ ] 同じYES/NOのparse/validation結果を利用し、content hashはcandidate/gate/evidence/applicabilityの意味的値のみから作る。受信時刻/再試行counterは除外し、本文中のcontrol fieldsは認証に使わない。初回prepareだけ既存curatorでchangesetを生成してTask 12に渡す。replayはcached identity/generated_atを維持する。new routeのprivacy拒否NOは評価完了proofへ変換しない（legacyCLIの従来出力は互換維持）。
- [ ] 結果に`knowledge`と`association={status,reason_code,acknowledged}`を追加。missing/unsupported contextではassociation UNKNOWN/CLOSEOUT_CONTEXT_UNVERIFIED、legacy knowledge処理は従来どおり。verified contextでもDEFERRED/FAILED/privacy/no-changeはCOMMITTEDにならない。Skill scripts/closeout.pyの`changeset_ready`は変更せず、提案だけでreceiptを確保しないことを回帰試験する。
- [ ] maintenanceの既存pending/source回収・spool GCとの順を確認し、GC前に`recover_closeout_associations(..., now=moment, budget=budget, max_records=64)`をphaseとして1回呼ぶ。別deadlineを作らず、disabled選択を変更しない。失敗は固定診断codeで既存health/incidentへ渡し、新通知経路を作らない。`operation_health.py`の純粋な入力へ関連付け未完了/容量/期限/metadata不明を加え、既存通知disable/間隔制限を共有する。
- [ ] acceptanceは設計12.8の9群を実観測へ対応付ける。2turnのみ/別Host・instance・store・session・cwd・domain除外、本文からの偽装無効、replay/content conflict、全故障位置、YES/NO/deferred/failed/privacy/proposal別結果、capacity/期限/corruption/deadline/concurrency/link、setup/update保持、legacyCLI/Skillを網羅する。前Taskのnamed testで同じ観測済みなら引用して重複試験を増やさない。
- [ ] 文書はengine対応能力と実Host証拠を分ける。public adapterはnative coverage未対応、既存単一候補蓄積は不変、metadataがない対象はUNKNOWN。全CLI対応・完全な取りこぼし防止・実機合格と書かない。Task10の未実装ラベルは接続試験/レビュー後に初めて更新する。
- [ ] Run: `python -B -X utf8 -m unittest tests.integration.test_adapter_closeout tests.unit.test_cli tests.unit.test_operation_health tests.integration.test_maintenance tests.acceptance.test_reliable_automatic_accumulation`、Task 11/12 targets。stdin閉鎖、有限timeout、実AI/OS通知なし。AstraのTask reviewで両verdictを得た後、固定snapshotでcomplete suiteを1回通し、source hashが不変であることを確認する。既存private plan-contractも開発checkoutで実行する。
- [ ] 固定差分レビュー・全体テスト・source監査が成功したら、既存Task9/10変更と追加Task11〜13のFilesに列挙した実変更だけをstageし、署名付きcommit。既存public export/履歴監査/clean-clone certificateに従う公開branch更新だけを実施し、新SHAのCIを確認する。未取得の実OS/CLI証拠は別枠のまま。週間40%の停止条件は公開完了要求より優先する。

追加設計coverage: 12.1〜12.3→Task11/13、12.4→Task12/13、12.5〜12.6→Task12/13、12.7→全3Task、12.8→各Taskのnamed testsと最終combined gate。Task11はbinding/contextの単独合格、Task12はtransactionの単独合格、Task13は実接続の合格であり、前段合格だけで全体完成としない。

#### Task 13 local implementation record (2026-10-05)

Task13の所有source、test、documentation変更を実装した。Task13のcombined target run `python -B -X utf8 -m unittest tests.integration.test_adapter_closeout tests.unit.test_cli tests.unit.test_operation_health tests.integration.test_maintenance tests.acceptance.test_reliable_automatic_accumulation` はworktree importを確認したsubprocess（stdin=DEVNULL、timeout=600秒）で66 tests / 142.888秒 / `OK`。module別collection数はadapter closeout 2、CLI 36、health 11、maintenance 3、acceptance 14で、skipはない。新しいmaintenance境界test `test_recovery_traversal_complete_does_not_resolve_pending_rows` は単独で1 test / 0.190秒 / `OK`。既存module identity、ordinary CLI provider route、Skill proposal、trusted structured evaluation欠落の追加named testsも上記66件に含まれる。

Task11/12の指定targetを一度ずつ実行するcombined runは84 tests / 213.794秒 / `OK (skipped=1)`。module別collection数はcontext 13、association 16、recovery 12、changeset 26、capture ledger 17。実結果は83 PASS・1 SKIPで、changesetのsymlink partition testはWindows privilege依存skipであり、成功扱いしない。

TDD evidence: adapter integration REDは`registry.run_adapter_closeout`未実装による`AttributeError`。health REDは新closeout fieldを持たない`HealthInput`へのkeywordで`TypeError`。maintenance REDは期待した`closeout_recovery → spool_gc`に対して旧実装が`spool_gc`だけを記録した。各named regressionは実装後に上記combined runでGREEN。ordinary CLI provider互換testは最初のmockが無効なGateDecisionを発生させたため、形式に沿う失敗`ProviderResult`へ修正して単独GREENを確認後、combined runでもGREEN。

source audit `scripts/audit-production-source.py --repo . --json` は169 pathsをscanし`passed` / 0 violations。`git diff --check`はexit 0で、別scopeの`install.ps1` / `setup.ps1`についてLF→CRLFのwarningのみ。残るcontroller gateはTask13独立レビュー、complete suite、clean-clone/publication/commit。Task13 workerはstage/commitしていない。

この記録はfake registered adapter、一時root、real journal/receipt、および隔離fixturesの証拠に限る。public adapterのnative closeout metadata、実CLI/Host、実OS、通知画面、公開CI、全体suiteの証拠ではない。Task13 SDD reportと差分hash記録は別途作成する。

#### Task 13 I1: 共有判定の既存保存・復旧への接続（2026-10-06）

Spec: 12.9。利用者は既存保存処理の拡張を承認済み。I2（privacy拒否再送）は修正・独立レビュー済みで、再実装しない。

**Files:**
- Modify: `src/ei/closeout_service.py`、`src/ei/closeout_association.py`、`src/ei/team_routing.py`
- Modify: `src/ei/journal.py`、`schemas/closeout-association.schema.json`
- Modify: `src/ei/team_outbox.py`（必要な既存receiptの直接照合・引渡し結果検証だけ。新queue/indexは不可）
- Modify: `tests/integration/test_adapter_closeout.py`、`tests/integration/test_closeout_recovery.py`、`tests/unit/test_closeout_association.py`、`tests/unit/test_team_routing.py`、`tests/unit/test_team_outbox.py`
- Modify: `docs/specs/2026-09-18-reliable-automatic-accumulation-design.md`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`（controller所有）

- [ ] team有効の実adapter integrationで再送時Provider再実行/hash変化をREDにする。
- [ ] `PreparedCloseout`と既存validated-result codecへ後方互換の共有判定を追加し、初回prepareでのみ判定。既存team routingを判定と耐久引渡しへ限定分離し、legacy経路は従来どおり接続する。
- [ ] 個人の実marker/event検証後、保存済み判定を用いて既存team event/outboxへ冪等引渡しする。本文なしの共有結果を既存associationに保存し、完了するまでspool/active予約をcleanupしない。recoveryにも同じ関数を使い、追加Provider呼出しをしない。
- [ ] 元の実hash/event IDs、確定対象外、保存前後の中断、outbox、破損/期限/設定先変更、legacy/team無効/I2互換を実journal/spool/receiptで検証する。外部Providerのみfake、手作り成功markerやprivacy緩和を使わない。
- [ ] 変更した対象moduleを有限時間・stdin閉鎖で実行しsource audit/diffcheck後freeze。同じAstraがI1とfix差分をレビューする。新規の全体レビューを重ねず、既存の最終PhaseBへ接続する。
- [ ] 固定版complete suite、公開gate、commit/pushは従来のcontroller最終工程を維持する。

#### Final PhaseB: closeoutと状態通知の接続修正（2026-10-06）

既存の期限切れ回収・個人適用証拠の設計は維持する。最終レビューで確認された2件の接続不具合だけを修正し、全体レビューを最初から繰り返さない。

**Files:** `src/ei/operation_runtime.py`、`src/ei/maintainer.py`、`src/ei/operation_health.py`、`src/ei/incidents.py`、`src/ei/notifications/base.py`、`tests/unit/test_operation_health.py`、`tests/integration/test_maintenance.py`、`tests/integration/test_unattended_operation.py`、`tests/unit/test_incidents.py`、`tests/unit/test_notifications.py`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`。incident/通知consumerは必要な接続修正のみ。

- [ ] 終了済みのLOST記録がactive一覧から外れても、その喪失結果を既存health/incidentへ渡し、後続の正常heartbeatや空recoveryで未解決の喪失を復旧扱いにしない。新しい索引、本文保持延長、AI再実行は追加しない。
- [ ] closeoutメタデータ件数を保管済み候補件数に流用しない。保管を検証していないcloseout通知は件数UNKNOWNとし、通常pendingの確認済み件数と容量・期限検知を維持する。
- [ ] 実cleanup→snapshot→incident/rendererの接続で、期限喪失後と次回maintenanceの誤復旧防止、本文なし予約・個人適用済みteam待ち・metadata不明の誤保管件数防止を検証する。通知disable/throttleは維持する。
- [ ] 変更moduleの有限実行、source監査、固定差分のfinding-only再レビュー後、新しい固定版でcomplete suiteと既存公開gateへ進む。修正前candidateの中断suiteを成功扱いしない。

同じB-I1の中断境界修正: `src/ei/closeout_association.py`のLOST cleanupで、既存incidentへ喪失を耐久保存する前に最後のactive復旧参照を解放しない。期限切れ本文の削除・元TTL・個人proofは維持し、incident保存失敗時も既存の有界参照から再試行する。追加の所有対象はこの接続点と`tests/integration/test_closeout_recovery.py`だけ。cache書込み失敗、handoff/active解放境界の中断、次回fresh runでの再配送を既存実fixtureで検証する。通知送信は既存同意・頻度制限から分離しない。新しい索引や保存形式は追加しない。

#### 最終gate: 既存R55の取り込み復旧進捗の修正

全件テストで既定500msの反復進捗と20候補の有界復旧に失敗した。既定予算・期待件数・安全境界を変更せず、計測で特定したファイル確認と既存catalog処理の重複だけを限定修正する。**Files:** `src/ei/safe_fs.py`、`src/ei/runtime_catalog.py`、`tests/unit/test_safe_fs.py`、`tests/unit/test_runtime_catalog.py`、`tests/integration/test_reparse_safety.py`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`。`tests/unit/test_capture_recovery.py`の既存失敗テストは変更せず検証に使用する。確認結果のcache、新しい索引、権限・reparse検査や変更前の再検証の省略、処理予算増量は行わない。安全に同等の小さな修正が成立しなければ、広い再設計へ進まず未解決として報告する。

#### 先行運用向け判定更新: 復旧の既定時間と実際の保存結果

先行運用では致命的な不具合を先に解消し、短時間性能などは後続改善とする。上記R55の500ms固定性能条件と最終gateの重複probe最適化方針は、本項で置き換える。実運用のmaintenanceは既に自身の残り時間を明示しており、500msの単体API既定値を使用していない。安全確認の削減や新たな保存機構は追加しない。

**Files:** `src/ei/capture_recovery.py`、`tests/unit/test_capture_recovery.py`、`docs/unattended-operation.md`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`。直前の未解決な実験差分だけを`src/ei/safe_fs.py`と`tests/unit/test_safe_fs.py`から除き、既存の検証済み処理へ戻す。

- 単体`recover_page`の既定時間を候補保存APIと同じ5000msへ合わせる。明示された`max_ms`、呼出し元deadline、件数・容量上限は維持し、新しい猶予時間を加えない。省略時の待機時間が最大約5秒になる点を文書化する。
- 既定時間で実保存が進むこと、短い明示時間・親deadlineで未完了をACKしないことを検証する。0.5秒での前進を一般保証しない。
- `max_records`は上限であり保証処理件数ではない。frontier再開テストは各回の上限と単調な保存進捗を保ち、最大20回の有界再開で20件すべての一意queueとSECURED receiptを検証する。期待件数の削減、skip、時間切れの成功扱いはしない。
- 修正差分レビュー、既存の全体テストと公開時の情報漏えい検査を通して公開branchを更新する。実Host/OS認定や性能最適化の未完了を先行運用の合格と混同しない。
- 先行運用の公開工程は、固定版の全体テスト、決定的な公開用抽出、抽出内容と検証済みtreeの一致、公開tree/履歴の情報漏えい検査、同じ公開SHAに対する既存CI（全体テスト・OS別clean-clone検証）を条件とする。抽出ツールのローカル全工程認定を省略した場合、そのreceiptは`exported_unvalidated`のまま保持し、正式なexport certificateや`PUBLIC_RELEASE_READY`を取得したと表示しない。実Host証拠と正式認定は別途残す。

#### 公開CIで検出された依存脆弱性の修正

**Files:** `requirements-ci.lock`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`。

CI用の間接依存`urllib3`だけを2.7.0から修正版2.8.0へ更新し、公式配布物のSHA256を検証する。runtime/build依存、scanner設定、権限、実インストール環境は変更しない。隔離環境でhash付きインストール、依存整合性・脆弱性検査、対象テストを実施し、差分レビューと固定版全体テスト後に既存公開branchへ反映する。

公開CIで判明したOS鍵ストア依存の試験fixtureも隔離する。**Files:** `tests/unit/test_closeout_context.py`、`tests/unit/test_maintainer.py`。既存`InMemoryKeyProvider`をテストの寿命に限定して明示し、暗号化・spool・journal・復旧・証拠照合の実処理と既存assertionは維持する。製品のOS鍵ストア選択や鍵が利用不能な場合の動作は変更しない。実OS依存がなくても既存試験が通ることを対象moduleで確認する。

**追加Files:** `tests/integration/test_unattended_setup.py`。Windows通知helperのfake-process試験がPOSIXにもWindows専用`creationflags`を要求していたため、Windowsでは`CREATE_NO_WINDOW`、POSIXでは0という既存製品契約に期待値を合わせる。shell無効、固定argv、ExecutionPolicy非変更の検査は維持する。

#### 公開Windows CI: 短縮パスと試験起動境界

**Files:** `src/ei/capture_recovery.py`、`tests/integration/test_capture_catchup.py`、`tests/unit/test_codex_memory_adapter.py`、`tests/unit/test_closeout_context.py`、`tests/unit/test_index.py`、`tests/integration/test_git_sync.py`、`tests/integration/test_multi_host_lifecycle.py`、`tests/integration/test_unattended_setup.py`、`tests/support/sitecustomize.py`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`。

同一取得元がWindows短縮パスと通常パスで別の保存経路になる不具合を修正する。元の字句パスのno-follow・containment検証を先に維持し、安全に検証した取得元identityだけを通常ingestと統一する。読取り前後のファイル同一性、本文hash、上限、deadline、既存plan/binding照合は緩めない。実aliasで両順序・中断再開の二重保存防止を回帰検証する。共通safe_fsの契約変更、新しい索引、既存履歴の書換えは行わない。

パス正規化時も元の字句パスを保持し、no-follow検証前後のfilesystem identityと正規化先の同一性を照合する。検証と正規化の間でjunction等へ差し替えられた場合は取得を拒否する。`tests/unit/test_capture_recovery.py`で実際の参照先差し替えを再現し、範囲外本文の保存・queue作成・cursorの成功更新がないことを検証する。

互換境界: `source-records` / `source-bindings`は今回の未マージ試験版で初めて導入され、前回公開コミットには存在しない。従来のナレッジ・イベントの互換性は維持する。一方、修正前の未マージ試験版が既に作った短縮パス由来メタデータの自動移行は今回追加せず、別Issueとして追跡する。既存runtimeや保留候補を削除して回避してはならない。

試験fixtureのmanifest、故障注入条件、相対パス計算、private recovery引数も正規化済みパスで統一する。故障注入が実際に発火したことを確認する。PowerShell 5.1で失われるテストshim内のPython引用符だけを修正し、通常の引数転送で検証する。ExecutionPolicy変更・回避、実インストール設定やOS鍵ストアへの変更は行わない。

**追加Files:** `tests/unit/test_capture.py`、`tests/unit/test_pending_capture.py`、`tests/unit/test_capture_recovery.py`。slot・scope分離・破損replay・削除frontierという機能試験の、成功が前提となる初回fixture作成だけに明示20秒の有限予算を渡し、結果の理由コードを含めて検証する。Windows CI失敗の時間切れ原因は未確定であり、この変更を性能修正とは呼ばない。製品既定値、共通test helper、後段の不正replay・件数・receipt・明示deadline検証は変更せず、失敗のretry/skip/黙殺は追加しない。

#### Windows専用wrapper試験の適用OS

**Files:** `tests/integration/test_unattended_setup.py`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`。

Windows batchのfake Pythonと`git.exe`を前提とするPowerShell wrapperの引数・終了値試験は、既存の同種試験と同じWindows限定にする。PowerShellの有無だけでLinux/macOSへWindows fixtureを適用しない。一般のPOSIXセットアップ試験や製品実装・安全検査は変更せず、Windowsでは元の引数転送と終了値の検証を引き続き実行する。

#### 公開Windows CI: 機能fixtureのbudgetとfault injection

**Files:** `tests/unit/test_capture_recovery.py`、`tests/unit/test_gate.py`、`tests/integration/test_one_shot_local_setup.py`、`tests/integration/test_organizer_restart.py`、`docs/plans/2026-09-18-reliable-automatic-accumulation-implementation.md`。検証報告: `.superpowers/sdd/2026-09-18-reliable-automatic-accumulation-implementation/ci-windows-functional-budget-report.md`。

Windows CIの失敗を機能回帰と時間切れ・故障注入不成立に分けて検証する。frontier permission-error試験は、実8.3 TEMP（repo外）のcanonical targetを比較し、faultが実際に発火したことを確認する。one-shotの機能試験はrun_maintenanceの既定30秒、gate YESは明示30秒の共有OperationBudget、organizerの初回/再開は同じ30秒の試験budgetを用い、結果とprovider呼出数を失敗時に表示する。元のstatus・receipt・retry・件数assertionは維持する。これらは機能試験の時間依存を避ける限定fixture変更であり、製品budget・timeout挙動やstandalone 5秒経路を修正したとの主張はしない。organizer CI失敗の期限原因は証拠不足で未確定のまま記録する。
