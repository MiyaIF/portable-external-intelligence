# Single Intelligence Multi-CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 1つの外部知能を複数CLIから安全に共有し、整理AIを1つだけ選択し、作業・記憶取得CLIを1つ以上選択できるセットアップと実行契約を実装する。

**Architecture:** 既存のappend-only event、queue、personal/team knowledge、host別hook所有権を維持する。manifest schema v8を機械ローカルの唯一の選択状態とし、`organizer`、`work_hosts`、host profileを保持する。hookで取得元hostとhost familyを記録し、候補確定前に適用範囲を正規化し、retrievalではスコア計算前に除外する。整理処理は選択済みproviderを1つだけ呼び、利用不能時も自動フォールバックや候補破棄を行わない。

**Tech Stack:** Python 3.11+、標準ライブラリ、JSON Schema、`unittest`、PowerShell/Bashセットアップラッパー

**Spec:** `docs/specs/2026-09-08-single-intelligence-multi-cli-design.md`

## Global Constraints

- 公開リポジトリには公開済みCLI名と、明示的に架空と分かるテスト用ID `test-compatible-cli` だけを置く。実在する非公開CLI名、実行コマンド、ユーザー固有パス、検出結果は置かない。
- 個人ナレッジ、チームナレッジ、event、patternをsetup/update/uninstallで削除または初期化しない。
- 既存のpersonal/team knowledge統合順序は変えず、host applicabilityの判定だけを候補スコアリング前に追加する。
- custom profileは機械ローカルのruntimeにだけ複製し、manifestには元ファイルの絶対パスや実行時検出結果を保存しない。
- 整理AIは常に0または1件とする。0件は移行直後の`SELECTION_REQUIRED`だけに許容し、整理処理を`DEFERRED`にする。自動的に別providerへ切り替えない。
- 旧manifestと旧patternは読めるようにするが、旧データを一括再書込みしない。append-only eventを維持する。
- 各タスクで先に失敗テストを追加し、対象テストを通した後、complete unittest suiteを通してから、そのタスクの列挙ファイルだけをstageする。
- 実装中にこの計画と仕様の意味変更が必要になった場合は実装を止め、仕様変更の承認を得る。

---

### Task 1: manifest v8と単一整理AI・複数作業CLIの設定契約

**Files:**

- Create: `src/ei/setup_contract.py`
- Modify: `src/ei/install_manifest.py`
- Modify: `schemas/install-manifest.schema.json`
- Modify: `src/ei/config.py`
- Modify: `src/ei/installer.py`
- Modify: `src/ei/cli.py`
- Modify: `tests/unit/test_install_manifest.py`
- Modify: `tests/unit/test_config.py`
- Modify: `tests/unit/test_cli.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class OrganizerSelection:
    status: Literal["READY", "SELECTION_REQUIRED"]
    provider_id: str | None
    host_id: str | None
    reason_code: str | None = None

def resolve_organizer(
    provider_id: str | None,
    host_id: str | None,
    work_hosts: Sequence[str],
    configured_provider_ids: Collection[str],
) -> OrganizerSelection: ...

def migrate_legacy_organizer(
    providers: Sequence[str],
    work_hosts: Sequence[str],
) -> OrganizerSelection: ...
```

`Settings`へ`organizer: OrganizerSelection`を追加する。`SetupSelection`へ`work_hosts`、`organizer_provider`、`organizer_host`を追加し、既存`hosts`は同値の後方互換alias、既存`providers`はv7移行入力だけにする。

`install-manifest.json` v8へ追加する選択fieldは次とする。既存の完全なhost所有権recordは`hosts`に維持する。

```json
{
  "schema_version": 8,
  "organizer": {
    "status": "READY",
    "provider_id": "subscription-cli",
    "host_id": "gemini-cli",
    "reason_code": null
  },
  "work_hosts": ["codex-cli", "gemini-cli"]
}
```

`work_hosts`の集合は`hosts`のkey集合の部分集合とする。差分に置けるのは`subscription-cli`の`organizer.host_id` 1件だけとする。整理専用hostを区別するため、manifestの`hosts`は全管理対象、`work_hosts`は取得・作業対象だけを表す。

- [ ] `tests/unit/test_install_manifest.py`へv8、v7曖昧移行、v7一意移行の失敗テストを追加する。

```python
def test_v7_multiple_providers_migrate_without_choosing_first(self):
    manifest = valid_v7_manifest()
    manifest["providers"] = ["ollama", "subscription-cli"]
    migrated = normalize_install_manifest(manifest)
    self.assertEqual(migrated["schema_version"], 8)
    self.assertEqual(
        migrated["organizer"],
        {
            "status": "SELECTION_REQUIRED",
            "provider_id": None,
            "host_id": None,
            "reason_code": "ORGANIZER_SELECTION_REQUIRED",
        },
    )

def test_v7_single_subscription_and_single_host_migrate_deterministically(self):
    manifest = valid_v7_manifest(host_ids=("gemini-cli",))
    manifest["providers"] = ["subscription-cli"]
    migrated = normalize_install_manifest(manifest)
    self.assertEqual(migrated["organizer"]["host_id"], "gemini-cli")
```

- [ ] 失敗を確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_install_manifest tests.unit.test_config tests.unit.test_cli`

Expected: v8未対応または`organizer`未定義でFAIL。

- [ ] `src/ei/setup_contract.py`にstrictな選択・移行関数を実装する。

実装規則:

- `READY`はproviderが設定済み一覧に存在するときだけ返す。
- `subscription-cli`はhost必須、それ以外はhostを`None`に正規化する。
- providerが複数、subscription hostが複数、または情報不足なら、先頭を選ばず`SELECTION_REQUIRED`を返す。
- host/provider IDは既存のsafe ID規則に従い、raw commandは受け取らない。

- [ ] `src/ei/install_manifest.py`とJSON Schemaをv8へ上げ、v6→v7→v8およびv7→v8を明示的に正規化する。

- [ ] `src/ei/config.py`でv8の`organizer`を読み、manifestがない初回だけrepository defaultsから`SELECTION_REQUIRED`を作る。`provider_order`は設定ファイル互換のため残すが、実行時選択には使わない。

- [ ] `src/ei/installer.py`のdesired state、plan、manifest生成、update復元を`organizer`と`work_hosts`へ切り替える。

- [ ] `src/ei/cli.py`とinstaller parserへ次を追加する。

```text
--organizer-provider PROVIDER_ID
--organizer-host HOST_ID
--work-host HOST_ID          repeatable
--hosts HOST_ID              deprecated alias of --work-host
```

非対話setupは`--organizer-provider`と1件以上の`--work-host`を必須にする。`--providers`は旧manifest/旧自動化の入力として受理するが、複数値ならエラーまたは`SELECTION_REQUIRED`とし、先頭を採用しない。

- [ ] 対象テストを再実行し、PASSを確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_install_manifest tests.unit.test_config tests.unit.test_cli`

- [ ] complete unittest suiteを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json`

Expected: failed 0。

- [ ] Task 1のファイルだけをcommitする。

```powershell
git add src/ei/setup_contract.py src/ei/install_manifest.py schemas/install-manifest.schema.json src/ei/config.py src/ei/installer.py src/ei/cli.py tests/unit/test_install_manifest.py tests/unit/test_config.py tests/unit/test_cli.py
git commit -m "feat: add single organizer setup contract"
```

---

### Task 2: 機械ローカルhost profileと互換adapter再利用

**Files:**

- Create: `src/ei/host_profiles.py`
- Create: `schemas/host-profile.schema.json`
- Modify: `config/hosts.json`
- Modify: `src/ei/config.py`
- Modify: `src/ei/installer.py`
- Modify: `src/ei/hooks/base.py`
- Modify: `src/ei/hooks/registry.py`
- Modify: `src/ei/inference/router.py`
- Create: `tests/unit/test_host_profiles.py`
- Create: `tests/compatibility/test_profiled_hooks.py`
- Modify: `tests/compatibility/test_all_host_contracts.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class HostProfile:
    schema_version: int
    host_id: str
    display_name: str
    host_family: str
    adapter_id: str
    executable_names: tuple[str, ...]
    hook_config_path: Path
    global_context_path: Path
    skill_roots: tuple[Path, ...]

def build_host_profile(data: Mapping[str, Any], host_home: Path) -> HostProfile: ...
def load_host_profile(path: Path, host_home: Path) -> HostProfile: ...
def install_host_profiles(
    profile_paths: Sequence[Path], runtime_root: Path
) -> Mapping[str, HostProfile]: ...
def load_installed_host_profiles(runtime_root: Path) -> Mapping[str, HostProfile]: ...
```

`HostSpec`へ`host_family`、`adapter_id`、`profile_hash`を追加する。組込みhostの`adapter_id`は自身の公開host ID、`host_family`は`codex-compatible`、`claude-compatible`、`gemini-compatible`、`qwen-compatible`の対応値とする。

host profile schemaのfieldは次だけを許可する。

```json
{
  "schema_version": 1,
  "host_id": "test-compatible-cli",
  "display_name": "Test Compatible CLI",
  "host_family": "gemini-compatible",
  "adapter_id": "gemini-cli",
  "executable_names": ["test-compatible"],
  "hook_config_path": ".config/test-compatible/settings.json",
  "global_context_path": ".config/test-compatible/context.md",
  "skill_roots": [".config/test-compatible/skills"]
}
```

- [ ] profile受理・拒否・runtime複製の失敗テストを追加する。

```python
def test_profile_reuses_public_adapter_without_changing_host_identity(self):
    profile = load_host_profile(self.profile_path, self.host_home)
    self.assertEqual(profile.host_id, "test-compatible-cli")
    self.assertEqual(profile.host_family, "gemini-compatible")
    self.assertEqual(profile.adapter_id, "gemini-cli")

def test_profile_rejects_command_and_parent_traversal_fields(self):
    document = valid_profile()
    document["command"] = ["powershell", "-Command", "Write-Output unsafe"]
    with self.assertRaisesRegex(ValueError, "HOST_PROFILE_INVALID"):
        write_and_load(document)
    document = valid_profile()
    document["hook_config_path"] = "../outside/settings.json"
    with self.assertRaisesRegex(ValueError, "HOST_PROFILE_PATH_INVALID"):
        write_and_load(document)
```

- [ ] 失敗を確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_host_profiles tests.compatibility.test_profiled_hooks tests.compatibility.test_all_host_contracts`

Expected: module未作成またはcustom host拒否でFAIL。

- [ ] `host_profiles.py`を実装し、exact-key validation、safe ID、relative path、`..`禁止、adapter allowlistを適用する。

実装規則:

- `adapter_id`は組込み公開host ID、`host_family`は対応する4つの公開family IDだけを許可する。
- executableは名前だけを許可し、separator、shell metacharacter、追加引数を拒否する。
- profile原本は読取専用入力とし、正規化JSONを`runtime_root/host-profiles/{host_id}.json`へatomic writeする。
- manifestにはprofile hashとruntime相対位置だけを記録し、原本の絶対パスを記録しない。
- `--host-profile`はrepeatable、custom hostには`--host-home test-compatible-cli=.runtime-fixtures/test-compatible-cli`のようにhost homeを必須とする。

- [ ] `hooks/registry.py`に`ProfiledHookAdapter`を追加する。encode/parse仕様は`adapter_id`へ委譲するが、生成event、hook command、receipt、idempotencyにはprofileの`host_id`を使う。

```python
class ProfiledHookAdapter(BaseHookAdapter):
    def __init__(self, host_id: str, host_family: str, delegate: BaseHookAdapter): ...

    def normalize(self, payload: Mapping[str, Any]) -> NormalizedHookEvent:
        normalized = self.delegate.normalize(payload)
        return replace(
            normalized,
            host_id=self.host_id,
            source_host_id=self.host_id,
            source_host_family=self.host_family,
        )
```

- [ ] `hooks/base.py`の固定host allowlistを、`expected_host_id`との完全一致とsafe ID検証へ置換する。expected IDなしで任意custom IDを受理しない。

- [ ] `inference/router.py`でcustom organizer hostのtransportを`adapter_id`から決め、実行ファイルだけをcustom profileから解決する。profileにprovider引数を持たせない。

- [ ] custom hookの実eventとreceiptが`test-compatible-cli`、payload解釈が`gemini-cli` adapter準拠になるテストを通す。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_host_profiles tests.compatibility.test_profiled_hooks tests.compatibility.test_all_host_contracts`

- [ ] complete unittest suiteを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json`

Expected: failed 0。

- [ ] Task 2のファイルだけをcommitする。

```powershell
git add src/ei/host_profiles.py schemas/host-profile.schema.json config/hosts.json src/ei/config.py src/ei/installer.py src/ei/hooks/base.py src/ei/hooks/registry.py src/ei/inference/router.py tests/unit/test_host_profiles.py tests/compatibility/test_profiled_hooks.py tests/compatibility/test_all_host_contracts.py
git commit -m "feat: support local compatible CLI profiles"
```

---

### Task 3: 取得元hostと適用範囲をeventからpatternまで保持

**Files:**

- Modify: `src/ei/hooks/base.py`
- Modify: `schemas/hook-event.schema.json`
- Modify: `src/ei/models.py`
- Modify: `src/ei/persistable_fields.py`
- Modify: `src/ei/queue.py`
- Modify: `schemas/queue-item.schema.json`
- Modify: `src/ei/ingest.py`
- Modify: `src/ei/cluster.py`
- Modify: `src/ei/curator.py`
- Modify: `src/ei/gate.py`
- Modify: `src/ei/maintainer.py`
- Modify: `src/ei/changeset.py`
- Modify: `src/ei/index.py`
- Modify: `src/ei/project.py`
- Modify: `src/ei/journal.py`
- Modify: `schemas/observation.schema.json`
- Modify: `schemas/pattern.schema.json`
- Modify: `schemas/change-set.schema.json`
- Modify: `schemas/gate-decision.schema.json`
- Modify: `skills/external-intelligence/schemas/change-set.schema.json`
- Modify: `skills/external-intelligence/schemas/gate-decision.schema.json`
- Create: `tests/unit/test_host_applicability.py`
- Modify: `tests/unit/test_curator.py`
- Modify: `tests/unit/test_gate.py`
- Modify: `tests/unit/test_maintainer.py`
- Modify: `tests/unit/test_changeset.py`
- Modify: `tests/unit/test_schema_contracts.py`
- Modify: `tests/acceptance/test_changeset_metadata_privacy.py`

**Interfaces:**

新規永続fieldを次に固定する。

```python
source_host_id: str
source_host_family: str
applicability_scope: Literal["universal", "family", "host"]
applicable_host_ids: tuple[str, ...]
applicable_host_families: tuple[str, ...]
```

既存`applicability`は業務domain/tag用として残し、host範囲と混在させない。

```python
def normalize_host_applicability(
    data: Mapping[str, Any],
    *,
    source_host_id: str,
    source_host_family: str,
) -> HostApplicability: ...
```

- [ ] 新規候補のscope正規化と、不正scopeのsource-host限定フォールバックをテストする。

```python
def test_missing_scope_is_limited_to_source_host(self):
    scope = normalize_host_applicability(
        {}, source_host_id="codex-cli", source_host_family="codex-compatible"
    )
    self.assertEqual(scope.scope, "host")
    self.assertEqual(scope.host_ids, ("codex-cli",))
    self.assertEqual(scope.host_families, ())

def test_family_scope_requires_exact_source_family(self):
    scope = normalize_host_applicability(
        {"applicability_scope": "family", "applicable_host_families": ["gemini-compatible"]},
        source_host_id="test-compatible-cli",
        source_host_family="gemini-compatible",
    )
    self.assertEqual(scope.host_families, ("gemini-compatible",))
```

- [ ] 失敗を確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_host_applicability tests.unit.test_curator tests.unit.test_gate tests.unit.test_maintainer tests.unit.test_changeset tests.unit.test_schema_contracts tests.acceptance.test_changeset_metadata_privacy`

Expected: field未定義またはschema additionalProperties拒否でFAIL。

- [ ] `NormalizedHookEvent`、`ObservationInput/State`、`ClusterState`、`PatternState`、`QueueItem`へsource host ID/familyを追加し、hook→event→queue→observation→cluster→candidateへ欠落なく伝播する。

- [ ] `GateDecision`へ5 field、`gate-decision.schema.json`と`_candidate_input`へ3つの適用範囲fieldを追加し、整理AIの1回の意味判定で継承可否と適用範囲を同時に返す。providerの`YES`出力では`applicability_scope`、`applicable_host_ids`、`applicable_host_families`を必須、`NO`出力では無視する。`source_host_id`と`source_host_family`はprovider出力を信用せず、入力candidateから決定論的に`GateDecision`へ複写する。root schemaとinstalled Skill schemaは同一内容にする。

- [ ] `maintainer._process_claimed`で`GateDecision`の5 fieldをcurator入力へそのまま渡す。gate後に適用範囲を決める2回目のprovider callは追加しない。

- [ ] `persistable_fields.py`のclosed allowlistに5 fieldを型・長さ制限付きで追加する。host ID/familyはsafe label、listは重複なし・上限16件とする。

- [ ] `curator.py`でprovider出力を正規化する。

正規化規則:

- `universal`: host ID/family listは両方空。
- `family`: family listが1件以上、host ID listは空。出力familyにsource familyが含まれなければsource-host限定へ落とす。
- `host`: host ID listが1件以上、family listは空。出力host IDにsource hostが含まれなければsource-host限定へ落とす。
- 欠落、未知scope、両list併用、空listはsource-host限定。
- 旧patternで5 fieldがすべて欠ける場合だけ、読取時に`universal`として解釈する。旧event/patternを書換えない。

- [ ] `changeset.py`、`index.py`、`project.py`、全schemaで5 fieldを保持する。pattern markdownにも`Applicability scope`、`Host families`、`Host IDs`を出すが、machine-local pathは出さない。

- [ ] 同一source eventの再送が同じidempotency keyになり、異なるsource hostの独立eventを誤って同一視しないテストを追加する。

- [ ] 対象テストを再実行する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_host_applicability tests.unit.test_curator tests.unit.test_gate tests.unit.test_maintainer tests.unit.test_changeset tests.unit.test_schema_contracts tests.acceptance.test_changeset_metadata_privacy`

- [ ] complete unittest suiteを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json`

Expected: failed 0。

- [ ] Task 3のファイルだけをcommitする。

```powershell
git add src/ei/hooks/base.py schemas/hook-event.schema.json src/ei/models.py src/ei/persistable_fields.py src/ei/queue.py schemas/queue-item.schema.json src/ei/ingest.py src/ei/cluster.py src/ei/curator.py src/ei/gate.py src/ei/maintainer.py src/ei/changeset.py src/ei/index.py src/ei/project.py src/ei/journal.py schemas/observation.schema.json schemas/pattern.schema.json schemas/change-set.schema.json schemas/gate-decision.schema.json skills/external-intelligence/schemas/change-set.schema.json skills/external-intelligence/schemas/gate-decision.schema.json tests/unit/test_host_applicability.py tests/unit/test_curator.py tests/unit/test_gate.py tests/unit/test_maintainer.py tests/unit/test_changeset.py tests/unit/test_schema_contracts.py tests/acceptance/test_changeset_metadata_privacy.py
git commit -m "feat: persist host applicability metadata"
```

---

### Task 4: retrieval前段のhost applicabilityフィルタ

**Files:**

- Modify: `src/ei/retrieve.py`
- Modify: `src/ei/hook_entry.py`
- Modify: `src/ei/cli.py`
- Modify: `tests/unit/test_retrieve.py`
- Modify: `tests/unit/test_hook_entry.py`
- Modify: `tests/integration/test_personal_team_recall.py`
- Modify: `tests/performance/test_retrieval_corpus.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class RetrievalQuery:
    host_id: str = ""
    host_family: str = ""

def host_scope_allowed(
    query: RetrievalQuery,
    pattern: PatternState | Mapping[str, Any],
) -> bool: ...
```

- [ ] universal、family一致/不一致、host一致/不一致、旧patternを網羅する失敗テストを追加する。

```python
def test_family_rule_is_available_to_compatible_host_only(self):
    pattern = make_pattern(
        applicability_scope="family",
        applicable_host_families=("gemini-compatible",),
    )
    matching = RetrievalQuery(
        prompt="reuse rule", host_id="test-compatible-cli", host_family="gemini-compatible"
    )
    other = RetrievalQuery(
        prompt="reuse rule", host_id="codex-cli", host_family="codex-compatible"
    )
    self.assertTrue(host_scope_allowed(matching, pattern))
    self.assertFalse(host_scope_allowed(other, pattern))

def test_host_rule_never_enters_other_host_scoring(self):
    pattern = make_pattern(
        applicability_scope="host", applicable_host_ids=("gemini-cli",), utility=1.0
    )
    result = retrieve(
        [pattern], RetrievalQuery(prompt="reuse rule", host_id="codex-cli", host_family="codex-compatible")
    )
    self.assertEqual(result.hits, ())
```

- [ ] 失敗を確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_retrieve tests.unit.test_hook_entry tests.integration.test_personal_team_recall tests.performance.test_retrieval_corpus`

Expected: family field未使用のため不一致hostへ候補が漏れてFAIL。

- [ ] `_pattern_mapping`に新fieldを含め、`_eligible`のscore計算前に`host_scope_allowed`を呼ぶ。

判定規則:

- `universal`は全hostに許可。
- `family`は`query.host_family`の完全一致だけ許可。
- `host`は`query.host_id`の完全一致だけ許可。
- 新fieldを持つpatternには`RetrievalPolicy.allow_cross_host`を適用しない。
- 旧`host_ids`だけを持つpatternは旧契約で判定し、host情報が一切ない旧patternは互換上`universal`とする。
- 不許可patternはlexical、freshness、utilityの採点対象に入れず、context文字数にも含めない。

- [ ] hook recallではeventのsource host ID/family、手動CLI recallでは`settings.hosts[host_id].host_family`をqueryへ渡す。未知hostは空familyでfamily ruleに一致させない。

- [ ] personalとteamの双方をhost filter後に既存ルールでmergeする。片方が利用不能でももう片方の結果を変えない。

- [ ] 対象テストを再実行する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_retrieve tests.unit.test_hook_entry tests.integration.test_personal_team_recall tests.performance.test_retrieval_corpus`

- [ ] complete unittest suiteを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json`

Expected: failed 0。

- [ ] Task 4のファイルだけをcommitする。

```powershell
git add src/ei/retrieve.py src/ei/hook_entry.py src/ei/cli.py tests/unit/test_retrieve.py tests/unit/test_hook_entry.py tests/integration/test_personal_team_recall.py tests/performance/test_retrieval_corpus.py
git commit -m "feat: filter memories by host applicability"
```

---

### Task 5: 単一整理AI routerと非破壊の失敗状態

**Files:**

- Modify: `config/defaults.json`
- Modify: `src/ei/config.py`
- Modify: `src/ei/inference/router.py`
- Modify: `src/ei/queue.py`
- Modify: `schemas/queue-item.schema.json`
- Modify: `src/ei/maintainer.py`
- Modify: `src/ei/doctor.py`
- Modify: `tests/unit/test_inference_router.py`
- Modify: `tests/unit/test_queue.py`
- Modify: `tests/unit/test_maintainer.py`
- Modify: `tests/integration/test_provider_quota.py`
- Modify: `tests/integration/test_queue_recovery.py`
- Create: `tests/integration/test_single_organizer.py`

**Interfaces:**

```python
class QueueState(StrEnum):
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    DEFERRED = "DEFERRED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_NEEDS_ATTENTION = "FAILED_NEEDS_ATTENTION"
    YES_CURATING = "YES_CURATING"
    NO_DISCARDED = "NO_DISCARDED"
    DONE = "DONE"
    QUARANTINED = "QUARANTINED"

class ProviderRouter:
    def selected(self) -> InferenceProvider: ...
    def generate(
        self,
        stage: str,
        schema_name: str,
        input_json: Mapping[str, Any],
        budget: InferenceBudget,
    ) -> ProviderResult: ...
```

`config/defaults.json`へ次を追加する。

```json
{
  "curation": {
    "max_attempts": 3,
    "retry_delay_seconds": 300
  }
}
```

- [ ] 選択AIが失敗しても別providerを呼ばないテストを先に追加する。

```python
def test_generate_never_falls_back_from_selected_organizer(self):
    selected = FakeProvider(
        "ollama", "local", ProviderResult("ollama", "failed", error_code=PROVIDER_UNAVAILABLE)
    )
    other = FakeProvider(
        "subscription-cli", "subscription", ProviderResult("subscription-cli", output={"decision": "YES"})
    )
    router = ProviderRouter(
        [selected, other], organizer=OrganizerSelection("READY", "ollama", None)
    )
    result = router.generate("gate", "gate-decision", {"candidate": "safe"}, budget())
    self.assertEqual(result.error_code, PROVIDER_UNAVAILABLE)
    self.assertEqual(selected.calls, 1)
    self.assertEqual(other.calls, 0)
```

- [ ] queueのdefer/retry/attention遷移テストを追加する。

```python
def test_malformed_response_retries_then_requires_attention(self):
    item = ready_item(attempts=0)
    first = process_failure(item, MALFORMED_RESPONSE, max_attempts=3)
    self.assertEqual(first.state, QueueState.FAILED_RETRYABLE)
    second = process_failure(replace(first, attempts=2), MALFORMED_RESPONSE, max_attempts=3)
    self.assertEqual(second.state, QueueState.FAILED_NEEDS_ATTENTION)

def test_unavailable_organizer_defers_without_discarding_candidate(self):
    result = run_once(provider_error=PROVIDER_UNAVAILABLE)
    self.assertEqual(result.item.state, QueueState.DEFERRED)
    self.assertTrue(result.item.payload_ref)
```

- [ ] 失敗を確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_inference_router tests.unit.test_queue tests.unit.test_maintainer tests.integration.test_provider_quota tests.integration.test_queue_recovery tests.integration.test_single_organizer`

Expected: routerが次providerを呼ぶ、または旧`DEFERRED_QUOTA`/`FAILED`になるためFAIL。

- [ ] routerを選択済み整理AI1件だけ構築・呼出す実装へ変更する。

実装規則:

- `SELECTION_REQUIRED`は`ProviderSelectionError("ORGANIZER_SELECTION_REQUIRED")`。
- provider disabled、unavailable、quota、rate limit、auth、timeoutは結果をそのまま返し、別providerを呼ばない。
- unit test用にprovider配列注入は残すが、`organizer.provider_id`一致1件だけを選ぶ。
- subscription providerは`organizer.host_id`のadapter/commandだけを使う。work hostの先頭を暗黙採用しない。

- [ ] queueの新規書込みは`provider_preference`を選択provider 1件だけにする。旧複数値は読取互換で受理するが、処理時には現在manifestのorganizerを使う。これによりupdate前のpending itemも新しい整理AIで再開する。

- [ ] maintainerの遷移を実装する。

| Error class | New state | Payload | Retry |
|---|---|---|---|
| organizer未選択、disabled、unavailable、quota、rate limit、auth、timeout | `DEFERRED` | 保持 | `next_eligible_at`以降 |
| malformed/schema violation、attempts < max | `FAILED_RETRYABLE` | 保持 | 固定300秒後 |
| malformed/schema violation、attempts >= max | `FAILED_NEEDS_ATTENTION` | 保持 | 自動再試行なし |
| privacy/schema safety violation | `QUARANTINED` | spool規則に従う | 自動再試行なし |
| gate `NO` | `NO_DISCARDED` | 既存規則 | なし |
| curate成功 | `DONE` | 既存規則 | なし |

旧`DEFERRED_QUOTA`は読取時に`DEFERRED`、旧`FAILED`は明示的manual retry対象として読めるようにする。履歴eventは書換えない。

- [ ] doctor/queue healthへ`deferred`、`retryable`、`needs_attention`件数と、organizerの`READY`/`SELECTION_REQUIRED`を追加する。

- [ ] 整理AI停止中も既存patternのrecallが成功するintegration testを通す。

- [ ] 対象テストを再実行する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_inference_router tests.unit.test_queue tests.unit.test_maintainer tests.integration.test_provider_quota tests.integration.test_queue_recovery tests.integration.test_single_organizer`

- [ ] complete unittest suiteを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json`

Expected: failed 0。

- [ ] Task 5のファイルだけをcommitする。

```powershell
git add config/defaults.json src/ei/config.py src/ei/inference/router.py src/ei/queue.py schemas/queue-item.schema.json src/ei/maintainer.py src/ei/doctor.py tests/unit/test_inference_router.py tests/unit/test_queue.py tests/unit/test_maintainer.py tests/integration/test_provider_quota.py tests/integration/test_queue_recovery.py tests/integration/test_single_organizer.py
git commit -m "feat: enforce one organizer without fallback"
```

---

### Task 6: 説明付き対話setupとhost別ライフサイクル

**Files:**

- Create: `src/ei/setup_ui.py`
- Modify: `src/ei/installer.py`
- Modify: `src/ei/compatibility.py`
- Modify: `src/ei/doctor.py`
- Modify: `src/ei/cli.py`
- Modify: `src/ei/hook_status.py`
- Modify: `src/ei/canary.py`
- Create: `tests/unit/test_setup_ui.py`
- Modify: `tests/unit/test_cli.py`
- Modify: `tests/unit/test_canary.py`
- Modify: `tests/acceptance/test_public_setup_journey.py`
- Modify: `tests/acceptance/test_cross_platform_setup.py`
- Modify: `tests/acceptance/test_setup_rerun_reconciliation.py`
- Create: `tests/integration/test_multi_host_lifecycle.py`
- Modify: `tests/certification/test_receipt_contract.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class SetupChoice:
    value: str
    label: str
    status: Literal["AVAILABLE", "AUTH_REQUIRED", "NOT_FOUND", "NOT_CONFIGURED", "UNSUPPORTED"]
    selectable: bool
    help_text: str

def render_intro() -> str: ...
def render_single_choice(title: str, choices: Sequence[SetupChoice]) -> str: ...
def render_multiple_choices(title: str, choices: Sequence[SetupChoice]) -> str: ...
def parse_single_choice(answer: str, choices: Sequence[SetupChoice]) -> str: ...
def parse_multiple_choices(answer: str, choices: Sequence[SetupChoice]) -> tuple[str, ...]: ...
def render_setup_summary(
    selection: SetupSelection,
    previous_manifest: Mapping[str, Any] | None,
    actions: Sequence[InstallPlanItem],
) -> str: ...
```

- [ ] 表示文、入力例、無効入力、変更summaryの失敗テストを追加する。

```python
def test_intro_explains_the_two_roles_before_selection(self):
    rendered = render_intro()
    self.assertIn("記憶の整理AI", rendered)
    self.assertIn("1つだけ選びます", rendered)
    self.assertIn("作業・記憶取得CLI", rendered)
    self.assertIn("複数選べます", rendered)

def test_multiple_choice_shows_example_and_deduplicates(self):
    rendered = render_multiple_choices("作業・記憶取得CLI", choices())
    self.assertIn("入力例: 1,2", rendered)
    self.assertEqual(parse_multiple_choices("2,1,2", choices()), ("second", "first"))

def test_summary_confirms_knowledge_is_preserved(self):
    rendered = render_setup_summary(selection(), previous_manifest(), actions())
    self.assertIn("既存ナレッジは削除・初期化しません", rendered)
    self.assertIn("更新", rendered)
```

- [ ] 失敗を確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_setup_ui tests.unit.test_cli tests.unit.test_canary tests.acceptance.test_public_setup_journey tests.acceptance.test_cross_platform_setup tests.acceptance.test_setup_rerun_reconciliation tests.integration.test_multi_host_lifecycle tests.certification.test_receipt_contract`

Expected: `setup_ui`未作成または既存raw promptのためFAIL。

- [ ] 対話順序と表示を次に固定する。

1. 「外部知能は1つで、どのCLIからも同じナレッジを使う」と説明する。
2. 「記憶の整理AIは候補を整理・統合する役割で1つだけ」と説明し、番号付き単一選択を出す。入力例は`1`。
3. subscription型整理AIを選んだ場合だけ、使用するCLIを番号付き単一選択する。
4. 「作業・記憶取得CLIはhookで経験を送り、作業前に記憶を取得する役割で複数選択可」と説明し、番号付き複数選択を出す。入力例は`1,2`。
5. custom compatible CLI追加の有無を聞く。対話追加では互換元の公開CLI、表示名、実行ファイル名、host home、hook設定相対path、context相対path、Skill root相対pathを入力例付きで順に読み、`build_host_profile`で検証してmachine-local runtimeへ保存する。既存profile取込を選んだ場合だけprofile pathとhost homeを読む。
6. personal knowledge rootと任意team knowledgeを既存フローで選ぶ。
7. setup/update判定、整理AI、work hosts、追加・更新・削除対象、ナレッジ保持を人間向け名称で表示し、既存承認フローへ渡す。

表示は`AVAILABLE=利用可能`、`AUTH_REQUIRED=要認証`、`NOT_FOUND=未検出`、`NOT_CONFIGURED=未設定`、`UNSUPPORTED=非対応`へ固定する。`AVAILABLE`だけ選択可能とし、それ以外は必要な対応を1文で表示する。既存値が利用不能でもupdate summaryへ残し、明示変更なしに削除しない。通常表示ではraw command、絶対path、private profile内容を表示しない。

- [ ] `setup`再実行で同じ選択なら`ALREADY_CURRENT`、変更時は差分だけ更新する。省略値は既存manifestから復元し、既存hostを暗黙削除しない。

- [ ] host追加は対象hostのhook/context/Skill/profileだけ追加し、host削除はownership hash一致時だけ対象hostの管理ファイルとruntime profileを削除する。personal/team knowledge、event、patternは保持する。

- [ ] custom hostを削除後、そのhost限定patternが保存されたまま他hostへ出ないことをintegration testで確認する。再登録後は同じhost IDで再取得可能にする。

- [ ] status/doctor/canary/receiptをhost instance単位にする。1 hostのreceiptを別hostの成功証拠へ流用しない。出力は整理AIを1件、work hostsを全件、queue状態を別欄にする。

- [ ] 対象テストを再実行する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.unit.test_setup_ui tests.unit.test_cli tests.unit.test_canary tests.acceptance.test_public_setup_journey tests.acceptance.test_cross_platform_setup tests.acceptance.test_setup_rerun_reconciliation tests.integration.test_multi_host_lifecycle tests.certification.test_receipt_contract`

- [ ] complete unittest suiteを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json`

Expected: failed 0。

- [ ] Task 6のファイルだけをcommitする。

```powershell
git add src/ei/setup_ui.py src/ei/installer.py src/ei/compatibility.py src/ei/doctor.py src/ei/cli.py src/ei/hook_status.py src/ei/canary.py tests/unit/test_setup_ui.py tests/unit/test_cli.py tests/unit/test_canary.py tests/acceptance/test_public_setup_journey.py tests/acceptance/test_cross_platform_setup.py tests/acceptance/test_setup_rerun_reconciliation.py tests/integration/test_multi_host_lifecycle.py tests/certification/test_receipt_contract.py
git commit -m "feat: add guided multi CLI setup lifecycle"
```

---

### Task 7: end-to-end契約、公開文書、公開前検証

**Files:**

- Modify: `README.md`
- Modify: `docs/setup.md`
- Modify: `docs/update.md`
- Modify: `docs/uninstall.md`
- Modify: `docs/cli-reference.md`
- Modify: `docs/compatibility.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security-and-privacy.md`
- Create: `tests/acceptance/test_single_intelligence_multi_cli.py`
- Modify: `tests/acceptance/test_public_setup_journey.py`
- Modify: `tests/acceptance/test_public_workflows.py`
- Modify: `tests/acceptance/test_public_repository_audit.py`

**End-to-end contract:**

```python
def test_two_work_hosts_share_one_intelligence_and_one_organizer(self):
    first = setup_selection(
        organizer_provider="subscription-cli",
        organizer_host="gemini-cli",
        work_hosts=("codex-cli", "test-compatible-cli"),
    )
    setup(first)
    observe_from("test-compatible-cli", reusable_candidate(scope="family", family="gemini-compatible"))
    maintain_once()

    self.assertEqual(recall_from("test-compatible-cli").selected_count, 1)
    self.assertEqual(recall_from("qwen-code").selected_count, 0)

    second = replace(first, organizer_host="test-compatible-cli")
    update(second)
    self.assertEqual(knowledge_identity_before(), knowledge_identity_after())
    self.assertEqual(count_events(), 1)
```

- [ ] 上記に相当するacceptance testを先に追加し、setup→2 host capture→1 organizer curate→scope別recall→organizer変更→host削除→再setupの全経路を1つのtemp rootで実行する。

test assertions:

- manifestのorganizerは常に1件。
- 1つの候補処理で選択外providerのcall countは0。
- 同じsource eventのhook再送でevent/candidateが増えない。
- universal/family/hostの3範囲が仕様通り見える。
- organizer停止中の新規候補は`DEFERRED`、既存記憶のrecallは成功。
- setup/update/uninstall前後でpersonal knowledge identityと既存event/pattern hashが一致。
- host削除はそのhostの管理対象だけに限定。
- team knowledge未設定時に余分なteam contextを読まない。

- [ ] 失敗を確認する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.acceptance.test_single_intelligence_multi_cli`

Expected: 統合経路未実装または契約不一致でFAIL。

- [ ] READMEと公開文書を実装済みCLI引数・画面文言・状態名に合わせて更新する。

文書要件:

- 外部知能1つ、整理AI1つ、作業・記憶取得CLI複数の違いを冒頭で説明する。
- `1`と`1,2`の入力例を載せる。
- custom compatible CLIは公開adapter familyを再利用できること、互換性は自動保証されずcheck/doctorが必要なことを説明する。
- custom profile例は`test-compatible-cli`だけを使い、実在非公開名、実command、個人pathを載せない。
- setup再実行は設定差分更新であり、既存ナレッジを削除・初期化しないと明記する。
- organizer unavailableは新規整理だけを遅延させ、既存記憶の取得を止めないと明記する。
- host削除後もhost限定patternは保持され、他hostには表示されないと明記する。
- team knowledgeは任意で、hostごとに複製しないと明記する。

- [ ] 文書・公開treeに禁止情報がないことをテストする。単語blacklistだけに依存せず、公開auditとdetect-secretsを使う。

- [ ] 対象acceptance testを実行する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.acceptance.test_single_intelligence_multi_cli tests.acceptance.test_public_setup_journey tests.acceptance.test_public_workflows tests.acceptance.test_public_repository_audit`

- [ ] complete unittest suiteを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json`

Expected: failed 0。

- [ ] production source auditを実行する。

Run: `\.venv\Scripts\python.exe -B scripts\audit-production-source.py --repo . --json`

Expected: status passed、findings 0。

- [ ] working treeとreachable historyのpublic auditを実行する。

```powershell
.\.venv\Scripts\python.exe -B scripts\audit-public-release.py --repo . --policy release\publication-policy.json --working-tree --json
.\.venv\Scripts\python.exe -B scripts\audit-public-release.py --repo . --policy release\publication-policy.json --reachable-history --require-scanner-receipts --json
```

Expected: 両方status passed。

- [ ] secret scan契約を実行する。

Run: `\.venv\Scripts\python.exe -B -m unittest tests.acceptance.test_public_workflows.PublicWorkflowTests.test_tracked_tree_has_no_unreviewed_secret_scanner_findings`

Expected: PASS。

- [ ] patch品質と変更範囲を確認する。

```powershell
git diff --check
git status --short
git diff --stat
```

Expected: whitespace errorなし、列挙ファイル以外の変更なし。

- [ ] Task 7のファイルだけをcommitする。

```powershell
git add README.md docs/setup.md docs/update.md docs/uninstall.md docs/cli-reference.md docs/compatibility.md docs/architecture.md docs/security-and-privacy.md tests/acceptance/test_single_intelligence_multi_cli.py tests/acceptance/test_public_setup_journey.py tests/acceptance/test_public_workflows.py tests/acceptance/test_public_repository_audit.py
git commit -m "docs: complete multi CLI public setup contract"
```

- [ ] commit後の最終証拠を取り直す。

```powershell
.\.venv\Scripts\python.exe -B scripts\run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts\unittest-summary.json
.\.venv\Scripts\python.exe -B scripts\audit-production-source.py --repo . --json
.\.venv\Scripts\python.exe -B scripts\audit-public-release.py --repo . --policy release\publication-policy.json --working-tree --json
git status --short
```

Expected: failed 0、audits passed、worktree clean。

## Spec Coverage Matrix

| Approved requirement | Implementation task | Primary proof |
|---|---:|---|
| 外部知能1つ、整理AI1つ、work host 1件以上 | 1, 5, 7 | manifest migration、router call count、end-to-end |
| custom compatible CLIを固有Host IDで扱う | 2, 6, 7 | profile validation、hook receipt、lifecycle |
| `universal` / `family` / `host` | 3, 4, 7 | schema、pre-score filter、cross-host negative cases |
| provider障害時も記憶取得継続 | 5, 7 | queue states、recall integration |
| setup/update/uninstallでナレッジ保持 | 1, 6, 7 | identity/hash before-after assertions |
| 説明、状態、入力例、差分、保持確認 | 6, 7 | setup UI string tests、public docs tests |
| Windows/macOS/Linux | 6, 7 | cross-platform generation/quoting tests |
| 公開安全性 | 2, 7 | local-only profile tests、production/public/secret audits |

## Final Implementation Report Contract

実装担当は完了時に次を分けて報告する。

- **Completed:** 実装したmanifest schema、organizer、work hosts、profile、scope、queue state、setup UX、文書。
- **Verified:** 対象テスト、complete suiteの総test数/failed/skipped、production audit、public audit、secret scan、`git diff --check`、worktree状態。
- **Preserved:** setup/update/uninstall前後のpersonal knowledge identity、event/pattern hash、team knowledge状態。
- **Unverified:** 実機ごとのCLI hook発火、実provider quota、remote CI、公開GitHub設定。receiptなしにverifiedと表現しない。
- **Blocked:** user権限、外部CLI、remote状態が必要な項目だけ。ローカル実装の未完了を外部要因として扱わない。
