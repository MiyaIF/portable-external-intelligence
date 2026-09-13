# Portable External Intelligence Engine

このプロジェクトは、複数のCLIで同じ記憶を安全に使うための公開ランタイムです。
冒頭で役割を分けます。

- 外部知能は1つです。個人ナレッジを1つの知識面として扱います。
- 整理AIは1つです。候補を整理するproviderは、設定した1件だけを呼びます。
- 作業・記憶取得CLIは複数選べます。各CLIは同じ知識面を取得し、取得元Hostの範囲を記録します。

この3つは同じものではありません。CLIを増やしても、CLIごとに別の外部知能や整理AIを作りません。
作業CLIの入力例は `1`（1つ）と `1,2`（2つ）です。

公開エンジンと個人ナレッジは別の場所に置きます。公開エンジンには、利用者のプロンプト、応答、認証情報、顧客情報を含めません。

## クイックスタート

GitとPython 3.11以降を用意し、リポジトリを取得してから対象OSのラッパーを実行します。

```text
git clone https://github.com/MiyaIF/portable-external-intelligence.git
cd portable-external-intelligence
```

Windows PowerShell:

```text
.\scripts\setup.ps1
```

macOS/Linux:

```text
sh scripts/setup.sh
```

通常の利用手順では、2回目の初期化コマンドはありません（No second initialization command is part of the normal journey.）。同じセットアップを再実行すると、既存のナレッジを保持したまま設定変更だけを反映します。

セットアップでは、次を順番に確認します。

1. 作業・記憶取得CLIを1件以上選ぶ（`1` または `1,2`）。
2. 整理AIを1件だけ選ぶ。`subscription-cli` を選ぶ場合だけ整理用Hostも選ぶ。
3. `local`、`github-new`、`github-existing` の知識モードと個人ナレッジの保存先を選ぶ。
4. 必要ならチーム保存先、同期、スケジュール、Skillの配置方法を選ぶ。
5. `--check-only` で計画を確認し、適用時は `--accept-plan` を付ける。

作業CLIと整理用Hostは別にできます。たとえば作業CLIを `codex-cli` と
`test-compatible-cli`、整理用Hostを `gemini-cli` とする構成です。
整理用Hostが停止しても、新しい候補の整理だけが `DEFERRED` になり、既存記憶の取得は続きます。

## 公開対応CLI

| ID | CLI | 用途 |
|---|---|---|
| `codex-cli` | Codex CLI | 作業と記憶の取得 |
| `claude-code` | Claude Code | 作業と記憶の取得 |
| `gemini-cli` | Gemini CLI | 作業と記憶の取得、または整理用Host |
| `qwen-code` | Qwen Code | 作業と記憶の取得 |

対応可否は、CLIの実行ファイルだけでなく、Hook、Skillの検出、同意、イベント受信で決まります。未対応の組み合わせは `not supported` と表示し、ファイルが置けただけでは有効化済みとは扱いません。

## 互換CLIのprofile

公開adapter familyを再利用する互換CLIは、機械ローカルのprofileで表します。公開例は架空の `test-compatible-cli` だけです。

```json
{
  "schema_version": 1,
  "host_id": "test-compatible-cli",
  "display_name": "Test Compatible CLI",
  "host_family": "gemini-compatible",
  "adapter_id": "gemini-cli",
  "executable_names": ["test-compatible-cli"],
  "hook_config_path": ".config/test-compatible/settings.json",
  "global_context_path": ".config/test-compatible/context.md",
  "skill_roots": [".config/test-compatible/skills"]
}
```

profileは実行時の機械ローカル領域へ複製し、元ファイルの場所や検出結果を公開manifestに保存しません。adapterの再利用は形式の互換性を示すだけで、CLIの動作を自動保証しません。`check-only` と `doctor` で確認し、実機のHook発火は別のreceiptで確認します。

## 適用範囲

各patternには、次のいずれかの適用範囲があります。

- `universal`: すべての対応CLIで使える。
- `family`: 同じ `host_family` のCLIで使える。
- `host`: 記録されたHost IDだけで使える。

取得時は範囲をスコア計算より先に確認します。そのため、Host限定patternは別Hostへ表示されません。Hostを削除してもHost限定patternとeventは個人ナレッジに保持され、別Hostには表示されません。同じHost IDを再登録すると、保持されたpatternを範囲内で再び取得できます。

## 保存先とチームナレッジ

自分のナレッジを見るときは、個人保存先の `knowledge/index.md` を開いてください。記録・候補・有効化済み知識へのリンクと件数があります。[ナレッジの見方と状態の確認](docs/knowledge-guide.md)で各フォルダの役割、候補の不足条件、索引の更新待ちを説明しています。

保存先は互いに重ならない4つの役割に分かれます。

| 役割 | 内容 |
|---|---|
| 公開エンジン | code、schema、policy、1つのSkill |
| 個人ナレッジ | append-only event、pattern、取得用projection |
| 任意のチームナレッジ | member/writer単位のsanitized event |
| 機械ローカルruntime | queue、spool、cache、cursor、receipt |

チームナレッジは任意で、既定では無効です。チームを有効にしても、Hostごとにチームナレッジを複製しません。共有eventを参照するprojection、cursor、outbox、writer identityは各machineのruntimeに置き、個人ナレッジとは別に扱います。チーム保存先が停止するとチームだけ `DEFERRED` になり、個人ナレッジの取得と整理は続きます。チームを無効にした場合はteam filesystem/provider/prompt/queue/projection/metricを読みません。

## セットアップの安全性

`local` はローカルGit保存、`github-new` は新しい非公開保存先、`github-existing` は既存の非公開保存先の確認・復元です。個人ナレッジの同期は既定で無効です。公開・不明な保存先は停止します。

セットアップの再実行は、設定差分を適用する非破壊の更新です。既存の個人ナレッジ、team event、pattern、writer identityを削除・初期化しません。差分がなければ `SETUP_COMPLETE` と `ALREADY_CURRENT` を返し、managed targetを再書込みしません。

更新と既定のアンインストールも同じ保持境界を使います。アンインストールはHook、context、Skill、schedulerなど管理対象だけを処理し、ナレッジのevent/patternは保持します。`--remove-runtime-cache` や `--remove-runtime` は追加の明示指定です。

## 日常の流れ

Hookは候補をsanitized envelopeとしてappend-only eventへ渡します。整理AIは1件の選択済みproviderだけを呼び、候補を `YES`、`NO`、または `DEFERRED` に分類します。別providerへ自動切替しません。`DEFERRED` の候補はqueueとpayload参照を保持して、次のmaintenanceで再試行します。

取得は整理AIを必要としません。個人projectionと、設定時だけ使うteam projectionを同じ上限で統合します。整理AIが利用不能でも、すでにactiveなpatternは取得できます。

## 状態の意味

- `SETUP_COMPLETE` は設定完了であり、`not proof`（external sync、member distribution、live hook、production completion、measured effect）の証明ではありません。これらは別のreceiptで確認します。
- `SETUP_COMPLETE`: ソフトウェア設定と管理対象の配置が完了した。
- `HOST_ACTIVATION_VERIFIED`: 実際のCLIからHook/Skillのreceiptを得た。
- `DEFERRED`: 新規処理を後で再試行する。既存記憶の取得停止を意味しない。
- `ALREADY_CURRENT`: 差分がなく、再実行が非破壊のno-opだった。
- `MIGRATION_REQUIRED`: 保存先やidentityの変更に移行手順が必要。
- `MANAGED_TARGET_CONFLICT`: 利用者が変更した管理対象を上書きせず停止した。
- `ACTIVE_RUNTIME_MISMATCH`: manifestとruntimeのidentityが一致しない。
- `PRODUCTION_COMPLETE`: 実機、全ライフサイクル、復旧など必要な証拠がそろった。
- `EFFECT_VALIDATED`: 事前登録した効果検証の条件を満たした。

後の状態を前の状態から推測しません。未取得の実機receipt、provider quota、外部同期、公開前の監査は `UNVERIFIED` または待機として残ります。

## 参照

- [セットアップ](docs/setup.md)
- [更新](docs/update.md)
- [アンインストール](docs/uninstall.md)
- [CLIリファレンス](docs/cli-reference.md)
- [互換性](docs/compatibility.md)
- [アーキテクチャ](docs/architecture.md)
- [セキュリティとプライバシー](docs/security-and-privacy.md)

ライセンスは Apache-2.0 です。
