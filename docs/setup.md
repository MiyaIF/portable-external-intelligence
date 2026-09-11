# セットアップ

このセットアップは、1つの外部知能、1つの整理AI、複数の作業・記憶取得CLIを登録する1回の操作です。外部知能は個人ナレッジと取得設定をまとめた論理的な知識面、整理AIは候補を整理するprovider、作業・記憶取得CLIはその知識面を使う入口です。CLIを複数選んでも、整理AIは1件だけです。

作業CLIの選択欄では、`1`（1件）または `1,2`（2件）のように入力します。公開対応CLIは `codex-cli`、`claude-code`、`gemini-cli`、`qwen-code` です。作業CLIと整理用Hostは別にできます。

## 前提

- GitとPython 3.11以降。
- 実機の確認をするCLIは、あらかじめインストール済みであること。
- `local` 以外では、対象の非公開保存先を操作できる認証済みクライアント。
- 公開エンジン、個人ナレッジ、機械ローカルruntimeの3つが重ならないこと。チームを使う場合は共有保存先も別にします。

セットアップで使う各保存先は、正規化後も互いに重なりません。`--skip-venv` は、管理済みのPython環境で `ei` がすでに読み込める場合だけ使います。

## ラッパーと確認

公開エンジンのルートから、OSに合うラッパーを実行します。

```text
scripts/setup.ps1
scripts/setup.sh
```

対話画面では、作業CLI、Host home、知識モード、個人ナレッジ、整理AI、整理用Host、任意のチーム保存先、同期、scheduler、Skill配置を選びます。画面の計画を確認してから適用します。画面を閉じたり入力を拒否した場合、保存先は変更しません。

非対話では、各選択を引数で明示し、`--non-interactive --accept-plan` を指定します。適用前は `--check-only` を使います。`--json` は状態とreason codeを機械可読にします。

重要な引数は次のとおりです。

- 作業CLI: `--work-host`（繰り返し）、互換aliasの `--hosts`。
- Host home: `--host-home`（`HOST_ID=HOME`、繰り返し）。
- 整理AI: `--organizer-provider`（必須）、必要な場合の `--organizer-host`。
- 互換CLI: `--host-profile`（繰り返し）。公開例は `test-compatible-cli` のみ。
- 個人保存先: `--personal-knowledge-root`。`--knowledge-root` は互換alias。
- チーム保存先: `--team-knowledge-root` と `--team-member-id`、または `--no-team-knowledge`。
- モード: `--knowledge-mode local|github-new|github-existing`。
- 計画: `--check-only`、`--accept-plan`、`--json`、`--non-interactive`。

`--providers` は旧設定の読み取り互換です。新規設定では整理AIを明示します。複数providerを先頭から自動選択することはありません。選択が不足すると `SELECTION_REQUIRED` になり、新規整理は `DEFERRED` として候補を保持します。

## 互換CLI profile

公開adapter familyを再利用したいCLIは、次のような機械ローカルprofileで登録します。

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

profileはruntimeへ正規化コピーされ、元profileの場所や実行時の検出結果は公開manifestへ入りません。`adapter_id` はイベント形式を再利用する指定であり、互換性の自動保証ではありません。`check-only` と `doctor` が通った後も、実機のHook/Skill receiptは別に必要です。

## 知識モード

| モード | 動作 |
|---|---|
| `local` | エンジンとruntimeの外に個人Git保存を作成または再利用します。継続同期は無効です。 |
| `github-new` | 新しい非公開保存先を作成し、初期化・接続・確認を行います。`--confirm-github-create` の値が対象名と一致する必要があります。 |
| `github-existing` | 既存の非公開保存先、branch、履歴、fingerprintを確認して復元または接続します。作成確認は指定しません。 |

非公開であることが確認できない保存先、engineと同じ保存先、変更されたremoteは停止します。認証や外部保存先の到達性はローカルセットアップの成功とは別です。

## 個人とチーム

個人ナレッジは常に1つの保存先です。チームナレッジは任意で、指定しない初回は `DISABLED` です。チームを使っても、Hostごとにチームeventやruleをコピーしません。共有eventのprojection、cursor、outbox、writer identityは各machineのruntimeにだけ作り、個人ナレッジと分けます。

既存manifestでチーム設定を省略する（`omitting`）と、既存の選択を保持します。無効化したいときだけ `--no-team-knowledge` を指定します。共有保存先が停止したときはチームだけ `DEFERRED`、reason codeは `TEAM_STORE_VALIDATION_DEFERRED` となり、個人の取得と整理は続きます。チームを無効にしたときは、team filesystem/provider/prompt/queue/projection/metricを読みません。

## 適用範囲

取得元Hostの情報は、event、candidate、pattern、projectionまで保持します。patternの適用範囲は次の3つです。

- `universal`: すべての対応CLI。
- `family`: 同じ `host_family`（例: `gemini-compatible`）。
- `host`: 指定されたHost IDだけ。

範囲は候補のスコア計算より前に判定されます。Hostを削除しても、そのHost限定patternとeventは個人ナレッジから削除・初期化しません。ただし、削除中は別Hostの取得結果に表示されません。同じHost IDを再登録すると、保持されたpatternを再び範囲内で取得できます。

## 再実行と結果

同じ入力での再実行は非破壊です。差分がなければ `SETUP_COMPLETE`、`reconciliation.status=ALREADY_CURRENT`、managed changesなしとなり、managed fileを書き直しません。差分が安全なら管理対象だけを更新します。

個人のevent、pattern、projectionのidentityとhashは、setup、update、uninstallをまたいで保持します。保存先の変更は `MIGRATION_REQUIRED`、利用者が変更した管理対象は `MANAGED_TARGET_CONFLICT`、manifestとruntimeの不一致は `ACTIVE_RUNTIME_MISMATCH` です。既存の整理用Hostが使えない場合、新規候補は `DEFERRED` になりますが、既存記憶のrecallは成功します。

`SETUP_COMPLETE` はソフトウェア設定の完了だけを示します。`HOST_ACTIVATION_VERIFIED`、`PRODUCTION_COMPLETE`、`EFFECT_VALIDATED` はそれぞれ別の実機・運用・効果証拠が必要です。証拠がない状態は `UNVERIFIED` として残します。

## 確認後の操作

`doctor --strict` でmanifest、profile、Skill binding、root分離を確認します。`status` で作業CLIごとのHook/Skill状態を確認し、`recall` は整理AIなしで既存patternを取得できます。初回の実機確認では、対象CLIのHook同意とSkill検出を行い、receiptを保存します。

詳細な引数は [CLIリファレンス](cli-reference.md)、更新は [update.md](update.md)、削除は [uninstall.md](uninstall.md) を参照してください。
