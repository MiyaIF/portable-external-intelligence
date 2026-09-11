# CLIリファレンス

このCLIは、1つの外部知能を複数の作業・記憶取得CLIから使うための操作面です。候補を整理するAIは1件だけを選びます。作業CLIの入力例は `1` と `1,2` です。

JSON出力は状態、件数、reason code、hashを返します。プロンプト、応答、tool output、credential、絶対path、raw payloadは出力しません。

## 終了コード

| code | 意味 |
|---:|---|
| 0 | 操作は完了。結果に `DEFERRED` などが含まれる場合があります |
| 2 | 入力、引数、schema、sourceのエラー |
| 3 | privacyまたはsecurityの拒否 |
| 4 | Git、remote、所有権の競合 |
| 5 | 依存、整理AI、quota、Host能力の停止 |
| 6 | 内部、復旧、回復不能の失敗 |

## コマンドと引数

| コマンド | 主な引数 |
|---|---|
| `ei setup` | `--repo`/`--engine-root`、`--knowledge-mode local\|github-new\|github-existing`、`--personal-knowledge-root`（`--knowledge-root` alias）、`--runtime-root`、`--work-host`（繰り返し）、`--hosts` alias、`--host-home`、`--host-profile`、`--organizer-provider`、`--organizer-host`、`--team-knowledge-root`/`--team-member-id`/`--no-team-knowledge`、`--sync`/`--no-sync`、`--check-only`、`--non-interactive`、`--accept-plan`、`--json` |
| `ei update` | `--repo`、`--runtime-root`、`--check-only`、`--target-ref`、`--json` |
| `ei uninstall` | `--manifest`、`--check-only`、`--confirm-manifest-sha256`、`--restore-config-backup`、`--keep-skills`、`--remove-runtime`、`--remove-queue`、`--remove-spool`、`--remove-runtime-cache`、`--remove-venv`、`--force`、`--json` |
| `ei doctor` | `--strict`、`--repair-plan`、`--json` |
| `ei status` | `--host HOST_ID`（繰り返し）、`--json` |
| `ei queue drain` | `--max-items INT`、`--time-budget-ms INT`、`--now ISO8601`、`--json` |
| `ei recall` | `--query TEXT`、`--host HOST_ID`、`--cwd PATH`、`--max-chars INT`、`--session-id ID`、`--json` |
| `ei closeout` | stdinのJSON object、または `--input-json PATH`、`--json` |
| `ei maintain` | `--source PATH`（繰り返し）、`--max-items INT`、`--time-budget-ms INT`、`--sync-policy disabled\|manual\|auto`、`--sync`、`--log-file PATH`、`--now ISO8601`、`--json` |
| `ei sync` | `--retry-now`、`--dry-run`、`--json` |
| `ei inventory-existing` | `--source PATH`、`--memory-root PATH`、`--inventory PATH`、`--allow-global-source`、`--approval-path PATH`、`--json` |
| `ei migrate-existing` | `--source PATH`、`--inventory PATH`、`--report PATH`、`--dry-run`、`--apply`、`--apply-plan-hash HASH`、`--json` |
| `ei metrics` | `--sqlite PATH`、`--from ISO8601`、`--to ISO8601`、`--json` |
| `ei experiment-report` | `--experiment-id ID`、`--exposures PATH`、`--outcomes PATH`、`--output PATH`、`--json` |

`observe`、`ingest`、`reconcile`、`project`、`query` は旧形式の読み取り互換です。新しい作業では setup、recall、closeout、maintain を使います。

## setupの選択

`--work-host` は作業と記憶取得の入口を1件以上指定します。`--organizer-provider` は候補を整理するAIを1件だけ指定します。`subscription-cli` の場合は `--organizer-host` も必要です。`--providers` は旧設定の読み取り用で、複数の値から先頭を自動選択しません。

対話画面の入力は `1` または `1,2` のように行います。CLI IDを直接使う非対話では、`--work-host`、`--host-home`、整理AI、必要な `--host-profile`、root、`--accept-plan` をそろえます。

互換CLI profileの公開例は架空の `test-compatible-cli` だけです。公開adapter familyを再利用できますが、互換性は自動保証されません。`check-only` と `doctor`、実機receiptを個別に確認します。

```json
{
  "host_id": "test-compatible-cli",
  "host_family": "gemini-compatible",
  "adapter_id": "gemini-cli"
}
```

## scopeとrecall

patternの適用範囲は `universal`、`family`、`host` の3種類です。Host familyを持つCLIは、同じfamilyのpatternだけを追加で取得できます。Host限定patternはそのHost ID以外へ表示されません。範囲判定はスコア計算より前に行います。

整理AIが停止またはquota超過になった場合、新規候補のqueueは `DEFERRED` になります。payload参照とeventは保持し、別providerへ切り替えません。既存のactive patternを読む `recall` は成功します。

teamを設定しないとteam storeは `DISABLED` です。teamが停止した場合だけteamが `DEFERRED` になり、個人storeの取得は続きます。teamを無効にしたrecallはteam filesystem/provider/prompt/queue/projection/metricを読みません。

## 状態

| 状態 | 意味 |
|---|---|
| `SETUP_COMPLETE` | manifest、管理対象、diagnosticsが完了 |
| `ALREADY_CURRENT` | 差分なしの非破壊no-op |
| `SELECTION_REQUIRED` | 整理AIの選択が未確定。新規整理は `DEFERRED` |
| `DEFERRED` | 新規処理を後で再試行。既存recallは停止しない |
| `DISABLED` | teamなど任意機能を使わない |
| `MIGRATION_REQUIRED` | root、remote、identityの移行が必要 |
| `MANAGED_TARGET_CONFLICT` | 利用者が変更した管理対象を上書きしない |
| `ACTIVE_RUNTIME_MISMATCH` | manifestとruntimeのidentityが不一致 |
| `TEAM_STORE_VALIDATION_DEFERRED` | team保存先の確認だけが保留 |
| `UNINSTALLED` | 管理対象の解除が完了。ナレッジは保持 |
| `UNVERIFIED` | 実機Hook、外部同期、ACL、quotaなど未確認 |

`SETUP_COMPLETE` から `HOST_ACTIVATION_VERIFIED`、`PRODUCTION_COMPLETE`、`EFFECT_VALIDATED` を推測しません。各状態には別の証拠が必要です。

## 変更しない境界

setupの再実行、update、既定のuninstallは、個人ナレッジのevent、pattern、identity、hashを削除・初期化しません。Hostを削除してもHost限定patternは保持し、別Hostには表示しません。再登録時は同じHost IDと範囲が一致した場合だけ取得します。team eventはHostごとに複製しません。
