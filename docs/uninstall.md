# アンインストール

アンインストールは、セットアップが所有するHost統合とruntimeだけを処理します。外部知能は1つの個人ナレッジとして保持され、event、pattern、projection、個人identityとhashは削除・初期化しません。

## 既定の動作

`--manifest` で対象manifestを指定し、`--check-only` で削除対象、所有hash、backup、rollback範囲と `manifest_sha256` を確認します。適用時は、確認した値を `--confirm-manifest-sha256 sha256:...` で再指定します。manifestが差し替わっていた場合は削除を開始しません。`--json` で結果を保存できます。既定では次を処理します。

- managed context、Hook設定、Skill、Skill binding。
- schedulerの登録情報と、必要なruntimeの管理状態。
- manifestの状態を `UNINSTALLED` に更新。

個人ナレッジのevent、pattern、projection、共有team event、team descriptor、team member/writer、writer identityは保持します。チームナレッジをHostごとに複製していないため、Host統合を削除しても共有eventは変わりません。

## 選べるオプション

| 引数 | 動作 |
|---|---|
| `--check-only` | read-onlyの削除計画だけを作る |
| `--confirm-manifest-sha256` | check-onlyで確認した対象manifestのSHA-256を適用時に固定する |
| `--keep-skills` | installed Skillを残す |
| `--remove-runtime-cache` | machine-localの個人/team cacheだけを削除する |
| `--remove-runtime` | queue、spool、lock、log、outbox、writer identityなどruntimeを削除する |
| `--remove-queue` | queueだけを追加削除する |
| `--remove-spool` | spoolとemergency-spoolを追加削除する |
| `--remove-venv` | セットアップが作ったvirtual environmentだけを削除する |
| `--restore-config-backup` | 所有が確認できるbackupを復元する |
| `--force` | 所有確認済みの対象に限り、競合方針を明示する |

`--remove-runtime-cache` と `--remove-runtime` はナレッジ削除ではありません。event/patternの履歴や共有team保存先は削除しません。個人保存先を消す場合は、別の所有者確認済みバックアップと手順が必要です。

## 競合と保持

利用者がmanaged targetを編集している場合は `UNINSTALL_CONFLICT` として、そのファイルを上書きせず停止します。所有hashが一致する対象だけをtransactionで変更します。途中で失敗してもappend-only event、pattern、個人identityは保持されます。

Hostを削除した後も、そのHost限定patternは個人ナレッジに保持されます。別Hostのrecallには表示されず、同じHost IDを再登録したときだけ範囲内で再表示されます。整理AIが停止している場合も、アンインストール後に保持された既存patternの取得は続けられます。

チームを無効にした状態では、アンインストールの確認でteam filesystem/provider/prompt/queue/projection/metricを読みません。共有保存先が停止中でも、個人の保持結果は `DEFERRED` とは別に確認できます。

## 再セットアップ

同じrootで再セットアップすれば、保持された個人ナレッジを再利用できます。選択を省略して先頭providerを採用することはありません。作業CLIの例は `1` と `1,2`、互換profileの公開例は `test-compatible-cli` だけです。再セットアップは既存ナレッジを削除・初期化しない非破壊操作です。

## 状態の境界

`UNINSTALLED` は管理対象の解除が完了した状態です。`SETUP_COMPLETE`、`HOST_ACTIVATION_VERIFIED`、`PRODUCTION_COMPLETE`、`EFFECT_VALIDATED` は別の証拠を必要とします。実機Hook、外部同期、ACL、provider quotaが未確認のときは `UNVERIFIED` として扱います。
