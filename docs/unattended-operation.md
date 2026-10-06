# 無操作運用の状態と限界

## 通常時

setupで選び、許可したHost・保存先・整理AIの範囲で、候補の受付、保存、再試行、既知の構造化sourceからの回収を進めます。正常終了ごとに質問や完了通知を出す運用ではありません。候補が必ず見つかること、AIがすべての有用な学びを選ぶこと、電源OFF中やOSの集中モード中に通知が表示されることは保証しません。

## 構造化sourceの回収時間

単体の`recover_page`を時間指定なしで呼ぶ場合の既定上限は5秒です。maintenanceからは保守処理全体の残り時間を渡し、明示された短い上限や親deadlineを延長しません。時間制限は協調的であり、単一OS処理の厳密な終了時刻を保証するものではありません。

件数指定は1回の上限で、必ずその件数を処理する保証ではありません。未完了の候補は成功扱いせず、保存済み進捗から再開します。特に0.5秒などの短い明示上限では、端末の速度によって保存まで進めない場合があります。短時間性能の改善は先行運用後の課題です。

## 何が保存されたか

状態は別々に読みます。受付receiptの`SECURED`は、暗号化spool、queue、receiptの永続化を確認した状態で、知識として整理・有効化された意味ではありません。未整理候補は機械ローカルruntimeのqueue/spoolに残ります。`YES`後のeventとknowledge projectionは、個人ナレッジのappend-only eventと取得用projectionに保存されます。incidentやcursorなどの診断・回収状態はruntimeにあり、知識本文とは別です。

構造化sourceが未対応、見つからない、読めない、cursorを確定できない場合はcoverageを`UNKNOWN`のままにします。sourceに候補がないことを、`NO`（保存不要）と同じにしません。runtime上のreceiptだけで、次回のrecall・実CLI受信・実OS通知まで証明されたとは扱いません。

## 複数turn closeoutの関連付け

既存の単一候補受付は変わりません。新しい関連付けは、登録adapterが候補本文とは別に渡したnative contextについて、現在のnamespace、install、session、scope、事前登録済みbinding、closeout recordと明示対象集合を検証できた場合に限ります。同一sessionの全turnを自動で対象にせず、明示されていないturnはWAITINGのままです。候補本文に含まれるHost ID、target ID、`trusted` flagは制御情報として使いません。

知識処理と関連付け状態は別です。実journal証拠を確認したYESのみを`knowledge=APPLIED`にし、全対象receipt/bindingのreadback後に`association=COMMITTED`とACKを返します。明示された構造化NOには永続評価証拠が必要です。評価のないtrusted入力、DEFERRED、FAILED、privacy拒否、提案だけの`changeset_ready`は関連付け完了ではありません。通常CLIのprovider動作は維持されますが、trusted routeでは評価がないとAIを追加呼出しせず`UNKNOWN`で待機します。

maintenanceのrecoveryはspool GC前に同じ処理予算で動きます。recovery巡回自体が`CLOSEOUT_RECOVERY_COMPLETE`でも、各resultが`PENDING`や`UNKNOWN`なら記録は未解決で、health/incidentへ残り、ACKや解消にはなりません。metadata不足・非対応Hostは`UNKNOWN`のままです。現在のpublic adaptersはnative closeout coverageを提供していません。fake adapterやテストは実Hostの自動連携を証明しません。

## 通知と対応

通知には原因と必要な操作を示します。OSまたはCLIが通知を拒否した場合、通知試験の成功へ読み替えません。

| 表示される理由の例 | 利用者ができること | 状態の扱い |
|---|---|---|
| `AUTH_FAILED` | setupで選んだ整理AIへ再ログインし、同じ設定rootで `ei resume-organizer --repo . --json` を実行する | 保留候補は保持し、認証成功を推定しない |
| `QUOTA_EXHAUSTED` | providerの再試行時刻まで待つ。別providerへ自動切替しない | 候補を再試行待ちとして保持する |
| `CAPACITY_RISK` | runtimeの空き容量を確保し、期限前の未整理件数を確認する | 容量上限を超えているのに受付済みと表示しない |
| `PENDING_EXPIRED` | 元の許可済みsourceが残っていれば、その回収結果を確認する | 期限切れ本文は保持済みと表示しない。復元できない場合がある |
| `SOURCE_UNAVAILABLE` / coverage `UNKNOWN` | 許可済みsourceの場所・権限・利用可能性を確認する | 回収成功や全件走査を推定しない |
| `SCHEDULER_STOPPED` | OSの登録状態と診断結果を確認する。明示的に無効化した設定は維持する | 自動で再有効化しない |

実際に表示される理由コードは状態と診断出力に従います。通知送信の受付と、画面に表示されたこと・利用者が読んだことは別の証拠です。

### `AUTH_FAILED` の明示的な再試行

選択済みの整理AIへ再ログインした後、setup時と同じcloneとrootを指定して、保留中の候補に対する一度限りの再試行要求を記録します。

```text
ei resume-organizer --repo . --json
```

`--repo .` はsetup済みclone内で実行する例です。setupでengine、personal knowledge、Codex home、machine runtimeを別rootに置いた場合は、その時と同じ `--engine-root`、`--knowledge-root`、`--codex-home`、`--runtime-root` を追加してください。別のrootやproviderを選び直すコマンドではありません。`--dry-run` は状態を表示するだけで、再試行要求を作りません。

このコマンドが記録するのは、既存の保留候補に対する一度限りの許可です。認証成功の確認でも、その場でAIを呼ぶ操作でもありません。次のmaintenanceが実際の処理を試みる際にも、元のbackoff、TTL、予算を維持します。同じ許可への重複要求はまとめられます。再試行が失敗または中断した場合は許可を再利用せず、backoffが満了した後に必要ならコマンドをもう一度実行してください。回復と扱うのはコマンドの受付時ではなく、setup時に選んだ同じ整理AIが保留候補を意味的に正常処理した後です。別providerへの自動fallbackや定期的な認証probeは行いません。診断の再実行だけでは再試行要求になりません。

## 保持と自動回復の限界

新しいpending領域の初期設定は30日、1,000件または暗号化後64 MiBのうち先に達する上限です。容量が80%以上、または最も近い保持期限まで24時間以下の場合は喪失リスクを通知します。既存利用者が個別に設定している保持値を一律に置き換える意味ではありません。期限後の本文は保持・復旧できるとは限りません。

回収は許可された構造化記憶・要約などを、時間・件数・byte上限付きで読みます。対応sourceがない、列挙できない、上限に達した、内容が変化中、または暗号鍵を利用できない場合は、不明・要対応として止まることがあります。生の会話履歴を後から読み直す経路や、削除済みsourceを復元する機能ではありません。AIの利用枠、認証、OS電源状態、通知設定を迂回しません。

Hookとschedulerの両方が停止している場合、その停止を自動では検知できません。次回のCLI起動または状態照会まで検知しないことがあります。

## 対応Hostと実証範囲

公開対応を宣言しているCLI IDは`codex-cli`、`claude-code`、`gemini-cli`、`qwen-code`です。認定手順では各Hostと宣言OSの20組を個別に扱います。fixture試験、mock provider/OS backend、CIのheadless結果は、実CLIからのHook受信、実schedulerの起動、実OS通知の画面表示、次回recallの代替証拠ではありません。

Task10の隔離fault-injection acceptanceはエンジンAPIとfake境界の契約を検証するものです。実OS・実CLI・実通知表示・公開CIでの今回の実行結果は、この文書だけでは確認されていないため`UNVERIFIED`です。Windows PowerShell 5.1のRestricted execution policyによりskipされたwrapper経路も`UNVERIFIED`のままです。新しいreal receiptやCI結果が得られたら、そのHost/OS/versionごとに公開認定記録へ追加し、未実証の組合せを一般化しません。
