# アーキテクチャ

このランタイムは、外部知能1つ、整理AI 1つ、作業・記憶取得CLI複数という境界で動きます。外部知能は個人ナレッジを統合して取得する論理的な知識面です。整理AIは候補の `YES` / `NO` / `DEFERRED` を決めるproviderです。作業・記憶取得CLIは知識面を読む入口で、CLIごとに別の知識面を持ちません。

セットアップ画面の作業CLI選択は `1` または `1,2` のように入力します。整理AIは常に1件です。

## 保存境界

1. 公開エンジンはcode、schema、policy、Skillを読み取ります。ここをナレッジ書き込み先にしません。
2. 個人ナレッジはappend-only event、candidate、pattern、projection、sanitized provenanceのsource of truthです。
3. 任意のチームナレッジは共有manifestとmember/writer単位のsanitized eventです。個人ナレッジとは別です。
4. 機械ローカルruntimeはqueue、spool、cursor、lock、cache、outbox、receiptを持ちます。

すべてのrootは正規化後も別で、重なりません。team projection、cursor、outbox、writer identityは各machineのruntimeに置きます。チームeventやruleをHostごとに複製しません。

## セットアップと更新

セットアップは、知識モードを確認し、read-only計画を表示してから1つのtransactionで適用します。`local`、`github-new`、`github-existing` を選べます。作業CLIは1件以上、整理AIは1件だけです。`test-compatible-cli` のような互換profileはruntimeにだけ複製し、元profileの場所や実行時の検出結果をmanifestへ保存しません。

再実行とupdateは差分更新です。個人のevent、pattern、identity、hashを削除・初期化しません。差分がなければ `ALREADY_CURRENT` の非破壊no-opです。Hostを削除してもHost限定patternは保持し、別Hostには表示しません。Host IDを再登録すると、同じ適用範囲のpatternを取得できます。

## 実行の流れ

```text
作業CLI
  -> Hook / context
     -> 個人projectionと任意のteam projectionから範囲付きrecall
  -> sanitized observation
     -> append-only event
        -> deduplicate / cluster / reconcile / project
           -> candidate / active pattern / revision / deprecation
  -> maintenance
     -> 選択済みの整理AIを1件だけ呼ぶ
        -> queue transition / changeset / projection
```

Hookは短時間の処理だけを行い、候補の重い整理はmaintenanceに渡します。整理AIが利用不能またはquota超過なら、新規候補を `DEFERRED` としてqueueと参照を保持します。別providerへ自動切替しません。整理AIの停止は既存patternのrecallを止めません。

## 適用範囲と取得

Hookで受けたsource Host IDと `host_family` はevent、candidate、patternまで保持します。patternの範囲は次のいずれかです。

- `universal`: すべての公開対応CLI。
- `family`: 同じfamilyだけ。例は `gemini-compatible` です。
- `host`: 指定Host IDだけ。

recallは範囲を候補スコアより先に判定します。Host限定patternが別Hostに表示されることはありません。既存のactive patternは整理AIなしで取得できます。個人とteamの候補は同じcontext上限で統合し、teamを無効にするとteam filesystem/provider/prompt/queue/projection/metricを読みません。

## Host profile

公開対応Hostは `codex-cli`、`claude-code`、`gemini-cli`、`qwen-code` です。公開する互換profileの例は架空の `test-compatible-cli` だけです。`adapter_id` は既存の公開familyの形式を再利用し、`host_id` は取得元とreceiptのidentityとして維持します。adapterの再利用だけでは互換性を自動保証しないため、`check-only`、`doctor`、実機receiptを個別に確認します。

## 個人・チーム・providerの停止

teamが未設定なら `DISABLED` で、team保存先を読みません。team保存先が停止中ならteamだけ `DEFERRED` となり、個人の取得と整理は続きます。整理AIが停止中なら、新規候補は `DEFERRED`、既存記憶のrecallは成功です。

チームは任意の追加境界であり、Hostごとのコピーではありません。外部の共有保存先、transport、ACL、providerの到達性はこのランタイムの成功状態と別に判定します。

## 状態の境界

`SETUP_COMPLETE` はソフトウェア設定の完了、`HOST_ACTIVATION_VERIFIED` は実機Hook/Skill receipt、`PRODUCTION_COMPLETE` は必要な運用証拠、`EFFECT_VALIDATED` は事前に決めた効果検証の完了です。後の状態を前の状態から推測しません。証拠がない場合は `UNVERIFIED` として残します。
