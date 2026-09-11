# 更新

`update` は、公開エンジンの管理対象とruntime manifestを更新します。外部知能は1つ、整理AIは1つ、作業・記憶取得CLIは1件以上という選択を保ったまま、必要な差分だけを適用します。

## 対象と保持境界

更新するのは、管理対象のcontext、Hook設定、Skill、binding、manifest、runtime設定です。個人ナレッジのevent、pattern、projection、writer identity、個人保存先のidentityとhashは削除・初期化しません。チームを設定している場合も、共有event、member/writerのidentity、team descriptorは保持します。

同じ保存先を指定し、Hostを追加・削除・再登録しても、残った管理対象だけを変更します。削除したHostのhost限定patternは個人ナレッジに保持され、ほかのHostのrecallには表示されません。同じHost IDを再登録すると、適用範囲が合う既存patternを取得できます。

## 実行前の確認

`--check-only` はread-onlyの計画を返します。計画には、選択した整理AI、整理用Host、作業CLI、profile、変更対象、既存hash、backup、rollback範囲が含まれます。適用時は `--json` で結果を保存できます。`--target-ref` は対象revisionを検証するだけで、branchのcheckoutや未保存変更の破棄はしません。

root、remote、team identityを変える更新は自動で切り替えません。個人remoteの変更は `MIGRATION_REQUIRED`、runtimeとmanifestのidentity不一致は `ACTIVE_RUNTIME_MISMATCH` です。管理対象を利用者が変更している場合は `MANAGED_TARGET_CONFLICT` として、変更を上書きせず止まります。

## 整理AIの切り替え

整理AIは常に1件です。`subscription-cli` を使う場合は `organizer_host` として選んだHostだけを使います。既存のproviderへ自動フォールバックせず、選択した整理AIが利用できないときは新規候補を `DEFERRED` としてqueueに残します。停止中でも、すでにactiveなpatternのrecallは成功します。

選択の入力例は、作業CLIを1件選ぶ `1` と、2件選ぶ `1,2` です。既存manifestの設定を使う更新では、整理AIを暗黙に先頭から選びません。

## 互換CLIの更新

公開adapter familyを使う互換CLIは、架空の `test-compatible-cli` profileで登録します。profileはruntimeだけに複製され、元profileの場所や実行時検出結果はmanifestに保存されません。更新ではprofileのhashとHost IDを照合し、内容が変わったときだけ管理対象を差し替えます。互換性は自動保証されないため、`check-only` と `doctor` の結果、および実機receiptを別々に確認します。

```json
{
  "host_id": "test-compatible-cli",
  "host_family": "gemini-compatible",
  "adapter_id": "gemini-cli"
}
```

## チームの扱い

チームナレッジは任意です。Hostを増やしても、チームeventやruleをHostごとに複製しません。team projection、cursor、outbox、writer identityは各machineのruntimeに置き、個人projectionとは分けます。team optionsを省略する（`omitting`）更新では既存選択を保持します。`--no-team-knowledge` を明示した場合だけ無効にします。

共有保存先が一時的に使えないときは、team statusが `DEFERRED`、reason codeが `TEAM_STORE_VALIDATION_DEFERRED` になります。個人の更新と既存記憶の取得は継続します。teamを無効にした更新では、team filesystem/provider/prompt/queue/projection/metricを読みません。

## 結果の読み方

- `SETUP_COMPLETE` は管理対象の更新とdiagnosticsが完了した状態です。
- `ALREADY_CURRENT` は差分なしの非破壊no-opです。
- `DEFERRED` は後で再試行する状態で、既存記憶が利用不能という意味ではありません。
- `MIGRATION_REQUIRED`、`MANAGED_TARGET_CONFLICT`、`ACTIVE_RUNTIME_MISMATCH` は、選択または所有状態を確認してから再実行します。
- `UNVERIFIED` は、実機のHook発火、外部同期、ACL、provider quotaなどをこの更新だけでは確認していない状態です。

更新が途中で停止しても、append-only eventとpatternは保持されます。計画とreceiptを確認して同じrootで再実行し、必要ならdoctorのrepair planを別途確認してください。
