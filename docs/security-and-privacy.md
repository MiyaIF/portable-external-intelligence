# セキュリティとプライバシー

このランタイムは、外部知能1つと個人ナレッジを複数の作業・記憶取得CLIで共有します。候補を整理するAIは1件だけです。CLIを増やしても、個人ナレッジや整理AIをHostごとに複製しません。

## 保存するデータ

公開エンジンにはcode、schema、policy、sanitizedな仕様だけを置きます。個人ナレッジにはappend-onlyのobservation、lifecycle event、pattern、範囲、hash、必要最小限のprovenanceを置きます。機械ローカルruntimeにはqueue、期限付きspool、cursor、cache、lock、receiptを置きます。

次のものはrawのまま保存・同期しません。

- prompt、query、応答、assistant message、tool output、transcript。
- credential、cookie、token、秘密鍵、SQLite、raw log。
- 顧客・取引先など個人や組織を特定する情報。
- 絶対path、machine/session/turn ID、未確認の外部データ。

入力はprivacy policy、サイズ、分類、source hash、適用範囲を検査します。違反は拒否、hash化、またはmachine-local quarantineとなり、個人・teamの共有eventへ流しません。

## 3つの役割の境界

- 外部知能: 個人ナレッジを統合してrecallする1つの論理的な知識面。
- 整理AI: queue内の候補を整理する1件のprovider。選択外providerを呼びません。
- 作業・記憶取得CLI: 同じ知識面を読む複数の入口。入力例は `1` と `1,2` です。

整理AIが停止、quota超過、認証待ちになった場合は、新規候補だけを `DEFERRED` としてqueueに保持します。自動フォールバックや候補破棄はしません。整理AIが停止中でも、既存のactive patternのrecallは成功します。

## 個人ナレッジとteam

個人ナレッジは常に個人の保存先に置きます。teamは任意で、未設定時は `DISABLED` です。teamを有効にしても、Hostごとにteam event、pattern、共有ruleを複製しません。共有eventのprojection、cursor、outbox、writer identityは各machineのruntimeにだけ置きます。

team保存先が停止中なら、team statusだけが `DEFERRED`、reason codeが `TEAM_STORE_VALIDATION_DEFERRED` になります。個人のrecall、capture、maintenanceは続けます。teamを無効にした操作では、team filesystem/provider/prompt/queue/projection/metricを読みません。

## Hostの適用範囲

取得元Host IDと `host_family` はeventからpatternまで保持します。patternの範囲は `universal`（全CLI）、`family`（同じfamily）、`host`（特定Host）です。範囲をスコア計算より先に判定するため、Host限定patternは別Hostに表示されません。

Hostを削除してもHost限定pattern、event、identity、hashは個人ナレッジに保持されます。削除中は他Hostに表示せず、同じHost IDを再登録した場合だけ範囲内で取得します。公開互換profileの例は架空の `test-compatible-cli` だけです。profileはruntimeへ複製し、元profileの場所や検出結果は公開manifestに記録しません。

## remoteと同期

個人ナレッジの同期は既定で無効です。同期を有効にする場合も、非公開であること、fingerprint、branch、履歴を確認できる保存先だけに限定します。公開・不明・別用途のremoteは停止します。teamの共有eventを個人remoteへpush/pullしません。

外部保存先のtransportやACLは別の管理境界です。ここで `SETUP_COMPLETE` になっても、外部同期、ACL、member distribution、provider到達性、実機Hook発火を意味しません。未確認は `UNVERIFIED` として残します。

team eventのhashは破損と衝突の検出用であり、書き込んだ個人を暗号学的に認証するものではありません。共有フォルダへ書き込める全アカウントをteam knowledgeの投稿者として信頼できるACLにしてください。この条件を満たせない場合はteamを無効のまま使います。

## Hook、Skill、profile

Hookはsanitized envelopeだけを受け取り、短い処理の後にappend-only eventへ渡します。Skill bindingは選択したengine、個人root、runtime、Python、Host IDを結び付けます。profileのadapter再利用は形式互換を示すだけで、CLIの動作を自動保証しません。`check-only`、`doctor`、実機receiptを個別に確認します。

管理対象の変更は所有hashを確認し、利用者が編集したファイルを上書きしません。範囲外のpath、raw payload、秘密情報をchangesetやreceiptへ書きません。派生projectionはeventから再構築できます。

## セットアップ、更新、削除

setupの再実行、update、既定のuninstallは非破壊です。個人・teamのevent、pattern、identity、hashを削除・初期化しません。Host削除はそのHostの管理対象だけに限定します。差分がなければ `ALREADY_CURRENT`、管理対象の解除後は `UNINSTALLED` と返します。

## 状態の独立性

`SETUP_COMPLETE`、`HOST_ACTIVATION_VERIFIED`、`PRODUCTION_COMPLETE`、`EFFECT_VALIDATED` は別の状態です。前の状態から後の状態を推測しません。整理AIや共有保存先の停止は `DEFERRED`、任意のteamを使わない状態は `DISABLED`、証拠がない実機状態は `UNVERIFIED` です。

脆弱性の報告では、秘密や個人・組織情報を含めず、公開issueではなく非公開の報告経路を使ってください。
