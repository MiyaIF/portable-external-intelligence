# 単一外部知能・複数CLI設計

- Status: Approved for implementation
- Approved: 2026-09-08
- Scope: セットアップ、Hook、記憶整理、取得、更新、互換CLIプロファイル

## 1. 決定

利用者ごとの外部知能は、使用するCLIの数にかかわらず論理的に1つとする。
個人ナレッジと任意のチームナレッジは既存の知識スコープとして維持し、CLIごとの知識リポジトリは作らない。

セットアップでは、次の2項目を独立して選択する。

1. 記憶整理担当AIを必ず1つ選択する。
2. 作業・記憶取得CLIを1つ以上選択し、複数選択を許可する。

記憶整理担当AIは、作業・記憶取得CLIに含まれていても、含まれていなくてもよい。

## 2. 目的

- 複数CLIで同じ思考コストを相続する。
- 同一候補をCLIごとに重複整理せず、推論とトークン消費を1回に抑える。
- CLI固有のコマンドや制約を別CLIへ誤適用しない。
- 記憶整理担当AIの障害が通常作業と既存記憶の取得を止めない。
- CLIの追加、削除、切替、互換CLI導入時も既存ナレッジを保持する。

## 3. 対象外

- CLIごとの独立した外部知能を作ること。
- 複数の記憶整理担当AIによる合議、投票、並列整理。
- 障害時に別の記憶整理担当AIへ自動切替すること。
- 任意のPythonコードを読み込む外部プラグイン機構。
- 互換性のない独自CLIを設定だけで対応させること。

## 4. 用語

| 用語 | 定義 |
|---|---|
| 外部知能 | 個人ナレッジと、設定時のみ参照するチームナレッジを統合して取得する1つの論理的な知識面 |
| 記憶整理担当AI | 候補の継承判定、重複排除、適用範囲決定、ChangeSet生成を単独で担当する推論Provider |
| 作業Host | 作業イベントの取得と既存記憶の注入を行うCLIインスタンス |
| Host ID | CLI製品または互換カスタムCLIを一意に識別するID |
| Host family | 互換Hook・操作体系を共有するCLI群。例: `gemini-compatible` |
| 適用範囲 | 記憶を全CLI、同一family、特定Hostのどこまで注入できるかを示す境界 |

## 5. セットアップ契約

### 5.1 対話の基本

対話形式のセットアップは、最初に役割の違いを次の文面で説明する。

```text
外部知能をセットアップします。

外部知能は1つです。複数のCLIを選んでも、CLIごとに別の記憶は作りません。
ここでは次の2つを決めます。

1. 記憶整理担当AI
   作業後に得た候補から、今後も再利用する知識を選び、整理するAIです。
   1つだけ選びます。

2. 作業・記憶取得CLI
   普段の作業で記憶を蓄積し、必要な記憶を受け取るCLIです。
   実際に使うものを1つ以上選びます。複数選択できます。

同じCLIを両方に選んでも、別々のCLIを選んでも構いません。
```

表示名は `Codex CLI` のような利用者向け名称を使用する。`provider_id`、`host_id`、Adapter名などの内部識別子は通常の対話には表示せず、詳細表示またはJSON出力だけに含める。

### 5.2 記憶整理担当AIの選択

選択前に役割と判断基準を表示する。

```text
[1/2] 記憶整理担当AIを1つ選んでください。

このAIは通常作業を代行するのではなく、保存候補を整理する時だけ使います。
ローカルAIは候補をPC外へ送信しませんが、利用可能なローカルモデルが必要です。
CLIのAIを選ぶ場合は、そのCLIの認証と利用枠を使います。

  1. Codex CLI      [利用可能]
  2. Gemini CLI     [利用可能]
  3. Qwen Code      [未検出]
  4. Claude Code    [未検出]
  5. ローカルAI     [未設定]

選択例: 1
> 1
```

- 実際の選択肢は、サポート対象かつ登録済みのProviderから生成する。
- 各選択肢に `利用可能`、`要認証`、`未検出`、`未設定` のいずれかを表示する。
- 現時点で選べない項目には、その場で必要な対応を1文で表示し、選択を確定しない。
- 選択後は `記憶整理担当AI: Codex CLI` のように利用者向け名称で復唱する。
- 整理担当設定は必ず1つだけ保存する。Providerの優先順位リストや暗黙のフォールバックは使用しない。
- CLI認証情報、APIキー、Cookie、トークンは設定・manifest・ナレッジへ保存しない。

### 5.3 作業・記憶取得CLIの選択

選択前に、複数選択の効果と非選択時の扱いを表示する。

```text
[2/2] 作業・記憶取得に使うCLIを選んでください。複数選択できます。

選んだCLIでは、作業から保存候補を取得し、関係する既存記憶を利用できます。
複数選んでも外部知能は1つのままです。
選ばなかったCLIの設定は変更しません。

  1. Codex CLI      [検出済み]
  2. Gemini CLI     [検出済み]
  3. Qwen Code      [未検出]
  4. Claude Code    [未検出]
  5. 互換カスタムCLIを追加

複数選択例: 1,2
> 1,2
```

- 実際の選択肢には、検出済みのサポート対象CLIと登録済み互換プロファイルだけを選択可能な状態で表示する。
- 未検出CLIを選んだ場合は、検出できなかった事実と確認対象を表示し、黙って除外しない。
- `互換カスタムCLIを追加` では、互換元となる公開CLI、利用者向け表示名、実行コマンド、設定ファイルの場所を順に尋ねる。各質問には一般化した入力例を付け、入力値はこのPCのmachine-local設定だけに保存されると明示する。
- 作業Hostは順序に意味を持たない集合として1つ以上保存する。
- 同一マシンのすべての作業Hostは、同じ個人ナレッジrootとmachine-local runtimeへ接続する。別マシンでは各マシン固有のruntimeを使用し、既存の安全な同期契約を通じて同じ個人ナレッジを共有する。
- チームナレッジは既存どおり任意であり、作業Hostごとには分けない。
- 各HostのHook、コンテキスト、Skill、実行ファイル、homeは個別に検証する。

### 5.4 適用前の確認

新規セットアップか更新かを明示し、変更内容を適用前に復唱する。

```text
設定内容を確認してください。

  外部知能:          1つ（既存ナレッジを共用）
  記憶整理担当AI:    Codex CLI
  作業・記憶取得CLI: Codex CLI, Gemini CLI
  実行内容:          既存設定の更新
  ナレッジ:          削除・初期化しない

この内容を適用しますか？ [Y/n]
```

- 初回は `新規セットアップ`、既存manifestがある場合は `既存設定の更新` と表示する。
- 再実行時は追加、削除、変更、変更なしを項目別に表示する。同じ選択なら `変更なし` としてナレッジも設定も書き換えない。
- 1つのHostの設定失敗は、未変更のHost設定とナレッジを巻き戻さない。セットアップ全体の適用前失敗ではトランザクションを中止し、既存状態を維持する。
- 確定前のキャンセルでは何も変更しない。

### 5.5 保存形式

対話で確定した内容は、内部的に次のように保存する。

```json
{
  "organizer": {
    "provider_id": "subscription-cli",
    "host_id": "codex-cli"
  },
  "work_hosts": [
    {"host_id": "codex-cli", "host_family": "codex-compatible"},
    {"host_id": "gemini-cli", "host_family": "gemini-compatible"}
  ]
}
```

- `provider_id` は必須で、登録済みProviderを1つ指定する。
- `provider_id=subscription-cli` の場合だけ `host_id` を必須とする。
- ローカルHTTPまたはOllamaのようにHostを持たないProviderでは `host_id` を保存しない。

### 5.6 非対話CLI引数

実装後の正規CLI入力は次の形とする。

```text
--organizer-provider <provider-id>
--organizer-host <host-id>        # subscription-cliの場合だけ必須
--work-host <host-id>             # 1回以上、繰り返し可能
--host-profile <json-path>        # 互換派生CLIを使う場合のみ繰り返し可能
```

既存の `--hosts` は移行期間中、`--work-host` の別名として解釈する。`--providers` に複数値がある既存manifestは自動で先頭を確定せず、更新計画を `ORGANIZER_SELECTION_REQUIRED` として提示し、明示承認まで新規整理を延期する。

## 6. 互換カスタムCLIプロファイル

公開CLIを基礎とし、Hook仕様を変更していない互換カスタムCLIは、固有Host IDを保持したまま既存Adapterを再利用できるようにする。公開仕様とサンプルには、実在する組織内CLIの名称、実行ファイル名、固有パス、設定内容を記載しない。

```json
{
  "schema_version": 1,
  "host_id": "<custom-host-id>",
  "display_name": "<display-name>",
  "host_family": "gemini-compatible",
  "adapter_id": "gemini-cli",
  "executable_names": ["<command-name>"],
  "hook_config_path": "<relative-hook-config-path>",
  "global_context_path": "<relative-context-path>",
  "skill_roots": ["<relative-skill-root>"]
}
```

- `adapter_id` は組み込み済みAdapterのallowlistからのみ選べる。
- 実値を含む互換プロファイルと検出結果はmachine-local runtimeへ置き、公開engineリポジトリやGit追跡対象へコピーしない。
- 公開engineリポジトリには、プレースホルダーだけのスキーマとテンプレートを置く。
- プロファイルから実行コード、任意コマンドテンプレート、環境変数値を注入できない。
- `host_id`、`host_family`、相対パス、実行ファイル名は厳格なスキーマで検証する。
- 派生CLIのイベント名、payload、応答形式がAdapter契約と一致しない場合は `HOST_ADAPTER_INCOMPATIBLE` とし、新しい組み込みAdapterを要求する。
- 派生CLIを基礎となった公式CLIとして認証しない。実機canaryとreceiptは派生CLI固有のHost IDへ結び付ける。

## 7. 記憶データ契約

すべての候補、観測、整理結果は取得元を示す次のフィールドを持つ。

```json
{
  "source_host_id": "<custom-host-id>",
  "source_host_family": "gemini-compatible",
  "applicability_scope": "family",
  "applicable_host_ids": [],
  "applicable_host_families": ["gemini-compatible"]
}
```

`applicability_scope` は次の3値だけを許可する。

| 値 | 注入先 | ID制約 |
|---|---|---|
| `universal` | すべての作業Host | Host ID・family配列は空 |
| `family` | 指定familyのHost | family配列が1件以上、Host ID配列は空 |
| `host` | 指定Hostのみ | Host ID配列が1件以上、family配列は空 |

記憶整理担当AIが適用範囲を返さない、または矛盾した値を返した場合は、取得元Hostだけを対象とする `host` へ安全側に固定する。CLI名、コマンド、Hook、設定パス、CLI固有機能を含む候補は、明示的な検証なしに `universal` へ昇格させない。

## 8. データフロー

1. 作業HostのHookがイベントを正規化し、`source_host_id` と `source_host_family` を付ける。
2. append-onlyイベントとmachine-local queueへ候補を1回記録する。
3. 冪等性キーにより、同一イベントの再送や複数Hook経路による重複整理を防ぐ。
4. 選択済みの記憶整理担当AIだけが継承判定とChangeSet生成を行う。
5. 決定論的バリデータがprivacy、証拠hash、適用範囲、既知Host/family、ライフサイクルを検証する。
6. 決定論的検証を通過したChangeSetを1つの外部知能へappendする。
7. 記憶取得時は `universal + 現在のfamily + 現在のHost` を候補とし、既存のdomain、version、scope、score、件数・文字数上限で絞る。
8. 個人・チームに同一clusterがある場合は既存のマージ規則で重複排除する。

## 9. 障害契約

### 9.1 記憶整理担当AIが利用不能

- quota、rate limit、認証利用不能、Provider利用不能、timeoutでは、新しい整理処理だけを `DEFERRED` にする。
- schema不正または応答不正では `FAILED_RETRYABLE` とし、候補を保持して同じ整理担当AIで再試行する。設定済み上限を超えた場合は `FAILED_NEEDS_ATTENTION` とし、自動切替や候補破棄を行わない。
- 候補と再試行情報はmachine-local queueへ保持する。
- 別AIへ自動切替しない。
- 既存記憶の取得、通常作業、他HostのHook処理を継続する。
- 復旧後のmaintenanceが同じ冪等性キーで再開する。
- 認証失敗、quota、timeout、schema不正を意味上のNOとして保存しない。

### 9.2 作業Hostが利用不能

- 該当Hostだけを `UNAVAILABLE` または `CONSENT_REQUIRED` とする。
- 他の作業Host、整理担当AI、ナレッジを停止しない。
- インストール済みファイルだけで有効と判定せず、Hostごとのcanaryとreceiptを要求する。

### 9.3 チームナレッジが利用不能

- 既存どおりチーム側だけを `DEFERRED` にする。
- 個人ナレッジからの取得と個人側の蓄積を継続する。

## 10. 更新・削除契約

- 作業Host追加時は、そのHostの管理対象だけを追加する。
- 作業Host削除時は、そのHostのHook、管理コンテキスト、Skill bindingだけを削除対象とし、過去のイベント・記憶は削除しない。
- 削除済みHost固有の記憶は保持し、同じHost IDが再登録されるまで通常取得から除外する。
- 整理担当AI変更はupdateの明示差分として表示し、承認後のみ適用する。
- 整理担当AI変更後、未処理候補は新担当が処理できる。ChangeSetには実際に処理したProvider IDを記録する。
- updateの再実行は冪等とし、同一選択なら設定・ナレッジを変更しない。
- engine、personal、team、runtimeのroot分離と既存ナレッジ保持契約を変更しない。

## 11. トークン・推論コスト契約

- 1候補につき整理担当AIへの意味判定は1回とする。再試行は失敗状態からのみ行う。
- 作業Host数に比例して同じ候補を再整理しない。
- 取得時は適用範囲フィルタをscore計算より前に行う。
- 既存の `max_results`、`max_chars`、Hook deadlineをHostごとに適用する。
- 適用対象外のCLI固有知識をコンテキストへ含めない。

## 12. セキュリティ・プライバシー

- raw prompt、raw response、transcript、tool output、資格情報をナレッジへ保存しない。
- Host IDとfamilyは安全な識別子へ正規化し、個人PCの絶対パスをナレッジへ保存しない。
- 互換カスタムCLIの名称、コマンド、固有パス、検出結果を公開engineリポジトリへ保存しない。
- 互換プロファイルはデータのみとし、任意コード実行を許可しない。
- 記憶整理担当AIへ渡す内容は、既存のサイズ上限・privacy分類・スキーマ検証を通過した候補だけとする。
- 個人・チーム・runtime・公開engineの境界を維持する。

## 13. 完了条件

実装完了は次をすべて満たした場合に限る。

1. 新規セットアップで整理担当AIが1つ、作業Hostが1つ以上なければ適用できない。
2. 複数作業Hostが同じ外部知能へ接続し、CLIごとのナレッジrootを作らない。
3. 同一候補が作業Host数にかかわらず1回だけ整理される。
4. `universal`、`family`、`host` の取得境界が一致・不一致ケースで検証される。
5. Hook互換カスタムCLIのプロファイルが基礎CLIのAdapterを再利用しつつ、固有Host IDで記録される。
6. 不正プロファイル、未知Adapter、任意コード・資格情報を含む入力がfail-closedになる。
7. 整理担当AIのquota、timeout、認証失敗時に整理だけが `DEFERRED` となり、既存取得が成功する。
8. 作業Hostの追加・削除・再追加と整理担当変更で既存ナレッジのtree hashが保持される。
9. setup/update/doctor/status/uninstallが複数Hostを個別表示し、別Hostのreceiptを流用しない。
10. Windows、macOS、Linux向けの設定生成とコマンドquotingテストが通る。
11. 対象テスト、完全release validation、production source audit、public tree audit、secret scanが成功する。

## 14. 実装単位

実装計画は次の順序で分割する。

1. manifest・設定・CLI引数の契約と既存manifest移行。
2. Host profile、Host family、互換Adapter再利用。
3. イベント・候補・ChangeSetへの取得元と適用範囲追加。
4. 取得フィルタとコンテキスト生成。
5. 単一整理担当Providerと `DEFERRED` 再試行。
6. setup/update/doctor/status/uninstallの複数Hostライフサイクル。
7. 統合・互換性・公開監査とドキュメント更新。
