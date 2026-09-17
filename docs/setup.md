# セットアップ

このセットアップは、1つの外部知能、1つの整理AI、複数の作業・記憶取得CLIを登録する1回の操作です。外部知能は個人ナレッジと取得設定をまとめた論理的な知識面、整理AIは候補を整理するprovider、作業・記憶取得CLIはその知識面を使う入口です。CLIを複数選んでも、整理AIは1件だけです。

作業CLIの選択欄では、`1`（1件）または `1,2`（2件）のように入力します。公開対応CLIは `codex-cli`、`claude-code`、`gemini-cli`、`qwen-code` です。作業CLIと整理用Hostは別にできます。

## 前提

- GitとPython 3.11以降（venv/ensurepipを含む）。OS別のsetupが確認し、不足時は承認を得て導入します。
- 実機の確認をするCLIは、あらかじめインストール済みであること。
- `local` 以外では、対象の非公開保存先を操作できる認証済みクライアント。
- 公開エンジン、個人ナレッジ、機械ローカルruntimeの3つが重ならないこと。チームを使う場合は共有保存先も別にします。

セットアップで使う各保存先は、正規化後も互いに重なりません。`--skip-venv` は、管理済みのPython環境で `ei` がすでに読み込める場合だけ使います。

## Git・PythonがないPCから始める

Gitがない場合はGitHubの **Code → Download ZIP** で公開エンジンを取得し、展開したフォルダでsetupを実行してください。Pythonを使わないPowerShell／シェルの前処理が、依存ソフトの有無と実行可否を確認します。

| OS | 使用する導入方法 | 対象 |
|---|---|---|
| Windows | 既存のWinGet。利用できない場合は公式インストーラーを案内 | `Git.Git`、`Python.Python.3.13` の不足分 |
| macOS | AppleのCommand Line ToolsとPython公式インストーラー | Git、Pythonの不足分。Homebrewは使用・追加導入しない |
| Linux | apt-get または dnf | `git`、`python3`、apt-getでは `python3-venv` の不足分 |

導入前にパッケージ名と導入方法を表示し、`y` または `yes` と答えた場合だけ実行します。初期値は「導入しない」です。インストーラーの利用規約や管理者確認は省略せず、setupが代理承認することもありません。HomebrewやWinGet自体を追加導入したり、社内PCの制限を回避したりはしません。利用可能な導入手段がない場合は公式の手動導入先を案内して停止します。

macOSのGit不足時は、承認後に `xcode-select --install` でAppleの導入画面を開きます。Command Line ToolsにはGit以外のコンパイラやSDKも含まれるため、承認前に説明します。Xcode本体は要求しません。導入完了後にsetupへ戻りEnterを押すと、実際にGitが使えることを確認します。画面を中断した場合やまだ導入中の場合は、Pythonの追加導入やエンジンの構築に進みません。

macOSのPython不足時は、`python.org` の公式Python 3.13.15パッケージを一時フォルダへ取得します。公式リリースに掲載されたSHA-256との一致、パッケージ署名、macOSのインストール審査を確認してから、標準インストーラーを開きます。バージョンとハッシュはsetupのソースに固定し、ダウンロード時に「最新版」へ勝手に切り替えません。更新時は公式リリースを再確認して両方を更新します。利用者が導入内容・利用規約・管理者確認に対応し、公式手順の `Install Certificates.command` も実行してください。インストーラーを終了するとsetupに戻ります。Enterを押しただけでは成功にせず、Python・venv・ensurepipの実行可否を再確認します。一時パッケージはインストーラーの終了後に削除します。起動・待機が中断されて終了を確認できない場合は保持し、場所を表示します。Installerを終了した後で手動削除できます。

導入済みで利用可能なGit・Pythonは再インストールしません。対応していないPythonを削除することもありません。導入失敗・拒否・導入後の再確認失敗では、エンジンの構築に進みません。途中まで導入できたソフトは保持し、原因を解消してsetupを再実行すると再検出します。新しいターミナルが必要な場合も、その旨を案内します。OS標準リポジトリでPython 3.11以降を提供していない環境は手動導入が必要です。

既にHomebrew等で導入したGit・Pythonも、実行可能ならそのまま利用します。導入元を理由に置き換えたり、既存の管理ソフトを削除したりしません。Linuxの自動導入は既存のapt-get・dnfに対応し、それ以外の環境では標準の導入手順を案内します。追加のパッケージ管理ソフトや外部リポジトリは登録しません。

確認だけの `-CheckOnly` / `--check-only` は、導入承認フラグがあってもインストールしません。非対話は既定で自動導入を禁止します。自動化で明示的に許可する場合だけ `-InstallPrerequisites`（PowerShell）／`--install-prerequisites`（sh）を指定してください。`-AcceptPlan` / `--accept-plan` はエンジン設定への同意であり、Git・Python導入への同意には流用しません。非対話で管理者確認や規約確認が必要になった場合は停止するため、対話実行または管理者による事前導入が必要です。

macOSの新規導入にはGUIの操作が必要なため、`--install-prerequisites` を指定しても非対話ではインストーラーを起動しません。対話端末で実行するか、Git・Pythonを事前導入してください。既に必要なソフトが使える場合は非対話setupを続行できます。`--check-only` ではAppleのGit・Pythonの案内用コマンドから導入画面が開かないように確認します。

これらの導入フラグはOS別setupラッパー専用です。Pythonで動く `ei setup` 自体にPythonを導入させるものではありません。Windowsでスクリプト実行が組織のポリシーにより禁止されている場合は管理者に確認してください。setupは実行ポリシーを変更しません。

参照: [WinGet公式の導入コマンド](https://learn.microsoft.com/en-us/windows/package-manager/winget/install)、[Git公式のmacOS導入方法](https://git-scm.com/install/mac)、[Apple公式のCommand Line Tools説明](https://developer.apple.com/library/archive/technotes/tn2339/_index.html)、[Python公式のmacOS導入手順](https://docs.python.org/3/using/mac.html)、[Python 3.13.15の配布元・SHA-256](https://www.python.org/downloads/release/python-31315/)。

## ラッパーと確認

公開エンジンのルートから、OSに合うラッパーを実行します。

```text
scripts/setup.ps1
sh scripts/setup.sh
```

通常の対話画面では、整理AI、整理用Host、作業CLI、個人ナレッジ、任意のチーム保存先、Git同期、定期整理を選びます。Host homeやSkill配置の変更は対応する引数でも指定できます。画面の計画を確認してから適用します。エンジン設定の適用を拒否した場合、ナレッジ保存先は変更しません。前段で別途承認して導入したGit・Pythonは残ります。

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
- 定期整理: `--scheduler` / `--no-scheduler`（PowerShellでは `-Scheduler` / `-NoScheduler`）。通常対話で省略した場合は有効・無効を質問し、再実行では以前の選択を初期値にします。
- Git同期: `--sync` / `--no-sync`。ローカルでの蓄積・整理とは独立した選択です。

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

設定を適用すると、各作業CLIのHook承認手順と定期処理の状態を表示します。Hookは任意コマンドを実行する機能なので、利用者が内容を確認してCLI側で承認してください。setupは信頼設定を変更したり、承認を迂回したりしません。Codex CLIの場合は `/hooks`、Claude Codeの場合は `/hooks`、Gemini CLIの場合は `/hooks list` が確認の入口です。互換CLIはそのCLI自身の手順に従います。Codex App自体は対応対象に含めません。

承認後、対象CLIで新しいセッションを開き、機密情報を含まない短い依頼を1回送り、応答後に終了してください。setupの確認画面で `r` を入力すると、実際のHook受信記録とOS側の定期処理の状態を再取得します。「承認した」と入力しただけでは確認済みにしません。Enterで後回しにでき、同一設定の再実行時も状態を取り直します。

JSON出力の `activation.hooks` は `VERIFIED` / `UNVERIFIED`、`activation.maintenance.status` は `ENABLED` / `DISABLED` / `UNVERIFIED` です。`ENABLED` はOSの登録・有効状態の確認であり、長時間の稼働実績ではありません。Windowsで手動停止されたタスクは正常扱いしません。同じ設定のsetupを繰り返しても、手動停止した同一定義のタスクを自動再開するものではありません。OSのタスク管理画面で停止理由・実行結果を確認してください。

`activation.automatic_operation=UNVERIFIED` は、setupが「作業→蓄積→整理→次回取得」までの実運用テストを代行していないことを示します。既存の `SETUP_COMPLETE` とは区別します。定期処理の登録だけ失敗した場合も、保持されたインストールについてHook案内と個別状態を表示し、エラーは成功に書き換えません。

`doctor --strict` でmanifest、profile、Skill binding、root分離を確認します。`status` で作業CLIごとのHook/Skill状態を確認し、`recall` は整理AIなしで既存patternを取得できます。初回の実機確認では、対象CLIのHook同意とSkill検出を行い、receiptを保存します。

詳細な引数は [CLIリファレンス](cli-reference.md)、更新は [update.md](update.md)、削除は [uninstall.md](uninstall.md) を参照してください。
