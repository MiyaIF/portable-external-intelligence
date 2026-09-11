# CLI互換性

公開対応はCLIエージェントです。1つの外部知能を、複数の作業・記憶取得CLIから共有します。整理AIは1件だけを選び、CLIの数に応じて増えません。

## 公開Host ID

| Host ID | lifecycle event | context / Skill | capture |
|---|---|---|---|
| `codex-cli` | `SessionStart`、`UserPromptSubmit`、`Stop`、`SessionEnd` | `AGENTS.md` とSkill root | `AUTO_ALLOWED` |
| `claude-code` | `SessionStart`、`UserPromptSubmit`、`Stop`、`SessionEnd` | `CLAUDE.md` とSkill root | `AUTO_ALLOWED` |
| `gemini-cli` | `SessionStart`、`BeforeAgent`、`AfterAgent`、`SessionEnd` | `GEMINI.md` とSkill root | `CONSENT_REQUIRED` |
| `qwen-code` | `SessionStart`、`UserPromptSubmit`、`Stop`、`SessionEnd` | `QWEN.md` とSkill root | `AUTO_ALLOWED` |

これはadapterと設定の対応表です。ファイルが置けたことだけではHook発火やSkill利用を意味しません。実機の対象CLIがreceiptを出して初めて `HOST_ACTIVATION_VERIFIED` とします。確認できない組み合わせは `not supported` または `UNVERIFIED` です。

## 互換CLI profile

公開adapter familyを再利用する互換CLIは、固有Host IDを持つprofileとして扱います。公開例は架空の `test-compatible-cli` だけです。

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

`adapter_id` はイベント形式の再利用先、`host_id` は取得元とreceiptの固有 identityです。profileはruntimeだけに複製し、元profileの場所や実行時検出結果を公開manifestに保存しません。互換性は自動保証されないため、`check-only`、`doctor`、実機receiptを分けて確認します。

## 適用範囲

patternの適用範囲は次の3つです。

- `universal`: すべての公開対応CLI。
- `family`: `host_family` が一致するCLI（例: `gemini-compatible`）。
- `host`: 記録されたHost IDだけ。

Hookからpatternまで、source host IDとfamilyを保持します。recallでは範囲をスコア計算より前に判定するため、Host限定patternは別Hostに表示されません。Hostを削除してもeventとpatternは個人ナレッジに保持し、同じHost IDの再登録時だけ範囲内で取得します。

## OSと証拠

実機確認のOS profileは Windows 10、Windows 11、対応中のmacOS、Ubuntu 24.04、Debian 12です。公開対応CLIとOSの組み合わせごとに、対象CLIのversion、lifecycle event、Hook状態、Skill検出、receiptを確認します。

`fixture` はsanitizedな契約テスト、`real_host` は対象revisionに結び付いた実機receipt、`production` は運用・復旧を含む証拠です。fixtureやCIの結果から `PRODUCTION_COMPLETE` や `EFFECT_VALIDATED` を推測しません。

## 利用不能時

HookやSkillの機能が足りない場合は、captureを `UNAVAILABLE`、`CONSENT_REQUIRED`、`DEFERRED`、`UNVERIFIED` のいずれかで返します。整理AIが停止しても新規候補だけが `DEFERRED` になり、既存patternのrecallは続きます。別の整理AIへ自動切替しません。
