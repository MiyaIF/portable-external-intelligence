# Release evidence

このディレクトリは、公開対象のコードと、公開可否を機械的に判定する最小限の証跡だけを管理します。
個人の作業履歴、raw transcript、プロンプト、応答、認証情報、runner の絶対パス、private host の詳細ログは置きません。

## Evidence の種類

- `fixture`: スキーマ、adapter、installer の契約確認。実環境の証明にはなりません。
- `hosted_contract`: GitHub-hosted runner 上の再現可能な契約確認。実際の利用者ホストの証明にはなりません。
- `real_host`: 非公開運用環境で exact public SHA を実行した実ホスト証跡。
- `activation`: 実際の Hook/Skill activation と canary の証跡。
- `rollback`: update、migration、uninstall からの復旧証跡。
- `ab`: 事前登録済みの効果測定証跡。

receipt は type と SHA256 だけを `receipt_index` に登録し、内容はそれぞれの契約で検証します。異なる type の receipt を相互に代用してはいけません。

## Status

`evidence-manifest.json` の status は生成処理が決めます。

- `awaiting_public_subject`: sanitized public root 未生成。
- `awaiting_post_push_attestation`: public subject はあるが、exact evidence commit と CI run が未結合。
- `verified`: exact evidence commit、全必須CI run、各 digest の整合性が確認済み。

`software_complete`、`production_enabled`、`effect_validated` は独立しています。`verified` だけで実運用や効果を意味しません。

A/B 効果証跡は、この不変 index の `index_sha256` と公開 subject SHA に
結び付く独立 sidecar です。index 自身の `effect_validated` は常に
`awaiting_sample` であり、最終 evaluator だけが sidecar を検証して状態を
引き上げます。

## 生成と検証

public root を作る前の候補を明示的に生成する場合:

~~~sh
python scripts/generate-release-evidence.py --output release/evidence-manifest.json --generated-at 2026-08-28T00:00:00Z
~~~

public root と各 digest が揃った後は、同じ生成器へ exact SHA と CI run を渡します。入力を省略した状態で pass へ昇格することはありません。

~~~sh
python scripts/verify-release-evidence.py --manifest release/evidence-manifest.json --status-only --json
~~~

post-push attestation は、公開リポジトリの protected `release` environment から固定パスの manifest と prerequisite document を検証して生成します。古い subject SHA、異なる branch の run、mutable な receipt、手編集した pass flag は受け付けません。

公開投入前は `scripts/audit-public-release.py`、依存ロック検証、workflow security verifier、package build、clean-clone acceptance を同じ public subject に対して再実行してください。
