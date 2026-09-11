# Public release evidence completion report

## Current verdict

- `PUBLIC_SOURCE_READY`: awaiting sanitized fresh-root export and its validated receipt
- `PUBLIC_RELEASE_READY`: awaiting exact public-subject hosted validation
- `PRODUCTION_COMPLETE`: not claimed
- `EFFECT_VALIDATED`: awaiting_sample
- `evidence-manifest.json`: `status=awaiting_public_subject`

この report は、公開リポジトリの visibility 変更や GitHub への push を実行したことを意味しません。
公開対象の private development history と、公開用の fresh root evidence は分離します。

## Verified locally

- owner publication policy は Apache-2.0、Fiso、MiyaIF、GitHub noreply author、Issues/PR + DCO の決定値で検証済み。
- three-root boundary、knowledge repository、lossless migration/rollback、recursive privacy validation、safe filesystem、portable hooks、依存 lock、SBOM、workflow security の契約を実装済み。
- public workflow は GitHub-hosted runner のみを使用し、active `.github/workflows/` に self-hosted runner はありません。
- public workflow の action pin、permissions、timeout、concurrency、artifact retention、release input boundary を静的検証できます。
- `fixture` と `hosted_contract` は `real_host`、`activation`、`rollback`、`ab` の証拠を代替しません。
- `src/ei/public_export.py` と `scripts/create-public-export.py` は、allowlist限定・新規Git root・所有者identity・tree/history監査・再現性比較を実装済みです。
- `src/ei/github_publication.py` と `scripts/configure-public-github.py` は、read-only計画、plan digest確認、公開設定/ruleset計画、外部変更の明示的な適用境界、fresh clone検証を実装済みです。実際のGitHub作成・push・設定変更は未実行です。
- R19の独立ゲート評価器は、公開source、公開release、production、A/B effectを別々に判定し、対象security scanが報告した全findingのremediation、必須receipt、20 host/OS pair、ライフサイクル、事前登録A/B条件を同一subject SHAへ束縛します。

## 未確認・未達

- sanitized fresh-root の exact public subject SHA と、default validation済みの export receipt は未生成。
- exact public SHA に対する hosted CI run ID/conclusion、package/SBOM digest、public-tree audit digest の結合は未達。
- advertised CLI/OS pair の real host receipt、実 global Hook/Skill activation、scheduler、private Git sync、migration、rollback は未実行または未提出。
- 14日・各 arm 50件以上・power・provenance・missingness・contamination 条件を満たす A/B 結果は未取得。
- R19の実公開SHAに対する対象scan全findingのsecurity remediation、hosted CI/package/SBOM/scanner/clean-clone/publication receipt、20件のreal host/OS receipt、production lifecycle receiptは未取得。これらが揃うまで上位ゲートは未達です。
- 記事にある token/cache 数値は外部記事の記載であり、この環境の baseline や因果効果には使用しない。

## 再開手順

1. clean clone で公開 allowlist export を作り、tree/history を再監査する。
2. export の root SHA を subject として `scripts/generate-release-evidence.py` を実行する。
3. hosted CI の exact SHA run が揃った後、protected `release` environment の attestation workflow を実行する。
4. private certification は `ops-private-template/` を非公開運用リポジトリへ配置し、exact public SHA ごとに実ホスト receipt を作る。
5. production と A/B の証跡を別 type で取り込み、全 gate を独立に判定する。

失敗時は evidence を手編集して pass にせず、原因を修正して同じ subject/evidence 契約から再生成してください。
