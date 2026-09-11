# Support

このプロジェクトは CLI agent の外側に private knowledge と local runtime を置くための、自己管理型のツールです。

## まず確認すること

1. `docs/setup.md` で3つのroot（public engine、private knowledge、local runtime）が分離されているか確認する。
2. `setup --check-only` と `doctor --strict` の出力を確認する。
3. Hook の公式 trust/consent、特に provider 側の同意状態をファイル存在だけで推測しない。
4. runtime、queue、spool、cache、logs、SQLite、credentials が Git 管理対象に入っていないか確認する。
5. sync、migration、scheduler、purge、rollback は対象と receipt を確認してから実行する。

## Issue と security report

再現可能な一般バグは GitHub Issue、改善提案は Feature Issue、脆弱性は `SECURITY.md` の Private Vulnerability Reporting を使用してください。
公開 Issue には秘密情報、絶対パス、raw transcript、client data を書かないでください。

サポート、レビュー、merge には固定の response SLA や保証はありません。利用者環境のCLIバージョン、OS、再現手順、サニタイズ済みエラーコードを添えてください。
