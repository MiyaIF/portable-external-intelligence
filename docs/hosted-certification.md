# Hosted clean-clone certification

公開候補の exact commit は、GitHub-hosted runner 上で `certify-public-clone.py`
を実行します。これは provider API を呼ばず、合成された fixture だけで
CLI agent の契約を確認します。Codex App や有料 API の実行証跡にはなりません。

## 検証内容

各 job は開発者の home、credential、agent cache、Git global config を使わない
一時 clone と venv を作ります。次を順に確認します。

- hash 付き dependency lock の導入、wheel/sdist の build
- production source、public tree、workflow、依存関係の監査
- bounded complete test runner の inventory と実行結果
- Unicode/space path での `local` one-shot setup と四つの CLI host の導入
- fixture canary、recall、closeout、maintenance、doctor
- manifest からの doctor 復元、update/uninstall check-only、実 uninstall、
  one-shot setup による restore、root migration rollback、sync plan
- package hash、Git SHA、test 数、OS/Python、実行時間の path-free receipt

fixture receipt は `PUBLIC_RELEASE_READY` の clean-clone evidence に使えますが、
実際の host が Hook の consent を完了したことは示しません。実 host の
activation、scheduler、private Git sync、migration、rollback は private ops
側の hash-bound receipt が必要です。

## ローカル実行

作業ツリーを clean にしてから、source の外へ出力先を置きます。

```text
python -B scripts/certify-public-clone.py \
  --source . \
  --output ../certification-artifacts/public-clone-receipt.json \
  --offline-fixtures
```

実行には Python 3.11 以上と lock の package を取得できる環境が必要です。
ネットワークや package index が使えない場合、receipt を合格扱いにせず、CI の
hosted evidence を待ちます。

## CI matrix

public workflow は `ubuntu-latest`、`macos-latest`、`windows-latest` と Python
3.11、3.13 を matrix にします。各 receipt は source commit と tree に束縛され、
失敗、欠落、test inventory の差分があれば release gate を通しません。
