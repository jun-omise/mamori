# mamori(守り)

**mamori** は、あなたが使っているコードと、いま使っている PC の脆弱性を調べる、**読むだけ**のスキャナです。
macOS・Windows・Linux で1つのファイルとして動き、ロックファイルを手元か GitHub から直接読みます。
結果は必ず3つに分けて出します:**何を調べたか・何が問題か・何を読めなかったか。**

[English](README.md)

```
mamori scan                                  # このフォルダと、この PC の実行環境
mamori scan --github my-org                  # 組織のすべてのリポジトリを、読むだけで
mamori scan --github owner/repo --format markdown --out report.md
```

## 安心して使える理由

| 約束 | どう守っているか |
|---|---|
| **GitHub の中身を変えることはできません。** | すべての通信は1か所の「門」([`internal/egress`](internal/egress/egress.go))を通り、`api.github.com` へは `GET`/`HEAD` 以外を通しません。テストで確かめています。書き込みもできるトークンを渡されても読むだけに使い、そのことを警告します。 |
| **あなたのコードと依存の一覧は外に出ません。** | 既定では、公開の [OSV](https://osv.dev) 脆弱性データベースを(変わったときだけ)落として、**手元で**照らします。依存の情報はどこにも送りません。パッケージ名を OSV の API に送る照合は、`--online` を付けたときだけです。 |
| **通信するすべての宛先が見えます。** | `mamori egress` で、許している宛先の一覧と理由を出します。報告の最後には、実際に通信した宛先と回数が載ります。`--offline` なら通信は一切しません。 |
| **利用状況の送信も、自動更新もしません。** | mamori は自分のことをどこにも知らせず、自分の実行ファイルを書き換えません。本体の更新は、パッケージ管理か、確かめたリリースで行ってください。更新されるのはデータ(脆弱性データベースと Patch the Planet のファイル)だけです。 |
| **「問題なし」が黙って出ることはありません。** | 読めなかったファイル、ロックファイルの無い依存の宣言、手元に無いデータベース、途中で切れたリポジトリの一覧、GitHub 自身の依存グラフがロックファイルを読めていないリポジトリ——これらを**読めなかったもの**として並べ、終了コードは `0` ではなく `3` にします。 |
| **照合の判断は自前ではありません。** | 版が当たるかどうかの判断は、Google の [OSV-Scanner](https://github.com/google/osv-scanner)(Apache-2.0)をそのまま使います。mamori が決めるのは、何を読みどう報告するかだけです。 |
| **動かすものを確かめられます。** | リリースは、タグを打ったコミットから GitHub Actions が再現できる形(`CGO_ENABLED=0 -trimpath -buildid=`)で作り、`SHA256SUMS` と、署名付きのビルドの証明(provenance)を付けます。 |

## 調べるもの

- **ロックファイル**:`bun.lock`・`package-lock.json`・`pnpm-lock.yaml`・`yarn.lock`・`uv.lock`・`poetry.lock`・`Pipfile.lock`・`requirements*.txt`・`Cargo.lock`・`go.mod`・`Gemfile.lock`・`composer.lock`、NuGet、Maven/Gradle など、OSV-Scanner が読めるもの。
- **GitHub のリポジトリ(読むだけ)**:持ち主のリポジトリを一覧にし、ファイルの一覧を読み、ロックファイルだけを落とします(clone しません)。Dependabot 自身の警告の数も並べて出します。GitHub の依存グラフも読み、版の多くが範囲のままなら、GitHub がロックファイルを読めていない=Dependabot が静かでも安心できない、と知らせます。
- **見ないフォルダ**:`node_modules`・`.venv`・`venv`・`__pycache__`・`.git` はインストール済みの写しなので中を見ず、隣のロックファイルを調べます。飛ばしたフォルダの数は報告に出します。GitHub のサブモジュールは「読めなかったもの」に出します。
- **この PC の実行環境**:見つけられるすべての Node.js(PATH・nvm・nvm-windows・volta・fnm)、Bun、PHP、Envoy、Istio、Python と、その中の Brotli。Node.js は nodejs.org とも照らし、取りこぼしたセキュリティ修正と、保守の終わった系列を知らせます。
- **[Patch the Planet](https://patchtheplanet.org/) の公開**:人が確かめたデータ([`overlay/patchtheplanet.json`](overlay/patchtheplanet.json))で、公開ごとに対象と直った版を対応づけています。サイトに新しい公開が出ると毎日の確認が issue を立て、人がデータを更新します。あなたの mamori がサイトを読みに行くことはありません。
- **悪用が確認された脆弱性**:米 CISA の [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) にあるものは印を付け、先頭に出します。

この版でまだ調べないもの:コンテナイメージ、OS のパッケージ、秘密の値、ソースコードそのものの解析。GitLab などへの対応は予定しています。

## 入れ方

[Releases](https://github.com/jun-omise/mamori/releases) から自分の環境のファイルを落とし、動かす前に確かめてください。

```bash
gh attestation verify mamori-v0.1.0-darwin-arm64 --repo jun-omise/mamori
shasum -a 256 -c SHA256SUMS --ignore-missing
```

ソースから作る場合(Go 1.27 以上):

```bash
go install github.com/jun-omise/mamori/cmd/mamori@latest
```

配布ファイルには、まだ Apple や Microsoft のコード署名を付けていません。初めて動かすとき、macOS の Gatekeeper や Windows の SmartScreen が警告を出すことがあります。大事なのは上の証明の確認です。

## GitHub のトークン

mamori に要るのは**読む**権限だけです。[fine-grained のトークン](https://github.com/settings/personal-access-tokens/new)を次の権限で作ってください。

- Repository access:調べたいリポジトリ
- Permissions:**Contents: Read-only**、**Metadata: Read-only**、必要なら **Dependabot alerts: Read-only**

`MAMORI_GITHUB_TOKEN` に入れて使います。`GITHUB_TOKEN`・`GH_TOKEN`・`gh auth token` も読みますが、そのトークンが書き込みもできる場合は知らせます。mamori に `gh` コマンドを動かさせたくない場合は `MAMORI_NO_GH_CLI=1` を設定してください。トークンが無くても、公開リポジトリは1時間に60回まで読めます。

## 出力と終了コード

`--format text`(既定)・`markdown`(issue や PR 向け)・`json`。`--lang ja|en`。言語はシステムの設定から選びます。Windows では多くの場合 `LANG` が無く英語になるので、日本語で見るときは `--lang ja` を付けてください。

| 終了コード | 意味 |
|---|---|
| 0 | 調べた範囲で問題なし・読めなかったものなし |
| 1 | 問題あり |
| 2 | mamori が動けなかった |
| 3 | 問題は見つからなかったが、読めなかったものがある(問題なしとは言えない) |

## 通信する宛先

| 宛先 | 方法 | 理由 |
|---|---|---|
| osv-vulnerabilities.storage.googleapis.com | GET, HEAD | 公開の OSV データベースを落とす |
| api.github.com | GET, HEAD | リポジトリ一覧・ファイル一覧・ロックファイル・Dependabot と依存グラフの状態 |
| raw.githubusercontent.com | GET, HEAD | 人が確かめた新しい Patch the Planet のデータ |
| www.cisa.gov | GET, HEAD | 悪用が確認された脆弱性の一覧 |
| nodejs.org, endoflife.date | GET, HEAD | Node.js のセキュリティ修正と保守の終わる日 |
| api.osv.dev | GET, HEAD, POST | **`--online` のときだけ**。パッケージ名と版を送ります |

## mamori 自身の脆弱性の報告

[SECURITY.md](SECURITY.md) を見てください。

## ライセンス

Apache-2.0。[OSV-Scanner](https://github.com/google/osv-scanner)(Apache-2.0)と、[OSV](https://osv.dev)・[GitHub Advisory Database](https://github.com/advisories)・[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[Patch the Planet](https://patchtheplanet.org/) のデータを使っています。
