<div align="center">

# mamori(守り)

**あなたの依存・GitHub のリポジトリ・いま使っている PC を調べる、読むだけの脆弱性スキャナ**

[English](README.md) · **日本語**

[![ci](https://github.com/jun-omise/mamori/actions/workflows/ci.yml/badge.svg)](https://github.com/jun-omise/mamori/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

**mamori** は、macOS・Windows・Linux で1つのファイルとして動きます。ロックファイルを手元か GitHub から直接(clone せず、書き込みの権限も使わずに)読み、公開の脆弱性データと**手元で**照らします。結果は、いつも次の3つに答えます。

1. **何を調べたか** — ファイル・パッケージの数・実行環境をすべて並べます。「問題なし」がどこまでの話かが分かります。
2. **何が問題か** — 勧告の ID、直った版、実際に悪用されているかを、1件ずつ示します。
3. **何を読めなかったか** — 判断できなかったファイル・フォルダ・リポジトリを並べます。読めなかったものがあるスキャンを「問題なし」とは言いません。

## 目次

- [すぐ使う](#すぐ使う) · [出力の例](#出力の例) · [安心して使える理由](#安心して使える理由)
- [調べるもの](#調べるもの) · [入れ方](#入れ方) · [使い方](#使い方) · [CI で使う](#ci-で使う)
- [GitHub のトークン](#github-のトークン) · [終了コード](#終了コード) · [通信する宛先](#通信する宛先)
- [よくある質問](#よくある質問) · [これから](#これから) · [参加のしかた](#参加のしかた) · [ライセンス](#ライセンス)

## すぐ使う

```bash
mamori scan                                   # このフォルダと、この PC に入っている実行環境
mamori scan --github your-org                 # ユーザーか組織のすべてのリポジトリを、読むだけで
mamori scan --github owner/repo --format markdown --out report.md
mamori egress                                 # mamori が通信しうる宛先と、その理由
```

## 出力の例

わざと古い版を入れた試しのフォルダを、通信なし(`--offline`)で調べた結果です(一部を省いています。全文では9件を並べます)。

```text
mamori スキャン結果 — mamori v0.1.0
照合の方法: 完全オフライン(通信なし・手元のキャッシュだけで照合)

== まとめ
  問題: critical 5 / high 1 / medium 3 / low 0 / unknown 0
  読めなかったもの・判断できなかったもの: 1

== 調べたもの
  [local] ~/my-app — 2 ファイル, 5 パッケージ
      api/requirements.txt  (PyPI, 2)
      web/package-lock.json  (npm, 3)

== 問題
  1. [重大] @tanstack/react-start 1.167.50  — local:~/my-app
     web/package-lock.json
     GHSA-qx66-fv34-fjm8, CVE-2026-102989  TanStack Router: Unauthenticated reflected XSS in TanStack Start server-function responses
     直った版: 1.168.60
  3. [重大] brotli 1.2.0  — local:~/my-app
     api/requirements.txt
     GHSA-9v8h-qqgm-4m35, CVE-2026-111497, …  Out-of-bounds write in the Brotli decoder ("Node2Shell") also affects the PyPI Brotli package
     直った版: 1.2.1
  4. [重大] seroval 1.5.2  — local:~/my-app
     web/package-lock.json
     GHSA-mv8w-475r-vwqw, CVE-2026-59940  seroval: `seroval.fromJSON()` Promise resolver type confusion invokes attacker-controlled methods during deserialization
     直った版: 1.5.3
  …

== 読めなかったもの・判断できなかったもの
  - local:~/my-app:worker/package.json — 依存は書かれていますが、隣にロックファイルが無いので、実際に入る版が分かりません

== Patch the Planet の公開
  Brotli decoder vulnerability (CVE-2026-111497) https://patchtheplanet.org/brotli
     確かめたもの: Google Brotli (Python binding) / 当たった数: 1
     手で確かめてください: Node.js, Bun, Envoy Proxy, Istio

== 通信した宛先
  通信はしていません。
```

勧告の要約は、データベースの原文(英語)のまま表示します。同じ報告を Markdown(issue や PR 向け)と JSON(ほかの道具向け)でも出せます。

## 安心して使える理由

| 約束 | どう守っているか |
|---|---|
| **GitHub の中身を変えることはできません。** | すべての通信は1か所の「門」([`internal/egress`](internal/egress/egress.go))を通り、`api.github.com` へは `GET`/`HEAD` 以外を通しません。[テスト](internal/egress/egress_test.go)で確かめています。書き込みもできるトークンを渡されても読むだけに使い、そのことを警告します。 |
| **あなたのコードと依存の一覧は外に出ません。** | 既定では、公開の [OSV](https://osv.dev) データベースを(変わったときだけ)落として、**手元で**照らします。依存の情報はどこにも送りません。パッケージ名を OSV の API に送る照合は、`--online` を付けたときだけです。 |
| **通信するすべての宛先が見えます。** | `mamori egress` で、許している宛先の一覧と理由を出します。報告の最後には、実際に通信した宛先が載ります。`--offline` なら通信は一切しません。 |
| **利用状況の送信も、自動更新もしません。** | mamori は自分のことをどこにも知らせず、自分の実行ファイルを書き換えません。更新されるのはデータ(脆弱性データベースと Patch the Planet のファイル)だけで、プログラムは変わりません。 |
| **「問題なし」が黙って出ることはありません。** | 読めなかったファイル、ロックファイルの無い依存の宣言、手元に無いデータベース、取得元の無い npm のパッケージ、途中で切れたリポジトリの一覧、サブモジュール、GitHub の依存グラフがロックファイルを読めていないリポジトリ——これらを**読めなかったもの**として並べ、終了コードは `0` ではなく `3` にします。`osv-scanner.toml` の除外ルールがかかっているときも、必ず報告に名前を出します。 |
| **照合の判断は自前ではありません。** | 版が当たるかどうかの判断は、Google の [OSV-Scanner](https://github.com/google/osv-scanner)(Apache-2.0)をそのまま使います。mamori が決めるのは、何を読み、どう報告するかだけです。 |
| **動かすものを確かめられます。** | リリースは、タグを打ったコミットから GitHub Actions が再現できる形(`CGO_ENABLED=0 -trimpath -buildid=`:2回作ると1バイトも違わない)で作り、`SHA256SUMS` と、署名付きのビルドの証明(provenance)を付けます。 |

## 調べるもの

**ロックファイル** — OSV-Scanner が読めるもの。`bun.lock`・`package-lock.json`・`pnpm-lock.yaml`・`yarn.lock`・`uv.lock`・`poetry.lock`・`Pipfile.lock`・`requirements*.txt`・`Cargo.lock`・`go.mod`・`Gemfile.lock`・`composer.lock`、NuGet、Maven/Gradle のロックファイルなど。

**GitHub のリポジトリ(読むだけ)** — 持ち主のリポジトリを一覧にし、ファイルの一覧を読み、ロックファイルだけを落とします(clone しません)。Dependabot 自身の警告の数も、mamori の結果の横に並べます。GitHub の依存グラフも読み、版の多くが範囲のままなら、GitHub がロックファイルを読めていない=Dependabot が静かでも安心できない、と知らせます。

**この PC の実行環境** — 見つけられるすべての Node.js(PATH・nvm・nvm-windows・volta・fnm)、Bun、PHP、Envoy、Istio、Python と、その中に入っている Brotli。Node.js は nodejs.org とも照らし、取りこぼしたセキュリティ修正と、保守の終わった系列を知らせます。

**[Patch the Planet](https://patchtheplanet.org/) の公開** — 人が確かめたデータ([`overlay/patchtheplanet.json`](overlay/patchtheplanet.json))で、公開ごとに対象と直った版を対応づけています。サイトに新しい公開が出ると毎日の確認が issue を立て、人が PR でデータを更新します。あなたの mamori がサイトを読みに行くことはありません。

**実際に悪用されているもの** — 米 CISA の [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) にあるものは印を付け、先頭に出します。

**見ないフォルダ** — `node_modules`・`.venv`・`venv`・`__pycache__`・`.git` はインストール済みの写しなので中を見ず、隣のロックファイルを調べます。飛ばしたフォルダの数は報告に出します。

この版でまだ調べないもの:コンテナイメージ、OS のパッケージ、秘密の値、ソースコードそのものの解析、GitHub 以外の置き場所。[これから](#これから)を見てください。

## 入れ方

macOS・Windows・Linux(Intel と Arm)向けのファイルを、v0.1.0 から [Releases](https://github.com/jun-omise/mamori/releases) で配ります。**動かす前に必ず確かめてください。**

### macOS と Linux

```bash
gh attestation verify mamori-v0.1.0-darwin-arm64 --repo jun-omise/mamori
shasum -a 256 -c SHA256SUMS --ignore-missing
chmod +x mamori-v0.1.0-darwin-arm64 && mv mamori-v0.1.0-darwin-arm64 /usr/local/bin/mamori
```

### Windows(PowerShell)

```powershell
gh attestation verify .\mamori-v0.1.0-windows-amd64.exe --repo jun-omise/mamori
(Get-FileHash .\mamori-v0.1.0-windows-amd64.exe -Algorithm SHA256).Hash   # SHA256SUMS の値と比べる
Rename-Item .\mamori-v0.1.0-windows-amd64.exe mamori.exe
```

### ソースから(Go 1.27 以上)

```bash
go install github.com/jun-omise/mamori/cmd/mamori@latest
```

配布ファイルには、まだ Apple や Microsoft のコード署名を付けていません。初めて動かすとき、macOS の Gatekeeper や Windows の SmartScreen が警告を出すことがあります。大事なのは上の証明の確認です(`gh attestation verify` は GitHub CLI 2.49 以上)。

## 使い方

```text
mamori scan [調べる対象] [オプション]
mamori egress
mamori version
```

| オプション | 意味 |
|---|---|
| `--local PATH` | フォルダを調べる(何度でも)。対象を何も書かないと、`.` と `--runtimes` を調べます |
| `--github OWNER` / `--github OWNER/REPO` | 持ち主のすべてのリポジトリ、または1つのリポジトリを調べる(何度でも) |
| `--runtimes` | この PC の Node.js・Bun・PHP・Envoy・Istio・Python を調べる |
| `--include-forks`, `--include-archived` | フォークやアーカイブ済みのリポジトリも調べる |
| `--online` | 手元ではなく OSV の API で照らす(パッケージ名と版を api.osv.dev に送ります) |
| `--offline` | 通信を一切せず、手元のデータベースだけで照らす |
| `--format text\|markdown\|json` | 出力の形(既定は `text`) |
| `--out FILE` | 報告をファイルに書く |
| `--lang ja\|en` | 報告の言語(既定はシステムの設定。Windows では多くの場合 `LANG` が無く英語になるので、日本語なら `--lang ja`) |
| `--cache-dir DIR` | データベースの置き場所(既定はユーザーのキャッシュフォルダ) |
| `--verbose` | OSV-Scanner 自身のログも出す |

## CI で使う

```yaml
- uses: actions/setup-go@v7
  with:
    go-version: "1.27"
- name: mamori
  run: |
    go install github.com/jun-omise/mamori/cmd/mamori@v0.1.0
    set +e
    mamori scan --local . --format markdown --out mamori.md
    code=$?
    cat mamori.md >> "$GITHUB_STEP_SUMMARY"
    exit $code   # 1 = 問題あり、3 = 読めなかったものあり
```

action も mamori も、確かめた版に固定して使ってください。

## GitHub のトークン

mamori に要るのは**読む**権限だけです。[fine-grained のトークン](https://github.com/settings/personal-access-tokens/new)を次の設定で作ってください。

- **Repository access**:調べたいリポジトリ
- **Permissions**:Contents: Read-only、Metadata: Read-only、必要なら Dependabot alerts: Read-only

`MAMORI_GITHUB_TOKEN` に入れて使います。`GITHUB_TOKEN`・`GH_TOKEN`・`gh auth token` も読みますが、そのトークンが書き込みもできる場合は知らせます。mamori に `gh` コマンドを動かさせたくない場合は `MAMORI_NO_GH_CLI=1` を設定してください。トークンが無くても、公開リポジトリは1時間に60回まで読めます。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | 調べた範囲で問題なし・読めなかったものなし |
| `1` | 問題あり |
| `2` | mamori が動けなかった |
| `3` | 問題は見つからなかったが、読めなかったものがある(**問題なしとは言えない**) |

## 通信する宛先

| 宛先 | 方法 | 理由 |
|---|---|---|
| `osv-vulnerabilities.storage.googleapis.com` | GET, HEAD | 公開の OSV データベースを落とす |
| `api.github.com` | GET, HEAD | リポジトリ一覧・ファイル一覧・ロックファイル・Dependabot と依存グラフの状態 |
| `raw.githubusercontent.com` | GET, HEAD | 人が確かめた新しい Patch the Planet のデータ |
| `www.cisa.gov` | GET, HEAD | 悪用が確認された脆弱性の一覧(1日は手元のものを使う) |
| `nodejs.org`, `endoflife.date` | GET, HEAD | Node.js のセキュリティ修正と保守の終わる日 |
| `api.osv.dev` | GET, HEAD, POST | **`--online` のときだけ**。パッケージ名と版を送ります |

ほかの宛先には通信できません。宛先を足すときは、[`internal/egress`](internal/egress/egress.go) とこの表を同じ PR で変えます。

## よくある質問

### コードや依存の一覧を、どこかに送りますか?

既定では送りません。公開のデータを落とし、手元で照らします。`--online` を付けたときだけ、パッケージ名と版を api.osv.dev に送ります。どの実行でも、報告の「通信した宛先」で確かめられます。

### Dependabot と何が違いますか?

両方使ってください。Dependabot は GitHub の側からリポジトリを見張ります。mamori は、何を調べ、何を読めなかったかを示します。たとえば GitHub の依存グラフがロックファイルを読めていない(入っている版ではなく `^1.167.50` のような範囲が並ぶ)とき、Dependabot は本当の版が見えず、静かなままになりえます。mamori はロックファイルを自分で読み、その穴を「読めなかったもの」として知らせます。

### OSV-Scanner と何が違いますか?

mamori は照合に OSV-Scanner を使っています。そのうえで、clone しない GitHub の読むだけのスキャン、実行環境の確認、Patch the Planet のデータ、CISA KEV の印、読めなかったものの報告、通信の門を足しています。

### なぜ「読めなかったもの」が出るのですか?

mamori が判断できなかったものがあるからです。ロックファイルの無い依存の宣言、読めないファイル、手元に無いデータベース、GitHub が一覧を最後まで返さなかったリポジトリなどです。1行ごとに、何をすればよいかを書いています。

### ファイルが約60MBあるのはなぜですか?

多くのエコシステム向けの OSV-Scanner の読み取り部品を含み、ほかの実行環境なしで動くためです。

## これから

- パッケージ管理:Homebrew、winget、Scoop
- Apple と Microsoft のコード署名
- GitHub のコードスキャン向けの SARIF 出力
- GitLab など、GitHub 以外の置き場所
- コンテナイメージ

## 参加のしかた

issue と PR を歓迎します。変更を送る前に `go vet ./...` と `go test ./...` を流してください。[`overlay/patchtheplanet.json`](overlay/patchtheplanet.json) を更新するときは、直った版ごとに公開ページへのリンクを付けてください。mamori 自身の脆弱性は公開の issue ではなく、[SECURITY.md](SECURITY.md) の方法で知らせてください。

## ライセンス

[Apache-2.0](LICENSE)。[OSV-Scanner](https://github.com/google/osv-scanner)(Apache-2.0)と、[OSV](https://osv.dev)・[GitHub Advisory Database](https://github.com/advisories)・[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[Patch the Planet](https://patchtheplanet.org/) のデータを使っています。
