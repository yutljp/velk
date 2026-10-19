# velk

LLM エージェントが使うことを前提にしたバイナリ解析エンジンです。ELF / PE / Mach-O を読み、
関数ごとに疑似 C・中間表現・逆アセンブル・関数カード(JSON の要約)を返します。
エージェントからは MCP 経由で JavaScript を実行して使い、人は CLI から使います。

## ビルド

```bash
cargo build --release
```

## CLI

関数は名前かアドレス(`0x1e0` または 10 進)で指定します。名前は完全一致を優先し、
部分一致が 1 つに絞れない場合は候補を示してエラーにします。

| コマンド | 内容 |
|---|---|
| `velk functions <file> [--limit N] [--json]` | 関数の一覧 |
| `velk sections <file>` | セクションの一覧 |
| `velk card <file> <function> [--budget N] [--signatures db.json]` | 関数カード(JSON) |
| `velk decompile <file> <function> [--signatures db.json]` | 疑似 C |
| `velk disasm <file> <function> [--limit N]` | 逆アセンブル |
| `velk ir <file> <function>` | 最適化後の中間表現 |
| `velk build-signatures <file> --output db.json` | 名前付き関数からシグネチャ DB を作る |
| `velk identify <file> --signatures db.json` | シグネチャ DB と形が一致する関数を探す |
| `velk run <script.js>` | スクリプト API で JavaScript を実行する |
| `velk mcp` | MCP サーバを標準入出力で起動する |

## スクリプト API と MCP

`velk mcp` は次の 2 つのツールを公開します。

- `velk_run_script`: JavaScript を内蔵の QuickJS で実行し、`console.log` の出力と最後の式の値を返す
- `velk_read_api`: API の目次、またはトピックごとの TypeScript 宣言を返す

スクリプトの中で絞り込みや集計をすれば、結果だけがモデルに返るのでトークンを節約できます。
開いたバイナリと関数ごとの解析結果は、サーバが動いている間キャッシュされます。
同じ API は `velk run` でも使えます。宣言は `src/script/api/` にあります。

```js
const b = velk.open("/path/to/binary");
for (const f of b.functions({ named: false, minSize: 200 }).slice(0, 5)) {
  console.log(f.addr, f.strings());
}
b.getFunction("main").decompile();
```

MCP クライアントには、実行ファイルを `mcp` 引数付きで登録します。

```json
{ "mcpServers": { "velk": { "command": "/path/to/velk", "args": ["mcp"] } } }
```

## 対応範囲

- 形式: ELF、PE、COFF、Mach-O
- 命令セット: x86-64、AArch64
- 関数の発見: シンボル表、動的シンボル、PE エクスポート、エントリポイント、DWARF、
  Go の pclntab。シンボルのないバイナリではプロローグを走査して関数の先頭を探す
- 名前: Rust(v0 / legacy)と C++(Itanium)のデマングル
- 解析: 引数と戻り値の型の推定、ポインタ引数の構造体フィールド、文字列とデータの参照、
  ジャンプテーブルと比較の連鎖からの switch の復元、定数除算・剰余の復元、スタック変数の命名、
  DWARF の引数名・型・構造体メンバ名の反映
- 疑似 C: if / else、while、do-while、for (;;)、switch、早期 return を構造化し、
  構造化できない部分はラベルと goto で出力する
- シグネチャ DB: 関数の形を正規化したハッシュで、別のバイナリの関数を照合する

## 既知の制限

- SIMD、浮動小数点、一部のシステム命令は未対応で、出力に `unsupported` と明示する
- x86-64 の文字列命令や `shld` など、一部の整数命令も未対応
- ジャンプテーブルの復元は AArch64 の clang の形式のみ。x86-64 の間接 switch は goto のまま残る
- デバッグ情報がない場合、構造体のフィールドはオフセットと幅だけで表す
- シンボルも DWARF もない Rust バイナリでは、関数名を復元できない
- DWARF の引数は、宣言順が ABI のレジスタ順と一致する場合にだけ正しく対応づく

## テスト

テスト用のバイナリは `tests/cases/` のソースから `tests/make_fixtures.sh` で生成し、
`tests/out/` に置きます(リポジトリには含めません)。足りないツールチェーンのケースは
`tests/out/skipped.txt` に記録され、失敗ではなくスキップになります。

| スクリプト | 内容 |
|---|---|
| `tests/make_fixtures.sh` | フィクスチャを生成する |
| `tests/smoke.sh` | ビルド、ユニットテスト、CLI と MCP の出力、性能をまとめて確認する |
| `tests/ladder.sh` | 難易度別の期待値(`tests/expect/ladder.tsv`)を採点する |
| `tests/bench.sh` | コマンドごとの平均実行時間がしきい値以内か確認する |
| `tests/dump.sh` | 全関数の疑似 C をファイルに書き出す |
| `tests/env-diff.sh` | 基準環境の出力と手元の出力を比べる |

```bash
./tests/make_fixtures.sh
./tests/smoke.sh
./tests/ladder.sh
```

### 基準環境

コンパイラの版によって生成コードが変わるため、x86-64 Linux のコンテナで版を固定した
ツールチェーンを使い、その出力を基準にします(clang / LLVM 18、Rust 1.98.1、Go 1.23.4、
Ubuntu 24.04。版は `compose.yml` の `build.args` で変えられます)。

```bash
docker compose run --rm canonical                 # 基準環境で smoke と ladder を回す
docker compose run --rm -e VELK_DUMP=1 canonical  # 疑似 C のダンプも作る(時間がかかる)
./tests/dump.sh tests/out && ./tests/env-diff.sh --show 3
```

`env-diff.sh` は関数ごとに、両環境で一致したもの、内容が違うもの、片方でしか復元できなかったものを数えます。

## ライセンス

未定です。
