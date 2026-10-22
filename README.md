# velk

ELF / PE / COFF / Mach-O を解析し、関数ごとの疑似 C・逆アセンブル・中間表現（IR）・要約を返すバイナリ解析エンジンです。
x86-64 と AArch64 を扱い、コマンドラインと、エージェントからツールを呼ぶための MCP 接続で利用できます。

```c
int32_t sum3(int32_t a0, int32_t a1, int32_t a2) {
    return a1 + a0 + a2;
}
```

## はじめかた

Rust のツールチェーンと C コンパイラを用意し、ソースを取得したディレクトリでビルドします。

```bash
cargo build --release --locked
./target/release/velk functions tests/fixtures/arm64.o
./target/release/velk decompile tests/fixtures/arm64.o sum3
./target/release/velk -d tests/fixtures/arm64.o sum3
```

上の例は、リポジトリに含まれるオブジェクトから関数を一覧し、`sum3` の疑似 C と逆アセンブルを表示します。
自分のファイルを調べるときは、ファイルのパスと、一覧から選んだ関数名またはアドレスを指定します。

```bash
./target/release/velk functions path/to/binary
./target/release/velk decompile path/to/binary 0x1e0
```

関数名は完全一致を優先します。部分一致が複数あるときは候補を示します。
以降の `velk` は、ビルドした実行ファイルのパスに読み替えてください。

## エージェントから使う（MCP）

MCP クライアントに実行ファイルを `mcp` 引数付きで登録します。通信は標準入出力を使います。

```json
{
  "mcpServers": {
    "velk": { "command": "/absolute/path/to/velk", "args": ["mcp"] }
  }
}
```

- `velk_run_script`: JavaScript を実行し、`console.log` の出力と最後の式の値を返します。
- `velk_read_api`: API の概要、または `binary` / `func` / `types` の宣言を必要なときに読みます。

スクリプト内で絞り込み、必要な結果だけ返します。開いたファイルと解析結果はサーバの実行中キャッシュされます。

```js
const b = velk.open("/absolute/path/to/binary");
b.functions({ named: true }).slice(0, 5).map(f => ({ addr: f.addr, name: f.name }));
```

結果の本文は既定で 4,000 文字までです。`velk_run_script` の `max_output_chars` に 256〜20,000 を指定して変更できます。
省略の通知が出たら、スクリプトの条件や `slice` で結果を絞るか、上限を明示して再実行します。
`card({ budget })` は概算のトークン数に応じた要約で、厳密な出力上限ではありません。

JavaScript は同期実行で、Node.js の API や `await`・`import` は使いません。
同じ API は `velk run script.js` でも使えます。例と宣言は [API の概要](src/script/api/index.md) を参照してください。

## CLI

| コマンド | 用途 |
|---|---|
| `velk functions <file>` | 関数の一覧と発見元 |
| `velk decompile <file> <function>` | 関数の疑似 C |
| `velk card <file> <function>` | 関数の要約を JSON で表示 |
| `velk -d <file> <function>` | 逆アセンブル |
| `velk ir <file> <function>` | 最適化後の中間表現 |
| `velk sections <file>` | セクションの一覧 |
| `velk build-signatures <file> --output db.json` | 名前付き関数からシグネチャ DB を作成 |
| `velk identify <file> --signatures db.json` | 形が一致する関数を検索 |
| `velk run <script.js>` | JavaScript API を実行 |
| `velk mcp` | MCP サーバを起動 |

`velk --disasm <file> <function>` と `velk disasm <file> <function>` も同じ処理です。
細かなオプションは `velk -d --help` や `velk <command> --help` で確認できます。

```bash
velk functions path/to/binary --json > functions.json
velk decompile path/to/binary main > main.c
```

端末では見出し・色・余白で読みやすく表示し、パイプやファイルへ出すときは装飾しません。
`NO_COLOR` に空でない値を設定した場合、または `TERM=dumb` の環境では色を使いません。JSON・スクリプト・MCP の出力にも装飾を加えません。

## 対応範囲

| 項目 | 内容 |
|---|---|
| 入力形式 | ELF、PE、COFF、Mach-O の実行ファイル・オブジェクト |
| 命令セット | x86-64、AArch64 |
| メタデータ | シンボル、デバッグ情報、Go の関数表、Rust / C++ の名前の復元 |
| 解析結果 | 疑似 C、IR、逆アセンブル、引数と戻り値の推定、文字列・データ参照、関数の要約 |
| 関数の照合 | 正規化した関数の形によるシグネチャ DB |

疑似 C の型や呼び出しは推定を含みます。対応する入力形式と、velk 自体を実行するホスト環境は別のものです。

- 未対応の命令は出力に `unsupported` と表示します。
- 引数が復元できない間接呼び出しなどは `f()` と表示します。
- レジスタで値渡しする構造体や、引数・戻り値の受け渡し規約とデバッグ情報の対応には制限があります。
- 名前を復元できないフィールドは `field_0x8` のようなオフセット名になることがあります。

命令と解析の詳細は [アーキテクチャ](docs/ARCHITECTURE.md)、未対応の項目と今後の方針は
[ロードマップ](docs/ROADMAP.md) にまとめています。

## ドキュメント

- [API の概要](src/script/api/index.md): スクリプトの書き方とトピック別の宣言
- [アーキテクチャ](docs/ARCHITECTURE.md): 解析の流れと各モジュールの責務
- [ロードマップ](docs/ROADMAP.md): 目指す設計と進める順序
- [Testing](docs/TESTING.md): 検証方法、必要なツール、fixture の再生成、測定値とその範囲

## 開発と検証

```bash
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release
cargo fmt -- --check
cargo clippy --release --all-targets -- -D warnings
```

命令の実機比較、最適化前後の中間表現の比較、疑似 C の再コンパイル比較、コマンドラインと MCP の検査を組み合わせています。
再コンパイル比較には clang、性能確認には uv、fixture の再生成には Docker を使います。
詳しい条件と実行手順は [Testing](docs/TESTING.md) を参照してください。

## ライセンス

未定です。
