<p align="center">
  <img width="240" height="240" alt="velk" src="https://github.com/user-attachments/assets/31a1c0c1-3ca4-4d9f-8d88-917cc43bd49e" />
</p>

<h1 align="center">velk</h1>

<p align="center">
  実行ファイルを読み、<b>そのままコンパイルでき、元の機械語と同じ計算をする C</b> に戻すデコンパイラ。<br>
  人と LLM エージェントの両方が使うことを前提に作っています。
</p>

---

```c
int32_t sum3(int32_t a0, int32_t a1, int32_t a2) {
    return a1 + a0 + a2;
}
```

velk は ELF / PE / COFF / Mach-O を解析し、関数ごとの疑似 C・逆アセンブル・中間表現（IR）・要約を返します。
コマンドラインのほか、JavaScript のスクリプト API と、エージェントから呼ぶための MCP サーバを備えています。

## 特徴

- **正しさを最優先**: 出力した C を実際にコンパイルし、IR の解釈実行と結果を突き合わせて検証しています。
  命令の意味は実機と比較し、ランダム生成した C プログラムを使った差分テストも継続的に回しています。
- **そのままコンパイルできる C**: すべての fixture のすべての関数の出力が、新旧のコンパイラでコンパイルできることをテストで保証しています。
  補助関数や宣言は、ファイル先頭のプレリュードに 1 度だけ出力します。
- **読みやすさ**: スタック上の構造体・共用体の復元、型付きポインタ、`for` ループと複合代入、`switch` の共有、
  宣言時の初期化、役割に応じた名前（`i`、`result` など）、`va_start` / `va_arg`、宣言されたプロトタイプでの呼び出しなど。
- **多くの言語と形式**: C / C++ / Rust / Go / Objective-C のバイナリを、デバッグ情報があってもなくても扱います。
- **エージェント向けの API**: 関数の要約（card）やスクリプト API で、必要な情報だけを小さく取り出せます。

## はじめかた

Rust のツールチェーンと C コンパイラを用意して、ビルドします。

```bash
cargo build --release --locked
./target/release/velk --functions tests/fixtures/arm64.o
./target/release/velk --decompile tests/fixtures/arm64.o sum3
./target/release/velk --disasm tests/fixtures/arm64.o sum3
```

自分のファイルを調べるときは、ファイルのパスと、関数名またはアドレスを指定します。
関数名は完全一致を優先し、部分一致が複数あるときは候補を示します。

```bash
velk --functions path/to/binary
velk --decompile path/to/binary 0x1e0
velk --decompile path/to/binary '*' > all.c   # すべての関数をまとめて出力
```

以降の `velk` は、ビルドした実行ファイルのパスに読み替えてください。

## エージェントから使う（MCP）

MCP クライアントに実行ファイルを `--mcp` 付きで登録します。通信は標準入出力です。

```json
{
  "mcpServers": {
    "velk": { "command": "/absolute/path/to/velk", "args": ["--mcp"] }
  }
}
```

- `velk_run_script`: JavaScript を実行し、`console.log` の出力と最後の式の値を返します。
- `velk_read_api`: API の概要、または `binary` / `func` / `types` の宣言を必要なときに読みます。

スクリプトの中で絞り込み、必要な結果だけを返します。開いたファイルと解析結果は、サーバの実行中キャッシュされます。

```js
const b = velk.open("/absolute/path/to/binary");
b.functions({ named: true }).slice(0, 5).map(f => ({ addr: f.addr, name: f.name }));
```

結果の本文は既定で 4,000 文字までです。`velk_run_script` の `max_output_chars` に 256〜20,000 を指定して変えられます。
`card({ budget })` は概算のトークン数に合わせた要約で、厳密な上限ではありません。
JavaScript は同期実行で、Node.js の API や `await`・`import` は使えません。同じ API は `velk --run script.js` でも使えます。
例と宣言は [API の概要](src/script/api/index.md) を参照してください。

## CLI

操作を 1 つ選びます。

| オプション | 用途 |
|---|---|
| `-f`, `--functions` | 関数の一覧と発見元 |
| `-s`, `--sections` | セクションの一覧 |
| `-c`, `--card` | 関数の要約を JSON で表示 |
| `-D`, `--decompile` | 疑似 C（複数の関数、または `'*'` で全関数） |
| `-d`, `--disasm` | 逆アセンブル |
| `-i`, `--ir` | 最適化後の中間表現 |
| `-b`, `--build-signatures` | 名前付き関数からシグネチャ DB を作成 |
| `-I`, `--identify` | シグネチャ DB と形が一致する関数を検索 |
| `-r`, `--run` | JavaScript API を実行 |
| `-m`, `--mcp` | MCP サーバを起動 |

引数・オプション・実行例は `velk --help` で確認できます。

```bash
velk --functions path/to/binary --json > functions.json
velk --decompile path/to/binary main > main.c
```

端末では見出しと色で読みやすく表示し、パイプやファイルへの出力では装飾しません。
`NO_COLOR` を設定した場合と `TERM=dumb` の環境でも色を使いません。

## 対応範囲

| 項目 | 内容 |
|---|---|
| 入力形式 | ELF、PE / COFF、Mach-O の実行ファイル・共有ライブラリ・オブジェクト |
| 命令セット | x86-64、AArch64（SIMD・アトミック命令・暗号命令を含む） |
| 呼び出し規約 | System V x86-64、Windows x64、AAPCS64（Linux / Apple）、Go のレジスタ・スタック規約 |
| デバッグ情報 | DWARF、CodeView / PDB（関数・引数・ローカル変数の名前と型、構造体のレイアウト） |
| 言語メタデータ | Go の関数表と型記述子、Rust / C++ の名前の復元、C++ の vtable、Objective-C のクラスとセレクタ |
| 例外処理 | DWARF の landing pad、Windows の SEH（保護範囲とハンドラを注釈として出力） |
| 解析結果 | 疑似 C、IR、逆アセンブル、引数と戻り値の推定、文字列・データ参照、関数の要約 |
| 関数の照合 | 正規化した関数の形によるシグネチャ DB |

疑似 C の型や名前は推定を含みますが、計算の内容は機械語と一致させることを前提にしています。
一致を保証できない形（例えば機械の状態を読む命令や、解決できない間接ジャンプ）は、組み込み関数や明示的なアダプタとして書き出します。

- 未対応の命令は出力に `unsupported` と表示します。
- 名前を復元できないフィールドは `field_0x8` のようなオフセット名になります。
- 境界を証明できない配列は、型付きの配列ではなくバイトオフセットでアクセスします。

解析の流れは [アーキテクチャ](docs/ARCHITECTURE.md)、今後の方針は [ロードマップ](docs/ROADMAP.md) にまとめています。

## 検証

velk の出力は、次の検査を通ることを条件に変更しています。

- **再コンパイル比較**: 出力した C をコンパイル・実行し、IR の解釈実行と同じ値を返すか（レジスタ・メモリの両方）
- **全関数のコンパイル**: すべての fixture のすべての関数が、標準ヘッダとともにコンパイルできるか
- **命令の実機比較**: 持ち上げた命令の意味が、実際の CPU と一致するか
- **差分テスト**: ランダム生成した C プログラムで、関数を velk の出力に置き換えても結果が変わらないか（arm64 / x86-64）
- **golden**: fixture ごとの出力と、行数・変数・キャスト・goto などの読みやすさの指標

```bash
cargo nextest run --release
cargo fmt -- --check
cargo clippy --release --all-targets -- -D warnings
```

再コンパイル比較には clang、性能確認には uv、fixture の再生成には Docker を使います。
詳しい条件と手順は [Testing](docs/TESTING.md) を参照してください。

## ドキュメント

- [API の概要](src/script/api/index.md): スクリプトの書き方とトピック別の宣言
- [アーキテクチャ](docs/ARCHITECTURE.md): 解析の流れと各モジュールの責務
- [ロードマップ](docs/ROADMAP.md): 目指す設計と進める順序
- [Testing](docs/TESTING.md): 検証方法、必要なツール、fixture の再生成、測定値

## ライセンス

未定です。
