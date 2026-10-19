# velk

**LLM エージェントのためのバイナリ解析エンジン。**

velk は ELF / PE / Mach-O の実行ファイルとオブジェクトを読み、関数ごとに疑似 C・中間表現・
逆アセンブル・関数カード（トークン予算つきの JSON 要約）を返します。エージェントは MCP 経由で
JavaScript を実行して必要な結果だけを受け取り、人は CLI から使います。単一のバイナリで動き、
起動から 1 関数の疑似 C を出すまで数ミリ秒です（`tests/bench.sh`）。

```c
/* velk pseudo-C: count_down @ 0x3c */
int32_t count_down(int32_t a0) {
    w8 = 0x0;
    v1 = (a0 > 0x1 ? a0 : 0x1);
    do {
        w8 = w8 + 0x1;
        sink = w8;
    } while (v1 != w8);
    return v1;
}
```

## 特長

- **意味で検証された出力**: すべての fixture のすべての関数について、最適化の前後の中間表現を
  ランダムな入力で実行し、戻り値・呼び出し・メモリが一致することを確かめています。
  見た目のきれいさのために意味を変える変換は入りません。
- **シンボルのないバイナリに強い**: unwind 表から関数の正確な範囲を求め、コンパイラが切り出した
  コールド部分を親の関数に戻します。PLT スタブには取り込んだ関数の名前を付けます。
- **LLM 向けの出力**: 関数カードは、トークン予算に収まる要約と、解析が難しい理由を返します。
  スクリプトの中で絞り込みや集計をすれば、結果だけがモデルに返ります。
- **言語ランタイムの知識**: Go の pclntab、Rust と C++ のデマングル、DWARF の名前・型・構造体メンバ。
- **シグネチャ DB**: 関数の形を正規化したハッシュで、別のバイナリの同じ関数を見つけます。

## 精度

`tests/fixtures/metrics/` の C の関数 148 個を、シンボルとデバッグ情報を取り除いたバイナリから
解析し、デバッグ情報を正解として測った値です（最適化レベルとアーキテクチャごと、`tests/golden/metrics.txt`）。

| 指標 | AArch64 -O0 | AArch64 -O2 | x86-64 -O0 | x86-64 -O2 |
|---|---|---|---|---|
| 関数の発見 | 148/148 | 148/148 | 148/148 | 148/148 |
| 余分な関数 | 0 | 0 | 0 | 0 |
| 引数の個数 | 144/147 | 141/147 | 140/147 | 139/147 |
| 引数の幅 | 138/144 | 133/140 | 138/143 | 136/142 |
| 引数の符号 | 122/138 | 122/133 | 126/138 | 125/136 |
| 戻り値の有無 | 143/148 | 142/148 | 123/148 | 142/148 |
| 戻り値の幅 | 114/120 | 111/119 | 112/117 | 113/118 |

シンボルを取り除いた Rust のバイナリ（`tests/fixtures/rust_probe_stripped`）では、
543 個の関数をすべて見つけ、余分は PLT スタブの 2 個だけです。

## はじめかた

```bash
cargo build --release
./target/release/velk functions path/to/binary
./target/release/velk decompile path/to/binary main
```

関数は名前かアドレス（`0x1e0` または 10 進）で指定します。名前は完全一致を優先し、
部分一致が 1 つに絞れない場合は候補を示してエラーにします。

| コマンド | 内容 |
|---|---|
| `velk functions <file> [--limit N] [--json]` | 関数の一覧と、それぞれを見つけた情報源 |
| `velk sections <file>` | セクションの一覧 |
| `velk card <file> <function> [--budget N] [--signatures db.json]` | 関数カード（JSON） |
| `velk decompile <file> <function> [--signatures db.json]` | 疑似 C |
| `velk disasm <file> <function> [--limit N]` | 逆アセンブル |
| `velk ir <file> <function>` | 最適化後の中間表現 |
| `velk build-signatures <file> --output db.json` | 名前付きの関数からシグネチャ DB を作る |
| `velk identify <file> --signatures db.json` | シグネチャ DB と形が一致する関数を探す |
| `velk run <script.js>` | スクリプト API で JavaScript を実行する |
| `velk mcp` | MCP サーバを標準入出力で起動する |

## エージェントから使う（MCP）

`velk mcp` は次の 2 つのツールを公開します。

- `velk_run_script`: JavaScript を内蔵のエンジンで実行し、`console.log` の出力と最後の式の値を返す
- `velk_read_api`: API の目次、またはトピックごとの TypeScript 宣言を返す

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

- **形式**: ELF、PE、COFF、Mach-O（実行ファイルとリロケータブルオブジェクト）
- **命令セット**: x86-64、AArch64
- **関数の発見**: シンボル表、動的シンボル、PE のエクスポート、エントリポイント、DWARF、
  Go の pclntab、unwind 表、PLT。どれにも覆われない隙間はプロローグの走査で補う
- **解析**: 引数と戻り値の型、ポインタ引数の構造体フィールド、文字列とデータの参照、
  ジャンプテーブルと比較の連鎖からの switch、定数除算・剰余の復元、スタック変数、
  ブロックをまたぐ定数伝播、再利用された引数レジスタの変数の分離
- **疑似 C**: if / else、while、do-while、for (;;)、switch、早期 return を構造化し、
  構造化できない部分はラベルと goto で出す
- **命令**: 整数命令のほぼすべて（回転・バイト反転・交換・ビットテストを含む）。
  x86-64 の SSE の転送とビット演算は、xmm を 64 ビットの半分 2 つ（`xmm0` と `xmm0_hi`）として扱う

## 既知の制限

- 浮動小数の演算、ベクトル演算、一部のシステム命令は未対応で、出力に `unsupported` と明示します
- noreturn を推定しないため、戻らない関数の呼び出しの後ろに次の関数のコードが続くことがあります
- 呼び出しの引数は IR に持たず、呼び出しの前のレジスタの設定として出ます
- デバッグ情報がない場合、構造体のフィールドはオフセットと幅だけで表します
- DWARF の引数は、宣言順が ABI のレジスタ順と一致する場合にだけ正しく対応づきます

これらへの取り組みは [docs/ROADMAP.md](docs/ROADMAP.md) にあります。

## ドキュメント

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): 解析の流れと各モジュールの責務
- [docs/ROADMAP.md](docs/ROADMAP.md): 目指す設計と進める順序

## テスト

テストの入力は `tests/fixtures/` のバイナリです。`tests/cases/` のソースから、ツールチェーンの版を
固定した基準環境（`tests/fixtures/toolchain.txt`）で生成してリポジトリに含めているので、
どのマシンでも同じバイト列をテストします。生成物にビルド環境のパスが残らないことは、生成時に確かめています。

```bash
cargo test                # ユニットテストと結合テスト
./tests/smoke.sh          # CLI と MCP の出力、性能
./tests/ladder.sh         # 難易度別の期待値
```

| テスト | 確かめること | 正解 |
|---|---|---|
| `src/analysis/semantics_tests.rs` | 最適化が関数の動作を変えていない（IR を実行して比べる） | 最適化前の IR |
| `tests/invariants.rs` | 飛び先のない goto、代入されないレジスタの読み取り、疑似 C での文の欠落がない | 出力の性質 |
| `tests/metrics.rs` | 関数の発見、引数と戻り値の推定の正解率 | デバッグ情報（`*.debug.elf`） |
| `tests/golden.rs` | 全 fixture の関数一覧、疑似 C、IR、シグネチャ、カードが変わっていない | `tests/golden/fixtures/` |
| `tests/api.rs` | スクリプト API の戻り値が `.d.ts` の宣言と一致する | `src/script/api/` |
| `tests/robustness.rs` など | 壊れたファイルやランダムな命令列で panic しない | なし |
| `tests/smoke.sh` | CLI と MCP の出力の要所、性能 | 文字列の照合 |
| `tests/ladder.sh` | 難易度 L0〜L7 の期待値（`known_*` は未達の目標） | `tests/expect/ladder.tsv` |

正解率、不変条件の違反、動作の違いは、今の値を `tests/golden/` に記録しています。値が変わると
テストは失敗し、どの関数がどう変わったかを示します。意図した変更なら `VELK_BLESS=1 cargo test` で
記録を更新し、差分を確かめてからコミットします。

### fixture の再生成

```bash
docker compose run --rm fixtures   # tests/cases/ から tests/fixtures/ を作り直す
docker compose run --rm check      # 基準環境でテストを回す
```

### LLM による意味の確認

`uv run tests/review.py [REVISION]` は、指定したリビジョンから疑似 C が変わった関数について、
元のソースと新旧の疑似 C を並べた `tests/out/review.md` を作ります（`--all` で全関数）。
LLM がそれを読んで意味が同じかを判定し、結果を `tests/review/verdicts.tsv` に残します。
判定は合否には使わず、ほかのテストでは見つからない誤りを探すために使います。

## ライセンス

未定です。
