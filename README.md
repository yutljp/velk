# velk

**LLM エージェントのためのバイナリ解析エンジン。**

velk は ELF / PE / Mach-O の実行ファイルとオブジェクトを読み、関数ごとに疑似 C・中間表現・
逆アセンブル・関数の要約（指定したトークン数に収まる JSON）を返します。エージェントは MCP 経由で
JavaScript を実行して必要な結果だけを受け取り、人は CLI から使います。単一のバイナリで動き、
起動から 1 関数の疑似 C を出すまで、小さなバイナリなら数ミリ秒です（`tests/bench.sh`）。

シンボルもデバッグ情報もない、最適化なしの x86-64 の関数から（元は `double average(const double *values, int n)`）:

```c
/* velk pseudo-C: sub_2011f0 @ 0x2011f0 */
double sub_2011f0(double *a0, int32_t a1) {
    int64_t v1;
    double *local_0; /* [sp-10] */
    int32_t local_1; /* [sp-14] */
    double local_2; /* [sp-20] */
    int32_t local_3; /* [sp-24] */
    double local_4; /* [sp-30] */

    local_0 = a0;
    local_1 = a1;
    local_2 = 0.0;
    for (local_3 = 0x0; local_3 < local_1; local_3 += 0x1) {
        v1 = (int64_t)(int32_t)(local_3);
        local_2 = local_0[v1] + local_2;
    }
    if (local_1 <= 0x0) {
        local_4 = 0.0;
        return local_4;
    }
    local_4 = local_2 / (double)(int32_t)local_1;
    return local_4;
}
```

## 特長

- **意味で検証された出力**: テスト用のすべてのバイナリのすべての関数について、最適化の前後の中間表現と、
  構造化した結果をブロックに戻したものを、ランダムな入力で実行し、戻り値・呼び出し・メモリが一致することを
  確かめています。見た目のきれいさのために意味を変える変換は入りません。
- **シンボルのないバイナリに強い**: unwind 表から関数の正確な範囲を求め、コンパイラが関数から
  分離したコールド部分（めったに通らない経路）を元の関数に戻します。共有ライブラリの関数を呼ぶ
  PLT のスタブには、呼び先の関数名を付けます。
- **LLM 向けの出力**: 関数の要約は、指定したトークン数に収まる内容と、解析が難しい理由を返します。
  スクリプトの中で絞り込みや集計をすれば、結果だけがモデルに返ります。
- **言語ごとのメタデータ**: Go の関数表（pclntab）、Rust と C++ のマングルされた名前の復元、DWARF の名前・型・構造体メンバ。
- **関数の照合**: 関数の形を正規化したハッシュを集めたデータベースで、別のバイナリの同じ関数を見つけます。

## 精度

`tests/fixtures/metrics/` の C の関数 151 個を、シンボルとデバッグ情報を取り除いたバイナリから
解析し、デバッグ情報を正解として測った値です（最適化レベルとアーキテクチャごと、`tests/golden/metrics.txt`）。

| 指標 | AArch64 -O0 | AArch64 -O2 | x86-64 -O0 | x86-64 -O2 |
|---|---|---|---|---|
| 関数の発見 | 151/151 | 151/151 | 151/151 | 151/151 |
| 余分な関数 | 0 | 0 | 0 | 0 |
| 引数の個数 | 150/150 | 150/150 | 150/150 | 150/150 |
| ポインタ引数 | 187/189 | 186/189 | 187/189 | 186/189 |
| 引数の幅 | 151/157 | 151/157 | 152/157 | 152/157 |
| 引数の符号 | 139/151 | 139/151 | 140/152 | 140/152 |
| 戻り値の有無 | 145/151 | 145/151 | 144/151 | 147/151 |
| 戻り値の幅 | 118/122 | 117/122 | 118/122 | 118/122 |
| 浮動小数点の型 | 10/10 | 10/10 | 10/10 | 10/10 |

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
| `velk card <file> <function> [--budget N] [--signatures db.json]` | 関数の要約（JSON） |
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
- **解析**: 引数と戻り値の型、ポインタ引数の構造体（固定オフセットのアクセスから定義を復元）、
  変数の型（幅・符号・浮動小数点・指す先の型を使われ方から決めて宣言する）、文字列とデータの参照、
  ジャンプテーブル（範囲判定のない列挙型の分岐や、前のブロックで番地を置いたテーブルも）と比較の連鎖からの switch、
  定数除算・剰余の復元、スタック変数、
  ブロックをまたぐ定数伝播、レジスタから値ごとの変数への分離、戻らない関数の判定
  （本体のどの経路も return に届かないことを、関数をまたいで繰り返し確かめる）、
  呼び出しの引数と戻り値（呼び出し先が読む整数・浮動小数点の引数の数を関数間で求め、`v = f(a, b)` の形で出す。
  2 つ目以降の戻り値も変数に移す）、GOT のスロットを通る取り込んだ関数の呼び出しを名前とプロトタイプで出す、
  例外表からのランディングパッド（届く呼び出しの範囲を注記し、受け取る例外を `exception` と書く）、
  呼び出しをまたいで退避した引数を引数のまま読む、Go の ABI（xmm15 のゼロ、書き込みバリア、スタック伸長の検査、
  アセンブリ関数のスタック渡しの引数、複数の戻り値）、文字列をその場に `"..."` と書く（Go と Rust の長さ付きの文字列も）、
  compare-and-exchange を `__sync_val_compare_and_swap` と書く
- **疑似 C**: 支配木に基づいて if / else、while、do-while、for (;;)、switch、早期 return を構造化し、
  構造化できない部分（還元不能なフローなど）だけをラベルと goto で出す。カウンタを初期化して比べ、最後に進める
  while は for にする。型付きポインタの演算は
  要素単位（`p[i]`、`p + 1`）で書き、C として読んで値が変わらない形を保つ
- **命令**: 整数命令のほぼすべて（回転・バイト反転・交換・ビットテスト・2 倍幅の除算・CRC-32 を含む）と、
  浮動小数点演算（四則・平方根・積和・整数との変換・比較、パックした形も）、SSE と AArch64 のベクトル演算の主なもの
  （レーンごとの算術・飽和演算・比較・シフト・パック・ビット数え、AArch64 の 2 倍の幅に広げる加減算と乗算・積和、
  半分の幅に狭める変換とシフト、レーンの並べ替え、浮動小数点のベクトル演算と整数との変換）、AES の 1 ラウンド、システムコール。
  xmm と AArch64 のベクトルレジスタは 64 ビットの半分 2 つとして、ymm はさらに上位の 128 ビットを 2 つとして扱い、
  AVX の転送・ビット演算・レーン演算を持ち上げる。どれも実機との比較テストで確かめている

## 既知の制限

- 一部のベクトル演算（AArch64 の飽和するシフト、2 倍して飽和する乗算（`sqdmulh` など）、半精度の浮動小数点、
  浮動小数点の最大・最小など）とシステム命令は未対応で、
  出力に `unsupported` と明示します
- 引数の数が分からない呼び出し（プロトタイプの表にない取り込んだ関数、間接呼び出し）は、引数を出さず `f()` の形で出ます
- 値で渡す構造体の引数は、スタックで渡すもの（x86-64）は 1 つの構造体の引数として出ますが、レジスタで渡す小さなものは
  まだ 8 バイトごとの引数として出ます
- デバッグ情報がない場合、構造体のフィールド名は `field_0x8` のようにオフセットで表します。
  構造体の配列は、まだ要素の型を持つポインタとしてしか表せません
- DWARF の引数は、宣言順が ABI のレジスタ順と一致する場合にだけ正しく対応づきます

これらへの取り組みは [docs/ROADMAP.md](docs/ROADMAP.md) にあります。

## ドキュメント

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): 解析の流れと各モジュールの責務
- [docs/ROADMAP.md](docs/ROADMAP.md): 目指す設計と進める順序

## テスト

テストの入力は `tests/fixtures/` のバイナリです。`tests/cases/` のソースから、コンパイラの版を
固定したコンテナ（版は `tests/fixtures/toolchain.txt`）で生成してリポジトリに含めているので、
どのマシンでも同じバイト列をテストします。生成物にビルド環境のパスが残らないことは、生成時に確かめています。

```bash
cargo test                # ユニットテストと結合テスト
./tests/smoke.sh          # CLI と MCP の出力、性能
./tests/ladder.sh         # 難易度別の期待値
```

| テスト | 確かめること | 正解 |
|---|---|---|
| `src/lift/hardware/` | lift した命令が実機と同じ結果になる（AArch64 は arm64 の macOS、x86-64 は C コンパイラのある環境で実行） | 実機での実行 |
| `src/analysis/semantics_tests.rs` | 最適化が関数の動作を変えていない（IR を実行して比べる） | 最適化前の IR |
| `tests/invariants.rs` | 飛び先のない goto、代入されないレジスタの読み取り、疑似 C での文の欠落がない | 出力の性質 |
| `tests/metrics.rs` | 関数の発見、引数と戻り値の推定の正解率 | デバッグ情報（`*.debug.elf`） |
| `tests/golden.rs` | 全テスト用バイナリの関数一覧、疑似 C、IR、シグネチャ、要約と、読みやすさの数（変数・キャスト・レジスタ名・goto など）が変わっていない | `tests/golden/fixtures/` と `tests/golden/readability.txt` に記録した出力 |
| `tests/api.rs` | スクリプト API の戻り値が `.d.ts` の宣言と一致する | `src/script/api/` |
| `tests/robustness.rs` など | 壊れたファイルやランダムな命令列で panic しない | なし |
| `tests/smoke.sh` | CLI と MCP の出力の要所、性能 | 文字列の照合 |
| `tests/ladder.sh` | 難易度 L0〜L7 の期待値（種別が `known_*` の行は、まだ満たせていない目標） | `tests/expect/ladder.tsv` |

正解率、不変条件の違反、動作の違いは、今の値を `tests/golden/` に記録しています。値が変わると
テストは失敗し、どの関数がどう変わったかを示します。意図した変更なら、環境変数 `VELK_BLESS=1` を付けて
`cargo test` を実行すると記録が更新されるので、差分を確かめてからコミットします。

### テスト用バイナリの再生成

```bash
docker compose run --rm fixtures   # tests/cases/ から tests/fixtures/ を作り直す
docker compose run --rm check      # 同じコンテナでテストを回す
```

### LLM による意味の確認

`uv run tests/review.py [REVISION]` は、指定したリビジョンから疑似 C が変わった関数について、
元のソースと新旧の疑似 C を並べた `tests/out/review.md` を作ります（`--all` で全関数）。
LLM がそれを読んで意味が同じかを判定し、結果を `tests/review/verdicts.tsv` に残します。
判定は合否には使わず、ほかのテストでは見つからない誤りを探すために使います。

## ライセンス

未定です。
