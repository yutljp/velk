# テストケース（ソースは追跡、生成物は未追跡）

`tests/cases/` にあるのは**コンパイルされる前のソース**。ビルドは
`tests/make_fixtures.sh` が行い、生成物は `tests/out/`（`.gitignore` 済み）に置く。
大きいバイナリをリポジトリに入れないための分離。

```
tests/
  cases/            ここ（追跡）
    c/              C のケース
    cpp/            C++（マングリング）
    go/             Go（pclntab）
    rust/           Rust（デマングル）
  expect/ladder.tsv 難易度ごとの期待値
  make_fixtures.sh  ソース → tests/out/（未追跡）
  ladder.sh         難易度ラダーの採点
  smoke.sh          詳細な回帰アサーション
  bench.sh          性能
```

## 難易度の段

`ladder.sh` は L0〜L7 の順に評価する。簡単な段が壊れたら、難しい段の
失敗より先に直す。

| 段 | 何を測るか | 主なケース | ビルド |
|---|---|---|---|
| L0 | 算術・選択・符号がそのまま式になる | `c/l0_arith.c` | `-O2`（a64/x64） |
| L1 | 分岐が三項/if として読める。goto を残さない | `c/l1_branch.c` | `-O2` |
| L2 | while / do-while / for・break / continue | `c/l2_loop.c` | `-O2`（volatile でループを保存） |
| L3 | 定数除算・剰余のマジック復元（幅・符号・形） | `c/divmod_a64.c`, `c/divmod_x64.c` | `-O2` |
| L4 | 配列・構造体メンバ・グローバル・文字列参照 | `c/l4_memory.c`, `c/strings.c` | `-O1`（-O2 は SIMD 化してループが消える） |
| L5 | switch（ジャンプテーブル/値テーブル） | `c/l5_switch.c`, `c/switch_jumptable.c` | `-O2` + `ld.lld` |
| L6 | テールコール境界・6 引数・64bit・stripped | `c/l6_abi.c`, `c/tail_*.c` | `-O2` / `llvm-strip` |
| L7 | Go pclntab・Rust デマングル・stripped 像 | `go/*.go`, `rust/*.rs` | `go build`, `rustc -O` |

## ケースを足すとき

1. `tests/cases/<lang>/<name>.<ext>` に**最小のソース**を置く。先頭コメントに
   「何を測るか」「期待する形」を書く。
2. `tests/make_fixtures.sh` にビルドを1ブロック追加する（出力名は
   `<case>_a64.o` / `<case>_x64.o` など、`tests/out/` の中）。
3. `tests/expect/ladder.tsv` に期待値を追加する（`has`/`nothas`/`count`）。
   現状の実装では満たせない理想は `known_has`/`known_nothas` にして TODO に置く。
4. `./tests/ladder.sh --build` で採点し、`./tests/smoke.sh` で回帰を確認する。

## コンパイル環境

| ツール | 必須 | 無い場合 |
|---|---|---|
| `clang` | ○ | 何も作れない（エラー終了） |
| `ld.lld` / `lld-link` | | リンク済み ELF / PE を飛ばす（該当ケースは ladder で SKIP） |
| `llvm-strip` / `llvm-objcopy` | | stripped 像を飛ばす（SKIP）。PATH に無ければ Homebrew の LLVM を探す |
| `rustc` | | Rust ケースを飛ばす（SKIP） |
| `go` | | Go ケースを飛ばす（SKIP）。`GO_BIN=` で指定、無ければ一般的な導入先を探す |

`make_fixtures.sh` は飛ばしたツールを `tests/out/skipped.txt` に記録し、
`ladder.sh` はそのフィクスチャを FAIL ではなく **SKIP** として数える
（ツールチェーンの有無で採点が赤くならない）。

### ツールの探し方

`make_fixtures.sh` は **`which` でコマンドを探す**。場所を決め打ちしないので、
どの環境でも PATH に通っていれば同じように動く。PATH に無いものは環境変数で
差し替える:

```
CLANG / CXX / LD_LLD / LLD_LINK / LLVM_STRIP / LLVM_OBJCOPY / RUSTC / GO_BIN
```

このマシンでの例: Apple clang 21.0.0 (`/usr/bin/clang`)、Homebrew LLD 23.1.3、
rustc 1.98.1、Go 1.27.2 (`/usr/local/go/bin/go`)、LLVM 23 の `llvm-strip`
(`/opt/homebrew/opt/llvm/bin`)。後ろ2つは PATH に追加済み。

### コンパイラの違いと校正

疑似 C の細部（定数除算のマジック列、-O0 のループ構造、マスク省略）は
**コンパイラごとに形が違う**。スイートは Apple clang の形で校正してあり、
`tests/out/toolchain.txt` に記録したコンパイラがそれと違う場合、
`smoke.sh` は該当ブロックを **skip**（FAIL にしない）し、`ladder.sh` は
先頭に使ったコンパイラを表示する。

- 校正済みで回すには、Apple clang を PATH の先に置く
  (`PATH=/usr/local/go/bin:$PATH:/opt/homebrew/opt/llvm/bin`)
- 別の clang で回すと、未対応の形がラダーの赤セルとして見える
  （例: Homebrew clang 23 の `smull` 形式の `sdiv3`）
- `-O2` は実際のバイナリに近いが、コンパイラが形を畳むことがある。
  ループや switch を測りたいときは `volatile` を挟むか `-O1` にする
  （L2 と L4 がその例）。
