# テストケース

ここにあるのはフィクスチャのソースです。`tests/make_fixtures.sh` がコンパイルして
`tests/out/` に置きます。生成したバイナリはリポジトリに含めません。

```
tests/cases/
  c/      C
  cpp/    C++(マングル)
  go/     Go(pclntab)
  rust/   Rust(デマングル)
```

## 難易度の段

`tests/ladder.sh` は `tests/expect/ladder.tsv` の期待値を L0 から順に評価します。
易しい段が壊れたら、難しい段より先に直します。

| 段 | 確認すること | 主なケース | ビルド |
|---|---|---|---|
| L0 | 算術、選択、符号がそのまま式になる | `c/l0_arith.c` | `-O2`(AArch64 / x86-64) |
| L1 | 分岐が三項演算子や if になり、goto が残らない | `c/l1_branch.c` | `-O2` |
| L2 | while、do-while、for、break、continue | `c/l2_loop.c` | `-O2`(volatile でループを残す) |
| L3 | 定数除算と剰余の復元(幅と符号) | `c/divmod_a64.c`、`c/divmod_x64.c` | `-O2` |
| L4 | 配列、構造体メンバ、グローバル変数、文字列参照 | `c/l4_memory.c`、`c/strings.c` | `-O1`(`-O2` ではベクトル化でループが消える) |
| L5 | switch(ジャンプテーブル、値テーブル) | `c/l5_switch.c`、`c/switch_jumptable.c` | `-O2` + `ld.lld` |
| L6 | テールコールの境界、6 引数、64bit、strip 済み | `c/l6_abi.c`、`c/tail_*.c` | `-O2`、`llvm-strip` |
| L7 | Go の pclntab、Rust のデマングル、strip 済みバイナリ | `go/*.go`、`rust/*.rs` | `go build`、`rustc -O` |

期待値は `has`(含む)、`nothas`(含まない)、`count`(関数の数)、`has_any`(`A|B` のどれかを含む)で書きます。
コンパイラによって形が変わる箇所には `has_any` を使います。
