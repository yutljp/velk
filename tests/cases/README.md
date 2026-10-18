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

## 構造化の現在地

`ladder.tsv` の `known_*` は手元で全て解消した。決め手になったのは
**2 通りに構造化して、ラベルの少ない方を採る**方式:

- アドレス順のまま構造化する（従来どおり）
- 深さ優先で並べ替え、壊れた fallthrough を `Br` で明示化してから構造化する

グラフは同じなので、どちらも同じプログラムを表す。並べ替え側だけが使う形:

| 形 | たとえば |
|---|---|
| 後方 `Br` で閉じるループ | `for (;;) { … }` |
| ループ出口への `Brif` | `if (c) { break; }`  |
| `if (c) goto L; …; L:` | `if (!c) { … }` |

`l2_loop_a64.o/sum_skip_odd` はこれでソースどおりの形になり、ラベルが消えた:

```c
for (;;) {
    if (x9 & 0x1 != 0x0) { x8 = w8 + w9; *(uint32_t *)(x10) = w8; }
    x9 = w9 + 0x1;
    if (a0 == w9) { break; }
}
```

正本（clang 18）の `arm64_jumptable.elf/d7` も、現在は `switch (a0)` として
構造化され、`goto L_` を残さない。比較木 → switch の再構成では、単純な比較列だけでなく
一意な条件付き predecessor が保証する入力範囲も使う。これにより、外側で `x > 4`
と判定された後に 5..9 を処理する入れ子の dispatch を完全な連続 case として復元し、
複数の switch arm が返却 epilogue のコードを共有しても本体を inline できる。
`structure_best` は従来どおり、結果としてラベルが減る場合だけ変換を採る。
L5 の `goto L_` 不在は `nothas` の必須期待値へ昇格済み。

