# Go のローカル領域

`tests/scripts/local_usage.py` は CLI の関数全体の出力にある宣言を分類します。
以下は `go_probe`、`go_stripped`、`go_probe_arm64`、`go_stripped_arm64` の
ランタイムを含む 5,088 関数が対象です。構文上の分類では 69,293 宣言が見つかります。
レジスタの束縛や匿名の結果領域も含むため、名前付き変数の読みやすさ指標とは
数え方が異なります。分類は出力された定義についてのものであり、Go のソース変数を
復元して識別したものではありません。

| 定義または領域 | 数 | `go_probe` の例 |
| --- | ---: | --- |
| 複数の定義、または認識できた定義なし | 18,330 | `internal/abi.Name.IsBlank`: `v1` |
| その他の計算値 | 15,750 | `internal/abi.Kind.String`: `v1` |
| メモリ読み出し | 13,732 | `internal/abi.Kind.String`: `v4` |
| スタックスロットまたはオブジェクト | 9,985 | `internal/abi.(*Kind).String`: `local_0` |
| 呼び出しを含む式 | 6,049 | `type:.eq.internal/abi.RegArgs`: `v1` |
| 定数 | 2,531 | `runtime.memhashFallback`: `v3` |
| 配列、集約値、または `&` の後のオペランド | 1,362 | `internal/cpu.doinit`: `call_values` |
| 同じ型のレジスタコピー | 1,174 | `internal/cpu.processOptions`: `v56` |
| 同じローカルからの繰り返しコピー | 326 | `runtime.chansend`: `v15` |
| 型が判明している文字列、スライス、インターフェースのヘッダー | 54 | `runtime.(*mheap).sysAlloc`: `string` |

`&` の分類は保守的で、ビット演算のオペランドも含む場合があります。
コピー元が後続の読み出しまでに変化することもあるため、構文上のコピー数は
削除可能な変数数ではありません。スタックスロットには退避値、結果、ループの状態、
アドレスが外に渡るオブジェクトなどが入ります。この分類ではそれらの履歴を区別しません。

リリースビルド後、次のコマンドで分類を再現できます。

```sh
for fixture in go_probe go_stripped go_probe_arm64 go_stripped_arm64; do
    target/release/velk -D "tests/fixtures/$fixture" '*' > "target/$fixture.c"
done
uv run python tests/scripts/local_usage.py target/go_probe.c target/go_stripped.c \
    target/go_probe_arm64.c target/go_stripped_arm64.c
```

保存された引数のすべての別名が入口の値だけを保持する場合、元の C 引数を使います。
引数レジスタにある未使用の結果の束縛は、この置換を妨げません。
後続ブロックで結果が読まれ得る場合は、生存解析によって束縛を残します。
宣言された結果の束縛や、解析できない制御フローがある場合も束縛を残します。
例えば `runtime.convT` は、別のスタックコピーを作らず `a1` を
`runtime_typedmemmove` に渡します。

構造化後のコピーは、すべての定義が同じ値をコピーし、すべての読み出し位置で
コピー元が変わっておらず、出力される型も一致する場合だけ削除します。
読み出し幅は維持します。コピー元が別の削除候補であるコピーは残し、同時の置換によって
元の値の生存期間が延びないようにします。呼び出し引数の束縛に関わるコピーも残します。
キャスト数、行数、goto 数が増えない場合だけ、レンダラーが変換結果を採用します。

`tests/recompile/go_locals.rs` は出力された C をコンパイルして実行し、
保存値、ポインタ引数、コピー元の上書き、依存するコピーの連鎖を検査します。
読み出し幅と、分岐やループでのコピーの有効性は単体テストでも検査します。
制御フローと ABI の規則は記号的な等価性モデルの対象外であり、
`tests/smt_inventory.tsv` にその検証範囲を記録しています。
