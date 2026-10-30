# 疑似Cの命令アドレス

`--addresses` を付けると、対応する命令が確実に分かる文の行末に
`/* 0x... */` を追加します。

```sh
velk -D --addresses tests/fixtures/l2_loop_x64.o sum_while
velk -D --json tests/fixtures/l2_loop_x64.o sum_while
```

100桁以内に収まる場合は関数ごとにコメントの位置を揃え、長い行では空白を1つ
挟みます。このオプションがなければ疑似Cの出力は変わりません。

文を置き換える場合は、出力する効果を実行するストア、呼び出し、分岐、リターンの
命令アドレスを引き継ぎます。共通化する効果のアドレスは、元のアドレスがすべて
一致する場合だけ保持します。複数の条件を結合した場合や、合成した制御フローなど、
1つの命令を確実に特定できない場合はコメントを付けません。波括弧、宣言、単独の
`else` にも付けません。異なる命令をまとめた `for` のヘッダーにも付けません。

`-D --json` は `code` と `addresses` を持つオブジェクトを返し、アドレスコメントを
自動的に有効にします。`addresses` は `code` の行番号（1から始まる）をキーとし、
16進数のアドレス文字列のリストを値とします。対応が不明な行は含みません。
行番号は共通の宣言部分を含む、結合後の出力全体に対応します。

JavaScriptのオプションはMCPと `--serve` からも利用できます。

```js
const b = velk.open("tests/fixtures/l2_loop_x64.o");
b.getFunction("sum_while").decompile({addresses: true});
```

各呼び出しでの既定値はfalseです。Rustでは逆コンパイルの前に
`Binary::set_instruction_addresses(true)` を呼び出して指定できます。
