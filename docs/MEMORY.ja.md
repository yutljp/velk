# バイト列の検索、メモリの値、標準的な定数

CLI の三つの操作はいずれも JSON を返します。JavaScript の各メソッドは
MCP の `velk_run_script` でも利用できます。

## 検索

```sh
velk --search app '48 8b ?? 24' --section .text
velk --search app 'hello' --encoding ascii
velk --search app 'hello' --encoding utf16 --byte-order big
velk --search app 0x12345678 --encoding integer --width 4 --byte-order little
```

```js
const b = velk.open("app");
b.search("48 8b ?? 24", {section: ".text", start: "0x1000", end: "0x2000"});
```

16 進数のパターンは空白で区切った 2 桁の数値です。`??` は任意の 1 バイトに
一致します。ASCII は ASCII 以外の文字を拒否し、UTF-16 は必要に応じて
サロゲートペアを使います。整数は 10 進数または 16 進数の文字列で、負数は 2 の補数表現です。
幅は 1、2、4、8 バイトです。範囲を超える値は拒否します。既定の形式は hex、
バイト順はイメージのバイト順です。テキストの終端のゼロは検索に含みません。

ロード対象のセクションを検索し、ファイル内に実体がないゼロ初期化セクションも含めます。
一致は 65536 件までです。超える場合は範囲やパターンを絞ってください。`--start` は
含み、`--end` は含みません。`--section` はセクション名の完全一致です。一致する
全バイトが指定範囲と単一のセクションに収まる必要があります。重なる一致も
返します。`matches` の各要素には `addr`、`section`、その位置を含む `function`
のアドレスが入ります。検出された関数の範囲外では function は null です。

## 値の読み取り

```sh
velk --read-memory app 0x1000 --type u32 --count 4
velk --read-memory app record --type 'struct sample'
velk --read-memory app 0x2000 --type 'u16[3]'
```

```js
b.readMemory("record", "struct sample");
b.readMemory("0x1000", "u64", {count: 2});
```

型は `u8/u16/u32/u64`、`i8/i16/i32/i64`、`f32/f64`、`pointer`、`cstring`、
`utf16`、固定長配列 `TYPE[N]`、デバッグ型情報にある名前付き構造体です。
個数の既定値は 1 です。構造体はフィールド名を持つオブジェクト、配列は
入れ子の配列として返します。文字列は終端のゼロを含めて次の位置に進みます。
未マップまたはセクション境界をまたぐ読み取りは、
アドレスと要求サイズを含むエラーになります。文字列は同じセクション内で
終端する必要があります。C 文字列は正しい UTF-8、UTF-16 は正しいサロゲート
ペアを要求します。

バイト順とポインタ幅はイメージに従います。ゼロ初期化セクションはゼロとして読み取ります。64 ビット符号なし整数とポインタは
16 進数の文字列、64 ビット符号付き整数は 10 進数の文字列です。小さい整数と
有限の浮動小数点数は JSON の数値、非有限の浮動小数点数は文字列です。
結果には `addr`、`type`、`values`、消費した合計の `bytes` が含まれます。
制限は入れ子のフィールドや要素を含めて 65536 個、深さ 16、16 MiB です。
未対応または曖昧なデバッグレイアウトは拒否します。ビットフィールドは省略し、共用体は
未対応です。符号の有無が不明な char フィールドは拒否します。デバッグ型の読み込みは現在リトルエンディアンに対応しています。
注釈による型はメモリレイアウトには使いません。

## 定数の検出

```sh
velk --detect-constants app
```

```js
b.detectConstants().matches.slice(0, 10);
```

シグネチャは `src/tables/signatures.json` にあります。AES の正逆 S-box と
ラウンド定数、MD5 と SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 の初期値と
ラウンド定数、CRC32、CRC32C、反射型 CRC64-ECMA、CRC64-ISO、正方向の
CRC64-ECMA テーブル、base64/base64url の文字集合、ChaCha/Salsa の鍵定数、
TEA の delta、16 ビット要素の deflate 長さ・距離の基底値を含みます。
数値テーブルは両方のバイト順を確認します。一部だけの一致や変更された
テーブルは一致しません。検査はすべて同じデータリストに従います。

データは実行可能でないロード対象セクションから完全一致で探します。コードは
デコードした命令の即値を調べ、有効にされたシグネチャの全ワードが同じ検出済み
関数に現れることを要求します。ビッグエンディアンの命令即値と、複数の命令で組み立てられる値は検出しません。
TEA delta など単独の値の完全一致は、その関数のアルゴリズムを証明しません。

一致には `name`、`addr`、`size`、`kind`（`data` または `immediates`）、
`section`、`byteOrder`、`functions` が含まれます。データでは一致範囲内の
任意のバイトへの相互参照から関数を集めます。即値ではその関数と最初の一致命令を
返し、section と byteOrder は null です。解析失敗は `failures` に返します。
解析できなかった参照は含まれない場合があります。

データの完全一致では、印字する C の参照先グローバルに `aes_sbox` などの名前を
付けます。同じ開始アドレスに複数が一致する場合は長い一致を優先します。
変更するのは名前であり、値、アクセス幅、式の表現は維持します。

定数の出典は [AES](https://doi.org/10.6028/NIST.FIPS.197-upd1)、
[SHA](https://www.rfc-editor.org/rfc/rfc6234.html)、
[MD5](https://www.rfc-editor.org/rfc/rfc1321.html)、
[ChaCha](https://www.rfc-editor.org/rfc/rfc8439.html)、
[deflate](https://www.rfc-editor.org/rfc/rfc1951.html) です。
フィクスチャのソースは `tests/cases/memory/` にあり、
`sh tests/make_memory_fixtures.sh` で x86-64、i386、AArch64、ARM、Thumb、
ビッグエンディアン AArch64 のイメージを `tests/data/byte_search/` に作ります。
`cargo test --release --test memory -- --test-threads 3` はこれらを使い、CLI、
JavaScript、MCP の各インターフェースを検証します。

既存フィクスチャの一致は `tests/data/byte_search/corpus_matches.txt` に 10 件
記録されています。`go_probe`、`go_stripped` とそれぞれの ARM64 版では ChaCha の
定数、`rust_demo`、`rust_probe`、`rust_probe_stripped` では deflate の距離・長さの
基底値です。名前のある Go の参照先は `internal/chacha8rand.block`、Rust は
`miniz_oxide::inflate::core::decompress` と `decompress_fast` です。シンボルを
除去した版にも、記録した位置に同じバイト列があります。このコーパスでは
他のシグネチャの一致はありません。

PE のファイル内のデータ長とメモリ上のセクション長は区別します。ゼロ初期化される末尾を、
次のファイル領域から読み込むことはありません。`section_tail.dll` はこの境界を三つの
インターフェースで確認するフィクスチャです。形式の規則は
[PE 仕様](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)に従います。
