# Windows COM

Windows のヘッダー型ライブラリは、対応する関数ポインタのフィールドについて、
引数・戻り値の型と呼び出し規約を保持します。`IUnknown`、`IDispatch`、`IStream` と、
取り込んだ mingw-w64 ヘッダーにあるほかのインターフェイスの vtable も対象です。
フィールドのオフセットと幅は x86-32 と x86-64 ごとに保持します。型やアラインメントを
通常の構造体で表現できないフィールドは、パディングとして残します。

インターフェイスの型と対応するメソッドの宣言が分かる場合、次のように表示します。

```c
uint32_t com_release(struct IUnknown *object) {
    return object->lpVtbl->Release(object);
}
```

この表示には引数の数と呼び出し規約が一致することが必要です。引数は整数かポインタで、
戻り値は最大 32 ビットの整数でなければなりません。使用する戻り値のビット数も確認します。
保存した vtable の値を式に置き換えるのは、読み込みが呼び出しの直前にあり、読み手が一つの
場合だけです。それ以外は間接呼び出しの表示を保ちます。スロット番号だけでインターフェイスの
型を推測しません。x86-32 で引数の数が不明な stdcall を復元する処理は、呼び出しが一つの
単一ブロックで、デバッグ情報に整数・ポインタの引数の型がすべてある場合を対象とします。
それ以外で引数の数が不明な場合は、デコンパイルできないことがあります。

参照する IID と CLSID の値は、ヘッダーから生成した定数と照合します。16 バイトすべてが、
ファイルに裏付けられた一つの読み取り専用データセクション内にあることを確認します。
一致するすべての名前、GUID の文字列表記、格納されたバイト列を返します。一致しない値に
GUID の注釈は付けません。出力するデータのアドレスに既存の名前がある場合は保持し、
ない場合はヘッダーの名前を付けます。宣言はバイト配列で、元のアドレスをコメントに記録します。

JavaScript、CLI のスクリプト（`velk -r script.js`）、MCP の `velk_run_script` から
同じ情報を取得できます。

```js
const b = velk.open("tests/fixtures/com_x86_64.dll");
({
  vtable: b.libraryType("struct IUnknownVtbl"),
  code: b.getFunction("com_read").decompile(),
  references: b.getFunction("com_unknown_id").references()
});
```

`libraryType()` は利用できないレコードに対して `null` を返します。フィールドの `function`
には `parameters`、`returnType`、`callingConvention`、`variadic` があります。
各参照の `guid` は、一致しない場合は `null`、一致する場合は `names`、`value`、`bytes` を持つ
オブジェクトです。

フィクスチャは次のコマンドで再生成します。

```sh
docker compose run --rm fixtures sh tests/scripts/make_com_fixtures.sh
```

フィクスチャは x86-32 と x86-64 の PE で `CreateStreamOnHGlobal`、`IUnknown`、
`IDispatch`、`IStream` を使います。テストでは検出した全関数を対象の Windows 向けに
コンパイルします。ネイティブ実行では、引数・戻り値・出力先への書き込みを確認するスタブを使い、
六つのメソッドのラッパーを 262 入力、二つの最適化レベルで実行します。この実行だけは
32 ビットのポインタのアラインメントをホストの 64 ビットレイアウトに合わせます。
対象向けのコンパイルでは出力した C をそのまま使います。GUID のテストは全バイトを照合します。
Windows のサービスや PE バイナリ自体を実行するテストではありません。

生成時のコンパイラとヘッダーのハッシュは `windows.json` に記録します。ヘッダーの
ライセンス表記は [windows.LICENSE](../src/analysis/prototypes/windows.LICENSE) に保持します。
