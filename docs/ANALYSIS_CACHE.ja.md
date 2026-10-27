# 解析結果の保存

[English](ANALYSIS_CACHE.md) | 日本語

バイナリを開くと、検出した関数と範囲、ライブラリシグネチャの照合結果、
例外情報、計算済みの呼び出し要約を保存します。参照の索引は最初の問い合わせが
完了した後に保存します。後で起動したプロセスはこれらを再利用します。
関数の C は要求時に生成します。参照の索引も、問い合わせで必要になった時に読み込みます。

既定の保存先は、正規化したバイナリの隣にある `<binary>.velk-cache` です。
注釈を保存する `<binary>.velk.json` とは別のファイルです。
キャッシュはいつでも削除できます。注釈はプロジェクトファイルに保持します。

保存先の変更と読み書きの無効化は、次のように指定します。

```sh
velk --functions app.elf --cache analysis.json
velk --functions app.elf --cache off
VELK_CACHE=analysis.json velk --functions app.elf
VELK_CACHE=off velk --functions app.elf
```

CLI の指定は `VELK_CACHE` より優先します。JavaScript と MCP のスクリプトでは、
同じ open オプションを使います。この指定も環境変数より優先します。

```js
const b = velk.open("app.elf", {cache: "analysis.json"});
b.getFunction("main").decompile();
const uncached = velk.open("app.elf", {cache: false});
uncached.getFunction("main").decompile();
```

`cache` を省略すると環境変数または既定の場所を使います。`cache: true` は
既定の場所を選びます。MCP の `velk_run_script` でもこのスクリプトを実行できます。

バイナリの内容、velk のバージョンとビルド、キャッシュ形式、アーキテクチャと
ヘッダーなしコードの配置、シグネチャのオプションとデータベースの内容、
外部 PDB の内容、プロジェクトの注釈が一致した場合にのみ再利用します。
コメントを含め、プロジェクトに変更があれば再計算します。壊れたファイル、
不完全なファイル、一致しないファイルは診断なしで無視して再作成します。
読み込むキャッシュは 256 MiB 以下に制限します。書き込みには別ファイルと
アトミックな名前変更を使うため、同時に実行するプロセスは完全なファイルを読みます。
書き込みが失敗しても解析は続き、開いたバイナリごとに一度だけ診断を表示します。
バイナリ、プロジェクト、選択したシグネチャデータベースをキャッシュで置き換えることはできません。

問い合わせで得た要約や索引は、バイナリのハンドルを解放すると保存します。
ハンドルを通じて明示的にシグネチャを照合した場合は解析オプションが変わるため、
そのハンドルからの以後の保存を止めます。

開く時間と最初の C・参照問い合わせの時間を別々の 2 プロセスで測るには、
`cargo build --release` の後に
`uv run tools/measure_analysis_cache.py --library LIBRARY` を実行します。
このスクリプトは所要時間とキャッシュのサイズを表示します。サイズが最大の
Rust フィクスチャ 2 個、Go フィクスチャ 1 個と、指定したシステムライブラリを使います。
`--binary` で別の velk 実行ファイルを指定できます。
