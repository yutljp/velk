<div align="center">

<img width="160" height="160" alt="velk" src="https://github.com/user-attachments/assets/31a1c0c1-3ca4-4d9f-8d88-917cc43bd49e" />

# velk

機械語を、そのままコンパイルできる C に。

[English](README.md) | 日本語

</div>

velk は ELF・PE・Mach-O（x86-64 / AArch64）、ELF32・PE32（x86-32）、リトルエンディアン ELF32（ARM32: A32/T32）を読み、
元のバイナリと同じ計算をする C を出力するデコンパイラです。
コマンドラインのほか、LLM エージェント向けにスクリプト API と MCP サーバを備えています。

```c
int sum_until_zero(int *p, int n) {
    int64_t i;
    int32_t v3;
    int32_t v4;

    if (n <= 0) {
        return 0;
    }
    v3 = 0;
    for (i = 0; i < (uint32_t)n; i++) {
        v4 = p[i];
        if (v4 == 0) {
            break;
        }
        v3 += (v4 <= 0 ? 0 : v4);
    }
    return v3;
}
```

## 機能

- クロスリファレンス、コールグラフ、文字列・定数の検索と関数の要約。
- [構造体レイアウトの復元](docs/STRUCTURES.ja.md)、関数間でのアクセスのビューとストライドの共有、不明なソース宣言を明示した関数カード。
- 組み込みシグネチャで[ライブラリ関数名](docs/LIBRARY_SIGNATURES.ja.md)を自動で復元。musl、mbedTLS、libsodium、OpenSSL libcrypto、Rust 標準ライブラリの共通処理、zlib のチェックサム、xxHash の完全なデータベースは別ファイルで読み込み可能。
- macOS、Windows（Win32 と C ランタイム）、Linux（glibc）の生成済み C API 型ライブラリ。
  Windows の COM vtable フィールドは、`IUnknown`、`IDispatch`、`IStream` を含め、関数の引数・戻り値の型と呼び出し規約を保持します。
  `b.libraryType("struct IUnknownVtbl")` で対象のレイアウトを確認できます。CLI のスクリプトと MCP からも利用できます。
  対応するインターフェイスの型が分かる呼び出しは `object->lpVtbl->Method(object, ...)` と表示します。
  参照する IID と CLSID はヘッダーの GUID 値に基づいて名前を付けます。[Windows COM](docs/WINDOWS_COM.ja.md)を参照してください。
- [解析結果を保存](docs/ANALYSIS_CACHE.ja.md)する `<binary>.velk-cache`。`--cache PATH` または `VELK_CACHE` で保存先を変更し、`--cache off`（`VELK_CACHE=off`）で無効化できます。
- プロジェクトファイルへの名前・型・コメントの永続化（`--project`、`--annotate`）。
- [プログラムのバージョン比較](docs/COMPARISON.ja.md)、C とブロックの差分確認、対応関数への注釈コピー（`--compare`、`--carry-annotations`）。
- C++ RTTI によるクラス名・継承・仮想テーブルの復元（`--classes`）と型付き例外コメント。

C++ の RTTI のクラス名、継承、仮想テーブルは `velk --classes app.elf` で JSON として一覧表示できます。
スクリプトの `b.classes()` と MCP ツール `velk_classes` も同じ情報を返します。型付きの例外情報は
C のコメントとして表示します。フィールドと制限は [C++ のクラスと例外テーブル](docs/CPP_CLASSES.ja.md)を参照してください。

## 使い方

安定版を使うには、ビルド前に最新のリリースタグへ切り替えてください（`git checkout v0.1.0`）。

```bash
cargo build --release --locked

velk --functions path/to/binary          # 関数の一覧
velk --classes   path/to/binary          # C++ クラスを JSON で一覧表示
velk --decompile path/to/binary main     # 疑似 C
velk --decompile path/to/binary          # すべての関数
velk --disasm    path/to/binary 0x1000   # 逆アセンブル
velk --emulate path/to/binary sum3 --emulation-options '{"arguments":[1,2,3]}' # 引数を指定して実行
velk --xrefs     path/to/binary main     # main への参照
velk --strings   path/to/binary          # 参照付きの文字列
```

そのほかの操作は `velk --help` を参照してください。

バイナリ全体の処理には利用可能な CPU コアを使います。`VELK_THREADS=1` でワーカーを 1 個に、
ほかの正の整数でワーカー数の上限を指定できます。結果は関数の順序を保ちます。
Linux ではバイナリのローダーが入力のスナップショットを読み取り専用でメモリにマップし、マップできない場合はファイルを読み込みます。

ユニバーサル Mach-O はこのマシンのアーキテクチャを開きます。別のものは `--arch x86_64`（または `arm64`、`arm64e`）で選びます。

## 生バイト列とパックされた入力

ヘッダーのないコードには命令セット、ロードアドレス、入口を明示できます。
`velk -D --raw-arch x86_64 --load-address 0x7000 code.bin 0x7000`。
スクリプトと MCP でも同じマッピングを使えます。UPX の ELF・PE 入力は
インストール済みの UPX デコーダーで展開し、`--save-unpacked FILE` で成功した
結果を保存できます。[入力形式と制限](docs/INPUT.ja.md)を参照してください。

## 読み込んだコードの実行

`velk --api-docs` で組み込み API のトピックを一覧表示し、
`velk --api-docs emulation` で実行オプションと結果を端末で確認できます。

関数名または仮想アドレスを指定し、引数とメモリーの初期値を渡して実行できます。

```sh
velk --emulate app.elf decode --emulation-options '{"arguments":["0x10000000",6,93],"memory":[{"address":"0x10000000","bytes":[53,56,49,49,50,93]}],"reads":[{"address":"0x10000000"}]}'
```

JSON の結果にはレジスター、整数の戻り値、変更されたバイト、停止理由を含めます。
スクリプトでは `b.emulate(start, options)` または
`b.getFunction(name).emulate(options)`、MCP では `velk_emulate` を使います。
エミュレーションの CLI は既定でテキストを表示し、`--json` で JSON を返します。
`stdin: {text: "candidate\n"}` で入力、`argv` で main の引数を渡せます。
`stdout` と `stderr` に出力を記録します。`reads` はシンボル、アドレス、最終レジスタ値の
メモリを読みます。復号の例、対応するライブラリのフック、エラー、実行の上限は
[読み込んだコードの実行](docs/EMULATION.ja.md)を参照してください。

velk は、バッファー、長さ、鍵が既知の復号関数の呼び出しや、インラインで
スタック上に組み立てる文字列も自動で復元します。復元した文字列はコメントに
表示し、`--strings` の `decodedStrings` 配列にはバッファー、呼び出し位置、
復号関数のアドレスを含めます。`--no-string-decoding` で無効にできます。
使用例と上限は[文字列の自動復元](docs/STRING_DECODING.ja.md)を参照してください。

関数の要約の `apiHashes` には、名前テーブルの走査で使われるハッシュ関数を
実行して得たエクスポート名の候補を含めます。C のコメントにも一致した名前を
表示します。ハッシュだけでは読み込まれたライブラリを特定できないため、
名前は候補として扱います。対応するデータの流れと制限は
[API ハッシュ](docs/API_HASHES.ja.md)を参照してください。

## エージェントから使う

velk が自分でどこかに登録することはありません。`cargo build --release` でビルドしてから、実行ファイルのフルパスを指定して、使うエージェントに自分で登録してください。

```sh
# Claude Code
claude mcp add --transport stdio velk -- /path/to/velk --mcp

# Codex CLI
codex mcp add velk -- /path/to/velk --mcp
```

`mcpServers` 形式の JSON ファイルで設定するクライアントでは、次のように書きます。

```json
{
  "mcpServers": {
    "velk": { "command": "/path/to/velk", "args": ["--mcp"] }
  }
}
```

エージェントは `velk_read_api` で概要と使用例を読み、`velk_run_script` に短い JavaScript を渡して、必要な情報だけを取り出します。

```js
const b = velk.open("/path/to/binary");
b.functions({ named: true }).slice(0, 5).map(f => ({ addr: f.addr, name: f.name }));
```

返信の大きさには上限があります（分割取得とタイムアウトは概要を参照してください）。同じ API はコマンドラインから `velk --run script.js` でも使えます。

バイト列の検索、型を指定したメモリの読み取り、標準的な定数の検出も JSON で利用できます。

```sh
velk --search app '48 8b ?? 24' --section .text
velk --search app 'hello' --encoding ascii
velk --read-memory app 0x1000 --type u32 --count 4
velk --detect-constants app
```

JavaScript API と MCP では `b.search(pattern, options)`、
`b.readMemory(address, type, {count})`、`b.detectConstants()` を使えます。
エンコーディング、範囲、型、完全一致する定数の詳細は
[メモリの問い合わせ](docs/MEMORY.ja.md)を参照してください。

コピーと塗りつぶしの処理を `memcpy`、`memmove`、`memset` の組み込み関数として
表示する場合があります。`velk --summary app function` と JavaScript/MCP の
`f.summary().inlineFunctions` は、復元した呼び出しと定数のバイト数を返します。
[認識の制限](docs/MEMORY.ja.md#インライン化されたメモリ関数)を参照してください。

関数の概要には `signature.callingConvention`、`signature.parameterCount`、
`signature.variadic` と、復元した呼び出し先や引数の個数を示す `calls` 配列が
含まれます。JavaScript の `f.signature()` も同じシグネチャのフィールドを返し、
MCP では `velk_run_script` から取得できます。
制限は[関数のシグネチャ](docs/CALLS.ja.md)を参照してください。

バイナリを開くと、ライブラリシグネチャが自動で適用されます。`velk -f app`
で復元した名前・出典のセット・確実性を確認し、`velk -D app XXH32` で一致した
関数の C を表示できます。`--identify app` では名前を確定できなかった候補も表示します。
組み込みセットを無効にするには `--no-default-signatures` を使います。
`--signatures custom.json` は繰り返し指定でき、独自のセットを追加します。
完全なデータベースは文書の再生成スクリプトで作り、
`--signatures target/library-signatures/libraries.json.gz` で読み込めます。
同じオプションで gzip 圧縮した JSON も扱えます。
JavaScript と MCP では
`velk.open("app", {defaultSignatures: false, signatures: ["custom.json"]})`
を使います。対応範囲・ライセンス・再生成方法・測定結果は
[ライブラリシグネチャ](docs/LIBRARY_SIGNATURES.ja.md)を参照してください。

整数の恒等式や解析で追跡した定数値によって、すべての入力に対して結果が
決まると証明できた条件分岐を除去します。ディスパッチループへ入る状態が
すべて定数の場合は、直接分岐に置き換えられます。遷移先が不明な場合は
ディスパッチャを残します。関数カードと JavaScript/MCP の関数概要の
`simplification` に、`simplified`、`predicatesRemoved`、
`dispatcherStatesRemoved` を返します。[制御フローの簡略化](docs/CONTROL_FLOW.ja.md)を参照してください。

ビット演算と算術演算を混ぜた式を、和、ビット演算、定数、短い多項式に
簡略化します。関数カードとサマリの `simplification.mbaExpressionsSimplified`
は、採用した式の置換の数です。対象となる式と制限は
[式の簡略化](docs/MBA.ja.md)を参照してください。

## ドキュメント

- [API の概要](src/script/api/index.md)
- [アーキテクチャ](docs/ARCHITECTURE.ja.md)
- [テスト](docs/TESTING.ja.md)
- [読み込んだコードの実行](docs/EMULATION.ja.md): CLI、JavaScript、MCP で初期状態と上限を指定して実行します。

## ライセンス

MIT ライセンスです。[LICENSE](LICENSE) を参照してください。
