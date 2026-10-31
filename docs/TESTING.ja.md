# テスト

[English](TESTING.md) | 日本語

velk の出力を変えるのは、以下のチェックがすべて通った場合だけです。このドキュメントでは、チェックの内容と実行方法、
テスト用バイナリの再生成方法を説明します。

## 必要なもの

- Rust (stable) と C コンパイラ
- 出力した C をコンパイルするチェック用の `clang`
- Python の補助スクリプト用の [uv](https://docs.astral.sh/uv/)
- テスト用バイナリの再生成と、基準となる Linux 環境でのテスト実行には Docker

## チェックの実行

リポジトリのルートで実行します。

```bash
export UV_CACHE_DIR=target/uv-cache
cargo build --release
cargo test --release -- --test-threads 3
cargo fmt -- --check
cargo clippy --release --all-targets -- -D warnings
BIN=target/release/velk bash tests/scripts/smoke.sh
BIN=target/release/velk bash tests/scripts/ladder.sh
```

- `tests/scripts/smoke.sh` はコマンドラインと MCP サーバーを端から端まで動かして確認します。
- `tests/scripts/ladder.sh` は難しさの異なる関数で期待する結果を確認します。`known_*` の行はまだ達成できていない目標です。

## テストが確認すること

- **命令の意味。** lift した各命令を CPU 上と IR インタプリタで多数の入力に対して実行し、結果が一致することを確かめます。
  同じアーキテクチャのホスト (Apple シリコンで x86-64 を試す場合は Rosetta) が必要です。ARM32 と x86-32 の整数命令のチェックは Docker の
  `linux/arm/v7` と `linux/386`、各ターゲット対応の clang、`ld.lld` を使い、Docker の実行環境が利用できない場合は理由を表示してスキップします。
- **最適化パス。** テスト用バイナリのすべての関数を最適化の前後でインタプリタ実行し、結果が一致することを確かめます
  (`tests/golden/semantics.txt` が空であること)。
- **再コンパイル。** 各テスト関数の出力した C をコンパイルして実行し、レジスタの結果とメモリへの影響の両方を IR インタプリタと
  比べます。`tests/golden/recompile.txt` と `tests/golden/recompile_memory.txt` の `differ` はすべて 0 でなければなりません。
- **全関数のコンパイル。** すべてのテスト用バイナリのすべての関数について、出力した C を標準ヘッダと一緒にコンパイルします。
  時間がかかるため `#[ignore]` になっています。
  `cargo test --release --test recompile every_fixture_function_compiles -- --ignored --test-threads 3` で実行します。
  通常のテストでは一部だけを高速に確認します。
- **ゴールデン出力。** `tests/golden/` には各テスト用バイナリの期待出力と、読みやすさの指標 (行数、変数、キャスト、goto)
  が入っています。これらのファイルの変更はすべてレビューしてください。

C のチェックに使うコンパイラは `VELK_TEST_CC` で指定できます (既定は `clang`)。Homebrew の新しい clang がある場合は、
一部のチェックをそれでも実行します。新しいコンパイラは古いものが受け付ける型変換の一部を拒否するためです。

再コンパイルのチェックは関数をまとめてコンパイルし、最大 3 ワーカーで処理します。
コンパイル・実行結果と IR の期待値を `target/recompile-cache/` にキャッシュし、入力が変わらない場合に再利用します。

## ゴールデンファイルの更新

出力の変更が意図したものであれば、ゴールデンファイルを再生成して差分を確認します。

```bash
VELK_BLESS=1 cargo test --release -- --test-threads 3
git diff tests/golden
```

## 差分テスト

テストスイートとは別に、ランダムに生成した C プログラムでもテストしています。プログラムをコンパイルし、関数を 1 つずつ
velk の出力に置き換え、同じ結果を出力し続けることを確かめます。arm64 と x86-64 で実行しており、この方法で正しさのバグを
多数見つけています。

## テスト用バイナリの再生成

ソースは `tests/cases/` にあります。通常のテスト実行ですべてのコンパイラとターゲットを必要としないよう、バイナリはリポジトリに
含めています。再生成するには次を実行します。

```bash
docker compose run --rm fixtures
```

バージョンを固定した同じ Linux 環境でテストを実行するには `docker compose run --rm check` を使います。

C API 型ライブラリは `UV_CACHE_DIR=target/uv-cache uv run tests/scripts/generate_type_library.py` で、
その Mach-O フィクスチャは `sh tests/scripts/make_type_library_fixtures.sh` で再生成します。

Windows と Linux のデータとフィクスチャは参照環境で生成します。

```sh
docker compose build fixtures
docker compose run --rm fixtures uv run tests/scripts/generate_type_library.py --platform windows
docker compose run --rm fixtures uv run tests/scripts/test_generate_type_library.py
docker compose run --rm fixtures uv run tests/scripts/generate_type_library.py --platform linux
docker compose run --rm fixtures sh tests/scripts/make_type_library_fixtures.sh linux
```

Windows データとリフターは x86-64 と x86-32 に対応します。
Linux のデータとフィクスチャは x86-64 と AArch64 を対象とします。各ターゲットの
コンパイラーで宣言とパディングを含む構造体のサイズ、アラインメント、フィールドのオフセットを検証します。

関数ポインタのフィールドは、呼び出し規約を含む型の互換性もコンパイラで確認します。
Rust のテストでは、出力された宣言を Windows の両対象向けにコンパイルします。
型やアラインメントを表現できないフィールドはパディングとして残します。
ヘッダーのライセンス表記は [windows.LICENSE](../src/analysis/prototypes/windows.LICENSE) にあります。

スクリプト API は、メソッドの引数・戻り値の型と呼び出し規約を含むレイアウトをデータとして返します。
次の例は CLI の `-r` と MCP の `velk_run_script` でも実行できます。

```js
const b = velk.open("tests/fixtures/type_library_windows.win64.exe");
b.libraryType("struct IUnknownVtbl");
```

一部のグループには専用のスクリプトがあります。`tests/scripts/make_pe_fixtures.sh` (Windows PE)、`tests/scripts/make_codeview.sh`
(CodeView / PDB)、`tests/scripts/make_seh_fixtures.sh` (Windows SEH)、`tests/scripts/make_objc_fixtures.sh` (Objective-C)、
`tests/scripts/make_arm64_lang_fixtures.sh` (AArch64 の Rust と Go) です。再生成は意図して行い、変わったバイトと記録された
ツールチェーンのバージョンを確認してください。

ARM32 A32/T32 は `sh tests/scripts/make_arm32_fixtures.sh`（ARM 対応 clang と `ld.lld` が必要）、x86-32 ELF・PE は
`bash tests/scripts/make_i386_fixtures.sh` で、それぞれ `-O0` / `-O2` のフィクスチャを再生成します。

## 性能

1 関数のデコンパイルは高速であるべきです。バイナリ全体の処理速度を比べるには次を実行します。

```bash
uv run tests/scripts/throughput.py target/release/velk tests/fixtures/go_probe
```

## 任意実行の有界検証、ファジング、Miri

これらは既定のテストとは別に実行します。Kani、Miri を含む nightly Rust、
`cargo-fuzz`、uv が必要です。ファズ用パッケージは初回ビルド時に `libfuzzer-sys` を取得します。
以下のコマンドは現在のチェックアウトの `target/` を使います。他のチェックアウトと共有しないでください。

```sh
sh tests/scripts/verify.sh kani
sh tests/scripts/verify.sh fuzz
sh tests/scripts/verify.sh miri
# 各検査の失敗を保持して、3 種類すべてを実行:
sh tests/scripts/verify.sh all
```

Linux では、スクリプトは 1 分間の負荷がプロセッサ数の 2 倍を超えている間は待機します。
既定ではビルドを 5 並列、テストを 5 スレッドで実行します。小さいマシンでは
`CARGO_BUILD_JOBS=2` を指定してください。各ハーネスの CBMC 検証には 300 秒の制限を設けます。
コンパイルと準備には別途時間がかかります。時間切れは証明成功ではなく失敗です。個別に実行するには
`cargo kani --lib --harness instruction_word` のように指定します。スクリプトは最大
`CARGO_BUILD_JOBS` 個のハーネスを並列に実行します。

すべてのハーネスは `cfg(kani)` の下にあります。Kani はパニック、算術オーバーフロー、
メモリアクセスと、ループの展開上限を検査します。成功時に保証されるのは下表の範囲と
事前条件だけです。任意サイズのバイナリや逆コンパイル全体の安全性を保証するものではありません。

オブジェクト読み出しの検査は、固定したリトルエンディアンのヘッダー配置と、残りの
任意のフィールドを使います。ELF は生のセクションデータと REL/RELA 配列、PE は
セクションデータと再配置の読み出しを検査します。セクション、空でないデータ、
ELF の REL/RELA 配列、PE の COFF 配列、Mach-O の再配置配列への到達性を確認します。
PE の汎用セクション再配置イテレータは空なので、ヘッダーから COFF 表を直接読みます。検証ホストでは CPU 機能検出が未対応のアセンブリに
到達するため、セクション名は検索しません。ELF のシンボル表と再配置マップも構築しません。
Mach-O は生のヘッダー、セグメント、セクションオフセット、データ、再配置のリーダーを使い、
上位のファイル型の構築やセクション名による分類は行いません。例外値とイメージ範囲の
検査は、ランダム化されたマップを持つイメージを構築せず、読み込み時と同じ純粋関数を呼びます。

この表の秒数は、2026-10-27 UTC に x86-64 Linux 上で Kani 0.68.0、CBMC 6.11.0 を
使った CBMC 実行時間です。全ハーネスの 5 並列実行と、対象を選んだ 1〜3 並列の実行結果を
合わせています。コンパイルと準備の時間は含みません。
スクリプトはハーネスごとの結果を `target/verification/kani.json` に保存します。

| ハーネス | 入力範囲と追加の表明 | 検証秒数 | 結果 |
| --- | --- | ---: | --- |
| `elf32_tables` | 136 バイト。固定の ELF32 ヘッダー、ヌルセクションと任意の 1 セクション。データ長 0–24 バイト、任意のデータオフセットと残りのメタデータ。プログラムヘッダーなし。 | 61.49 | pass |
| `elf64_tables` | 200 バイト。同じ構成と上限の ELF64。 | 58.25 | pass |
| `pe32_tables` | 352 バイト。固定の PE32 配置、1 セクション、COFF 再配置 0–1 個。任意のセクションオフセットとサイズ。シンボルとデータディレクトリなし。 | 51.41 | pass |
| `pe64_tables` | 368 バイト。同じ構成と上限の PE32+。 | 33.27 | pass |
| `macho32_tables` | 152 バイト。32 ビットのセグメントコマンドとセクションを各 1 個、再配置 0–1 個。任意のオフセット、アドレス、サイズ。 | 88.87 | pass |
| `macho64_tables` | 184 バイト。同じ構成と上限の 64 ビット形式。 | 64.42 | pass |
| `instruction_word` | 0–8 バイト、全 usize オフセット。4 バイトが収まる場合だけ成功し、リトルエンディアン値が一致する。 | 1.70 | pass |
| `image_ranges` | 0–16 バイト、全 u64 スライス基準位置・オフセット・サイズ。取得の成否、長さ、バイト列が範囲に一致する。 | 7.22 | pass |
| `relocation_words` | 0–16 バイト、全 usize オフセットと 32/64 ビット値。有効な書き込みは読み戻せ、無効なら不変。両方の幅の書き込みで周囲を保持する。 | 19.20 | pass |
| `aarch64_relocation` | 全命令・再配置番号・PC・対象値。CALL26 は命令の上位ビットを保持し、剰余演算による変位を符号化する。 | 3.10 | pass |
| `leb_readers` | 任意の 0–10 バイト。128 ビットの復号式と値を比較する。終端があれば消費長も一致し、終端がなければ入力内に留まる。オーバーフローと切り詰めを拒否する。 | 47.46 | pass |
| `leb_round_trip` | 全 u64 を最大 10 バイトで符号化し、同じ値へ復号して全体を消費する。 | 19.47 | pass |
| `encoded_pointers` | 任意の 0–16 バイト、全 64 ビット基準位置と 8 ビット符号化指定、4/8 バイトのポインター幅。例外値の復号が入力内に留まり、固定幅の値、符号拡張、PC 相対加算、オーバーフローが一致する。 | 30.94 | pass |
| `codeview_records` | 任意の 0–16 バイトと全 usize 要求長。スライス取得の成否、バイト列、読み取り位置、数値の読み取り境界とレコード数。64 ビット数値と消費長の一致、複数レコードの到達性。 | 153.62 | pass |
| `dwarf_units` | 12 バイトの DWARF32 バージョン 4 単位の各接頭部。任意の略記表オフセットとペイロード、4/8 バイトのアドレス幅。入力全体が揃った場合だけ成功し、単位のサイズ、バージョン、アドレス幅、略記表オフセットと終端が一致する。 | 118.45 | pass |
| `unwind_entries` | 空の拡張指定を持つ 16 バイトのバージョン 1 CIE。コード・データ整列値は各 1 バイト、戻りレジスターと命令バイトは任意。コード・データ整列値と戻りレジスターが一致し、解析と反復が終了する。 | 31.52 | pass |
| `unwind_fde32` | 固定 CIE と 32 ビット FDE、計 32 バイト。全開始アドレスと範囲。参照先 CIE を解析でき、開始アドレスと範囲が一致し、反復が終了する。 | 74.44 | pass |
| `unwind_fde64` | 64 ビットアドレスについて同じ性質。計 40 バイト。 | 77.08 | pass |
| `bit_fields` | 全 64 ビット値と有効幅 1–64。マスク、下位ビットの保持、符号付き値の範囲、シフトによる厳密な符号拡張。 | 2.43 | pass |
| `vector_window` | 全 64 ビット定数 2 個、オフセット 0–63、後続半分の有無。128 ビットシフトと一致する。定数式なので展開上限 1 で足りる。 | 198.84 | pass |
| `chained_pointer_arm64e` | 形式 1。8 バイトのポインター 1 個。ペイロードと 64 ビット基準アドレスは任意。次へのリンクは 0 または 1。再配置値、認証の有無、インポート番号と加算値、反復終了、入力外の 0 以外のリンクの拒否。 | 183.15 | pass |
| `chained_pointer_64` | 形式 2 について同じ性質。 | 107.16 | pass |
| `chained_pointer_64_offset` | 形式 6 について同じ性質。 | 108.87 | pass |
| `chained_pointer_arm64e_kernel` | 形式 7 について同じ性質。 | 168.91 | pass |
| `chained_pointer_arm64e_userland` | 形式 9 について同じ性質。 | 213.31 | pass |
| `chained_pointer_arm64e_firmware` | 形式 10 について同じ性質。 | 223.81 | pass |
| `chained_pointer_arm64e_userland24` | 形式 12 について同じ性質。インポート番号の全 24 ビットを含む。 | 148.52 | pass |
| `chained_pointer_links` | 全 7 形式。16 バイト、ペイロードと基準アドレスは 0。形式のストライドでオフセット 8 に進む最初のリンク。正確な位置、再配置先、認証なし、反復終了。 | 121.75 | pass |
| `export_trie_limit` | 無限反復子の全値と全 usize 要求インデックス。実際の共通処理は MAX_EXPORTS 未満だけ値を返し、それ以降は終了する。 | 0.37 | pass |

`go_table_walk` は本番のスライス走査を呼び出します。関数エントリは最大 2 個、
関数データは 0〜16 バイト、名前は 0〜8 バイトで、text の基点は任意の 64 ビット値です。
出力件数の上限、コードアドレスの非ラップ、名前の長さを確認します。
関数 2 個の受理と、無効な最初のエントリの後で第 2 エントリを受理する到達性も確認します。`go_table_offsets` は、
エントリ 1 個、8 バイトの関数ヘッダー、終端付きの固定名を使い、任意の 32 ビットの
エントリオフセット、符号付きの関数・名前オフセット、64 ビットの text の基点について、
受理条件と出力が正確に一致することを確認します。テーブルの仮想アドレスへの対応付けと
実行可能セクションへの所属は、これらのハーネスではなく通常の回帰テストで確認します。

Go のハーネスは 2026-10-27 UTC に x86-64 Linux 上の Kani 0.68.0 と CBMC
6.11.0 で検証しました。時間にはコンパイルと準備を含みません。

| ハーネス | 検証秒数 | 結果 |
| --- | ---: | --- |
| `go_table_walk` | 189.26 | pass |
| `go_table_offsets` | 16.66 | pass |

chained pointer の検査は固定の 60 バイトの開始位置テーブルを依存ライブラリで解析し、
ローダーの再配置値の正規化を使います。各形式のハーネスは、リンク 1 が 8 バイトの入力外を指す場合に拒否することを確認します。
別のハーネスはペイロード 0 のポインター 2 個について、両方のストライドでの走査と終端を検証します。
ファイル全体への適用、インポート名の検索、任意長・任意のリンク値と任意のペイロードを同時に扱うチェーン、
重なるポインター、ページの配置条件は証明しません。これらの経路は通常の
`src/loader/macho/fixups/tests.rs` で検査します。エクスポートの上限はエラーを含む
返却エントリー数に対するもので、反復子の `next` 内部の処理量やトライの復号は
証明しません。循環するエクスポートファイルは、通常の堅牢性テスト
`cyclic_export_tries_finish_loading` でも検査します。

これらの実行で 31 個のハーネスすべてが成功し、98 個の到達性の表明すべてが成立しました。
userland24 形式は単独で 1 並列にして検証しました。
ポインター形式の展開上限は実装の表の位置に応じて 3/4/5/6/7 とし、展開上限の表明も検査します。

各ハーネスには、対象とする境界値や意味のある成功入力に到達できることを示す
`kani::cover!` があります。10 バイトの LEB 最大・最小値、切り詰めた符号化、
負の値とオーバーフローを伴う PC 相対ポインター、完全な DWARF 単位と切り詰めた単位、
負のアンワインド整列値、Go の関数 2 個、0 以外のチェーンリンクとインポート番号を対象とします。
認証とリベースのオーバーフローの到達性は、その機能を持つ形式のハーネスにだけ追加します。
到達不能と判定された条件は、そのケースを検証した根拠にはなりません。

任意数のセクション、ビッグエンディアン、圧縮デバッグデータ、DIE 走査、巻き戻し命令の実行、
関数発見全体、全形式の再配置適用は対象外です。これらの証明から逆コンパイル全体の
安全性は保証できません。

### UPX の展開と Windows のページ範囲

これらのハーネスは `src/loader/packed/` の組み込み UPX デコーダーと、Windows の仮想メモリ
呼び出しで使うページ境界の丸めを対象とします。2026-10-31 UTC に x86-64 Linux 上で
Kani 0.68.0 と CBMC 6.11.0 を使い、3 並列で検証しました。`x86_branch_filters` だけは
単独で実行しました。秒数にコンパイルと準備の時間は含みません。

| ハーネス | 入力範囲と追加の表明 | 検証秒数 | 結果 |
| --- | --- | ---: | --- |
| `field_reads` | 任意の 8 バイト、全 usize のオフセットと長さ。フィールドは入力内にあるときに限り返る。8 バイト以下の数値フィールドはリトルエンディアンの値と一致する。 | 5.04 | pass |
| `checksum_chunk_cannot_overflow` | 5552 バイトのチェックサム単位内の任意の位置で、その位置の上限内の任意の状態に 1 バイトを加える。次の状態も上限内に収まるので、剰余を取る前の加算はオーバーフローしない。 | 8.09 | pass |
| `image_writes` | 8 バイトのイメージ、全 usize のオフセットと値、幅 0–8。書き込みはイメージ内のときに限り成功し、リトルエンディアンの値を書き、他のバイトは変えない。失敗した書き込みは何も変えない。 | 2.15 | pass |
| `image_copies` | 8 バイトのイメージ、0–4 バイトのコピー元、全 usize のオフセット。コピーについて同じ性質。 | 2.63 | pass |
| `image_strings_and_offsets` | 任意の 8 バイト、全 usize のオフセット。返る文字列は最初の 0 バイトで終わり、入力と一致する。オフセット以降に 0 バイトがないときに限り失敗する。全アドレスと全ベースについて、アドレスがベース以上のときに限りイメージ内オフセットが返る。 | 11.81 | pass |
| `headers_from_arbitrary_bytes` | 任意の 312 バイト、PE ヘッダーのオフセット 0–8。受け付けたヘッダーのセクション表は入力内にあり、データディレクトリは表の終わりより前にある。 | 80.27 | pass |
| `bit_reads` | 4 バイトの入力上の任意の読み取り状態から、NRV のビット読み取りと整数の延長を 1 回ずつ行う。語は 1 バイトまたは 4 バイト。ビットは 0 か 1 で、位置は入力内に収まり、延長した整数は上限を超えない。 | 4.04 | pass |
| `match_copies` | 0–4 バイトのブロック、全一致距離と全長さ、ブロック以上で 0–6 のサイズ。受け付けた一致はサイズに収まり、各バイトを指定距離だけ前からコピーする。失敗した一致はブロックを変えない。 | 135.38 | pass |
| `x86_branch_filters` | フィルター 0x26、0x46、0x49 を、任意のバイトと分岐先バイトを持つ長さ 0–12 のすべての入力に適用する。パニックせずに成功し、6 バイト以上のある入力で呼び出しを書き換える。 | 230.81 | pass |
| `arm_branch_filter` | フィルター 0x50 を同じ入力に適用する。長さ 0–13 では、BL のフィールドから別に書いた詰める側の変換を復号が打ち消す。先頭以外の各 BL 語には語の番号が加わり、他のバイトは変わらない。 | 19.83 | pass |
| `aarch64_branch_filter` | フィルター 0x52 を同じ入力に、B/BL のフィールドで適用する。 | 15.88 | pass |
| `page_ranges_cover_the_request` | 全 64 ビットのアドレスとサイズ。返る範囲はページ境界に揃い、要求を覆い、両端に余分なページを含まない。失敗するのは空の要求かオーバーフローする要求だけ。 | 0.18 | pass |

分岐フィルターの 3 行は、2026-10-31 UTC に同じ版の Kani と CBMC を使い、AArch64 macOS 上で
5 並列で検証し直しました。NRV のハーネスはデコーダーの 1 ステップを確認するもので、
ストリーム全体は対象外です。x86 のフィルターのハーネスは書き換えた呼び出し先を確認しません。
その計算は SMT テスト `smt_modular_branch_targets_round_trip` で確認します。往復の検証で使う
詰める側の変換は、復号と同じくバッファーの最後のバイトを除きます。この境界は、分岐で終わる
UPX の回帰用フィクスチャでだけ確認しています。ELF ヘッダーの読み取りには
Kani のハーネスがありません。プログラムヘッダーの配置を固定し、任意のバイトを 1 個だけに
しても、CBMC は 300 秒以内に終わりませんでした。LZMA の展開とファイル全体の再構成は
UPX の回帰テストで確認しており、これらのハーネスの対象外です。

### ジャンプテーブル、PLT のスロット、値の範囲

これらのハーネスは 2026-10-31 UTC に AArch64 macOS 上で Kani 0.68.0 と CBMC 6.11.0 を使い、
5 並列で検証しました。秒数にコンパイルと準備の時間は含みません。

| ハーネス | 入力範囲と追加の表明 | 検証秒数 | 結果 |
| --- | --- | ---: | --- |
| `case_values_name_the_checked_value` | 幅 1–64、全定数・上限・値、定数の加算と減算、符号なしの 2 種類の境界チェック（default へ進む条件が `>` と `>=`）。通る値はちょうど case の位置で、各 case の値は幅を法として switch の値と一致する（64 ビットでは厳密に一致）。 | 1.39 | pass |
| `table_entries_stay_in_the_address_space` | 全表アドレス・位置・要素サイズ。要素のアドレスは 2^64 を超えないときに限り返る。全バイトと全シフト量。バイト要素のオフセットはシフト量 0–63 のときに限り返る。 | 9.47 | pass |
| `referenced_addresses_follow_the_encodings` | 全 7 バイトと全位置。`lea r64, [rip + d]` は次の命令のアドレスに `d` を足した値になる。ADRP と ADD（即値）の全語の組。アドレスは Arm のフィールド定義に従い、ゼロレジスターへの ADRP は組にしない。 | 0.41 | pass |
| `aarch64_slots_follow_adrp_and_ldr` | ADRP と LDR の全語の組と全ベースアドレス。スロットは ADRP と、符号なしオフセットを持つ 64 ビット LDR の Arm のフィールド定義に従う。他の組はスロットを返さない。 | 2.36 | pass |
| `facts_keep_every_member` | 既知の 0、既知の 1、下限、上限のすべて。4 つを満たす値は `Fact::new` の結果に残る。 | 1.15 | pass |
| `joins_and_meets_are_sound` | 任意の 2 つの事実と要素。結合は要素を残し、交わりは両方の要素を残す。 | 12.49 | pass |
| `sums_are_sound`、`differences_are_sound` | 任意の 2 つの事実とその要素。和と差は結果に残る。すべての結果が回り込む場合も含む。 | 4.89、12.02 | pass |
| `bitwise_operations_are_sound` | AND、OR、XOR について同じ性質。 | 2.88 | pass |
| `left_shifts_are_sound`、`right_shifts_are_sound`、`signed_right_shifts_are_sound` | シフトについて同じ性質。算術シフトは幅 1–64 のすべて。 | 10.90、8.57、104.88 | pass |
| `remainders_are_sound`、`signed_remainders_are_sound` | 任意の事実の符号なし剰余。符号付き剰余は `expression` を通して幅 8、16、32、64 で確認する。 | 3.66、14.59 | pass |
| `truncations_and_sign_extensions_are_sound` | 任意の事実、要素、幅 1–64。 | 25.12 | pass |
| `decided_comparisons_hold_for_every_member` | 任意の 2 つの事実、要素、条件、幅 1–64。決まった比較は要素でも同じ結果になる。 | 214.85 | pass |
| `*_refines_soundly`（11 個） | 条件ごとに 1 個、フラグの 4 条件はまとめて 1 個。任意の 2 つの事実、要素、幅 1–64。要素で条件が成り立つとき、絞り込んだ事実が存在し、左の要素をその幅で残す。 | 33.58–188.82 | pass |
| `swapped_and_inverted_comparisons_agree` | 全条件、全オペランド、全幅。`swapped` でオペランドを入れ替えても、`invert` で否定しても結果が保たれる。 | 9.00 | pass |
| `constrained_reads_keep_every_member` | 幅 1–64 の読み取りの任意の事実、制約、制約する下位の幅。下位ビットが制約を満たす値は残る。 | 33.95 | pass |

積、符号なし・符号付きの商、上位の積にはハーネスがありません。64 ビットの乗算器と除算器のため、
MiniSat でも CaDiCaL でも CBMC が 30 分以内に終わりませんでした。代わりにシードを固定したテスト
`every_operation_keeps_the_values_it_can_produce` が、抽出した事実で確認します。テスト
`every_bitfield_move_matches_the_architecture` は、両方のサイズの SBFM、BFM、UBFM のすべての
エンコーディングを、Arm のビットマスクの定義から書いた参照と比べます。
`smt_accepted_magic_numbers_divide_every_32_bit_value` は、[SMT_RULES.ja.md](SMT_RULES.ja.md)
に書いた逆数乗算による除算の定理を証明します。

### ファズ対象と再現可能なシード

`fuzz/` には、読み込み用の `elf`、`pe`、`macho` と、`functions`、`decompile`、
`script_request`、`mcp_request` があります。読み込みは実際のローダーを使い、関数一覧と
逆コンパイルは `service::Binary` を使います。逆コンパイルは 1 関数を選び、解析期限を
100 ミリ秒にします。要求の検査は実際の serde 型と MCP ディスパッチを使います。
MCP は与えられた JavaScript を空のスクリプトに置換し、パスを削除してから処理します。
JavaScript の構文や、与えられた操作の実行は検査しません。

```sh
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/scripts/fuzz.py --seed-only
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/scripts/fuzz_runner_test.py
# 1 対象を指定する。省略すると 7 対象すべて:
sh tests/scripts/verify.sh fuzz elf --seconds 60 --quiet 120 --rounds 20
cargo +nightly fuzz build --target-dir target/fuzz
```

シードは 65536 バイト以下の ELF、PE、Mach-O フィクスチャと JSON 要求例から再生成します。
それより大きいフィクスチャは使いません。生成したコーパスは git の対象外です。
各対象を 60 秒単位で実行し、1 入力の制限を 10 秒、RSS 上限を 2048 MiB にします。
AddressSanitizer、デバッグ表明、オーバーフロー検査を有効にします。
各回の時間、エッジ被覆数 `cov`、特徴数 `ft` を `target/verification/fuzz/` に記録します。
連続した回で 240 秒間カウンターが変わらなければ `cargo fuzz cmin` でコーパスを最小化します。
20 回以内にこの条件を満たさなければ失敗です。この停止条件は全経路の被覆を意味しません。
クラッシュや時間切れの入力は `fuzz/artifacts/` に残ります。
`cargo +nightly fuzz run TARGET ARTIFACT` で再現し、通常の回帰テストを加えてから原因を修正してください。

### unsafe ブロックと Miri の制約

以下は `src/` に明示された unsafe ブロックの全一覧です。外部関数の宣言は含みません。

| 位置 | 関連テストと Miri の制約 |
| --- | --- |
| `src/main.rs` の `exit_on_closed_pipe` | Miri の場合だけコンパイルする `tests::closed_pipe_signal`。外部関数 `signal` は未対応。 |
| `src/lift/hardware/aarch64.rs:137` | `Page` のテストが登録するシグナルコールバック。カーネルのシグナルコンテキストが必要。ネイティブ実行でのコールバックの被覆は未確認。 |
| `src/lift/hardware/aarch64.rs:179`, `:183`, `:213`, `:231` | `lifted_instructions_match_the_processor` などの `Page` を使うテスト。シグナル設定、実行可能マッピング、生成コード、Darwin FFI。 |
| `src/lift/hardware/aarch64.rs:466`, `:473` | `sqdmulh_vector_results_match_the_processor`。FPSR の読み出し・復元にインラインアセンブリを使用。 |
| `src/lift/hardware/aarch64.rs:832`, `:842`, `:868`, `:890`, `:901` | `scalar_half_immediates_match_the_processor_without_status_changes`。FPCR/FPSR の読み書きにインラインアセンブリを使用。 |

AArch64 ハードウェアモジュールは macOS AArch64 だけでコンパイルされ、Linux では実行できません。
Miri は生成した機械語やそのインラインアセンブリを解釈できません。
スクリプトは Unix のシグナルテストを試し、未対応操作の結果を明示します。他の失敗は無視しません。
命令語読み出し、LEB128 オーバーフロー、CodeView レコードの単体テストも Miri で実行します。
これらの安全な Rust のパーサーテストが成功しても、ハードウェアの unsafe ブロックや依存先の
外部コードを検証したことにはなりません。
