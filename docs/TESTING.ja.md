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
BIN=target/release/velk bash tests/smoke.sh
BIN=target/release/velk bash tests/ladder.sh
```

- `tests/smoke.sh` はコマンドラインと MCP サーバーを端から端まで動かして確認します。
- `tests/ladder.sh` は難しさの異なる関数で期待する結果を確認します。`known_*` の行はまだ達成できていない目標です。

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

C API 型ライブラリは `UV_CACHE_DIR=target/uv-cache uv run tests/generate_type_library.py` で、
その Mach-O フィクスチャは `sh tests/make_type_library_fixtures.sh` で再生成します。

Windows と Linux のデータとフィクスチャは参照環境で生成します。

```sh
docker compose build fixtures
docker compose run --rm fixtures uv run tests/generate_type_library.py --platform windows
docker compose run --rm fixtures uv run tests/generate_type_library.py --platform linux
docker compose run --rm fixtures sh tests/make_type_library_fixtures.sh linux
```

Windows データとリフターは x86-64 と x86-32 に対応します。
Linux のデータとフィクスチャは x86-64 と AArch64 を対象とします。各ターゲットの
コンパイラーで宣言とパディングを含む構造体のサイズ、アラインメント、フィールドのオフセットを検証します。

一部のグループには専用のスクリプトがあります。`tests/make_pe_fixtures.sh` (Windows PE)、`tests/make_codeview.sh`
(CodeView / PDB)、`tests/make_seh_fixtures.sh` (Windows SEH)、`tests/make_objc_fixtures.sh` (Objective-C)、
`tests/make_arm64_lang_fixtures.sh` (AArch64 の Rust と Go) です。再生成は意図して行い、変わったバイトと記録された
ツールチェーンのバージョンを確認してください。

ARM32 A32/T32 は `sh tests/make_arm32_fixtures.sh`（ARM 対応 clang と `ld.lld` が必要）、x86-32 ELF・PE は
`bash tests/make_i386_fixtures.sh` で、それぞれ `-O0` / `-O2` のフィクスチャを再生成します。

## 性能

1 関数のデコンパイルは高速であるべきです。バイナリ全体の処理速度を比べるには次を実行します。

```bash
uv run tests/throughput.py target/release/velk tests/fixtures/go_probe
```

## 任意実行の有界検証、ファジング、Miri

これらは既定のテストとは別に実行します。Kani、Miri を含む nightly Rust、
`cargo-fuzz`、uv が必要です。ファズ用パッケージは初回ビルド時に `libfuzzer-sys` を取得します。
以下のコマンドは現在のチェックアウトの `target/` を使います。他のチェックアウトと共有しないでください。

```sh
sh tests/verify.sh kani
sh tests/verify.sh fuzz
sh tests/verify.sh miri
# 各検査の失敗を保持して、3 種類すべてを実行:
sh tests/verify.sh all
```

Linux では、スクリプトは 1 分間の負荷がプロセッサ数の 2 倍を超えている間は待機します。
既定ではビルドを 5 並列、テストを 5 スレッドで実行します。小さいマシンでは
`CARGO_BUILD_JOBS=2` を指定してください。各ハーネスの CBMC 検証には 120 秒の制限を設けます。
コンパイルと準備には別途時間がかかります。時間切れは証明成功ではなく失敗です。個別に実行するには
`cargo kani --lib --harness instruction_word` のように指定します。

すべてのハーネスは `cfg(kani)` の下にあります。Kani はパニック、算術オーバーフロー、
メモリアクセスと、ループの展開上限を検査します。成功時に保証されるのは下表の範囲と
事前条件だけです。任意サイズのバイナリや逆コンパイル全体の安全性を保証するものではありません。

| ハーネス | 入力範囲と追加の表明 |
| --- | --- |
| `elf_tables` | 任意の 0–128 バイト。ローダーと同じ `object` リーダーで 32/64 ビットヘッダー、セクション名・データ、再配置を読む。 |
| `pe_tables` | 任意の 0–512 バイト。PE32/PE32+ ヘッダー、セクション、再配置。 |
| `macho_tables` | 任意の 0–128 バイト。32/64 ビットヘッダー、セクション、再配置。 |
| `instruction_word` | 0–8 バイトと全 `usize` オフセット。4 バイトが収まる場合だけ成功し、リトルエンディアン値が一致する。 |
| `image_ranges` | 0–16 バイトと全 `u64` オフセット・長さ。読み出しの成否と返す長さが範囲に一致する。 |
| `relocation_words` | 0–16 バイト、全 `usize` オフセット、全 32/64 ビット値。有効な書き込みは読み戻せ、無効なら変更しない。64 ビット書き込みは周囲を保持する。 |
| `aarch64_relocation` | 全 32 ビット命令・再配置番号、全 64 ビット PC・対象値。CALL26 は命令の上位ビットを保ち、剰余演算による変位を符号化する。 |
| `leb_readers` | 任意の 0–10 バイト。符号付き・符号なし LEB 読み出しは範囲内に留まり、成功時に 1–10 バイトを消費する。 |
| `leb_round_trip` | 全 `u64` を最大 10 バイトで符号化し、同じ値へ復号して符号化全体を消費する。 |
| `encoded_pointers` | 任意の 0–16 バイト、全 64 ビット基準アドレス、全 8 ビット符号化指定。例外ポインターリーダーがセクション内に留まる。 |
| `codeview_records` | 任意の 0–16 バイト、全 `usize` 要求長。数値・レコード読み出しの境界とスライス取得の成否条件。 |
| `dwarf_units` | 任意の 0–32 バイトのリトルエンディアン単位ヘッダー。宣言された単位が入力内に収まる。DIE の走査は対象外。 |
| `unwind_entries` | 任意の 0–32 バイトのリトルエンディアン `.eh_frame`。参照先 CIE の解析を含む。巻き戻し命令の実行は対象外。 |
| `bit_fields` | 全 64 ビット値と有効幅 1–64。マスク、下位ビットの保持、符号付き値の範囲。 |
| `vector_window` | 全 64 ビット定数 2 個、オフセット 0–63、後続半分の有無。128 ビットシフトとの一致。 |

サイズ上限によって到達できるテーブル形状も制限されます。任意数のセクション、圧縮された
デバッグデータ、関数発見全体、全形式の再配置適用は証明対象ではありません。
再配置の書き込み処理は別のハーネスで検査します。ローダーには Mach-O の chained fixup
デコーダーがないため、その符号化について保証しません。

### ファズ対象と再現可能なシード

`fuzz/` には、読み込み用の `elf`、`pe`、`macho` と、`functions`、`decompile`、
`script_request`、`mcp_request` があります。読み込みは実際のローダーを使い、関数一覧と
逆コンパイルは `service::Binary` を使います。逆コンパイルは 1 関数を選び、解析期限を
100 ミリ秒にします。要求の検査は実際の serde 型と MCP ディスパッチを使います。
MCP は与えられた JavaScript を空のスクリプトに置換し、パスを削除してから処理します。
JavaScript の構文や、与えられた操作の実行は検査しません。

```sh
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/fuzz.py --seed-only
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/fuzz_runner_test.py
# 1 対象を指定する。省略すると 7 対象すべて:
sh tests/verify.sh fuzz elf --seconds 60 --quiet 120 --rounds 20
cargo +nightly fuzz build --target-dir target/fuzz
```

シードは 65536 バイト以下の ELF、PE、Mach-O フィクスチャと JSON 要求例から再生成します。
それより大きいフィクスチャは使いません。生成したコーパスは git の対象外です。
各対象を 60 秒単位で実行し、1 入力の制限を 10 秒、RSS 上限を 2048 MiB にします。
AddressSanitizer、デバッグ表明、オーバーフロー検査を有効にします。
各回の時間、エッジ被覆数 `cov`、特徴数 `ft` を `target/verification/fuzz/` に記録します。
連続した回で 120 秒間カウンターが変わらなければ `cargo fuzz cmin` でコーパスを最小化します。
20 回以内にこの条件を満たさなければ失敗です。この停止条件は全経路の被覆を意味しません。
クラッシュや時間切れの入力は `fuzz/artifacts/` に残ります。
`cargo +nightly fuzz run TARGET ARTIFACT` で再現し、通常の回帰テストを加えてから原因を修正してください。

### unsafe ブロックと Miri の制約

以下は `src/` に明示された unsafe ブロックの全一覧です。外部関数の宣言は含みません。

| 位置 | 関連テストと Miri の制約 |
| --- | --- |
| `src/main.rs:478` | Miri の場合だけコンパイルする `tests::closed_pipe_signal`。外部関数 `signal` は未対応。 |
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
