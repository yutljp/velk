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
cargo build --release
cargo test --release
cargo fmt -- --check
cargo clippy --release --all-targets -- -D warnings
BIN=target/release/velk sh tests/smoke.sh
BIN=target/release/velk sh tests/ladder.sh
```

- `tests/smoke.sh` はコマンドラインと MCP サーバーを端から端まで動かして確認します。
- `tests/ladder.sh` は難しさの異なる関数で期待する結果を確認します。`known_*` の行はまだ達成できていない目標です。

## テストが確認すること

- **命令の意味。** lift した各命令を CPU 上と IR インタプリタで多数の入力に対して実行し、結果が一致することを確かめます。
  同じアーキテクチャのホスト (Apple シリコンで x86-64 を試す場合は Rosetta) が必要です。
- **最適化パス。** テスト用バイナリのすべての関数を最適化の前後でインタプリタ実行し、結果が一致することを確かめます
  (`tests/golden/semantics.txt` が空であること)。
- **再コンパイル。** 各テスト関数の出力した C をコンパイルして実行し、レジスタの結果とメモリへの影響の両方を IR インタプリタと
  比べます。`tests/golden/recompile.txt` と `tests/golden/recompile_memory.txt` の `differ` はすべて 0 でなければなりません。
- **全関数のコンパイル。** すべてのテスト用バイナリのすべての関数について、出力した C を標準ヘッダと一緒にコンパイルします。
  時間がかかるため `#[ignore]` になっています。
  `cargo test --release --test recompile every_fixture_function_compiles -- --ignored` で実行します。
  通常のテストでは一部だけを高速に確認します。
- **ゴールデン出力。** `tests/golden/` には各テスト用バイナリの期待出力と、読みやすさの指標 (行数、変数、キャスト、goto)
  が入っています。これらのファイルの変更はすべてレビューしてください。

C のチェックに使うコンパイラは `VELK_TEST_CC` で指定できます (既定は `clang`)。Homebrew の新しい clang がある場合は、
一部のチェックをそれでも実行します。新しいコンパイラは古いものが受け付ける型変換の一部を拒否するためです。

## ゴールデンファイルの更新

出力の変更が意図したものであれば、ゴールデンファイルを再生成して差分を確認します。

```bash
VELK_BLESS=1 cargo test --release
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

一部のグループには専用のスクリプトがあります。`tests/make_pe_fixtures.sh` (Windows PE)、`tests/make_codeview.sh`
(CodeView / PDB)、`tests/make_seh_fixtures.sh` (Windows SEH)、`tests/make_objc_fixtures.sh` (Objective-C)、
`tests/make_arm64_lang_fixtures.sh` (AArch64 の Rust と Go) です。再生成は意図して行い、変わったバイトと記録された
ツールチェーンのバージョンを確認してください。

## 性能

1 関数のデコンパイルは高速であるべきです。バイナリ全体の処理速度を比べるには次を実行します。

```bash
uv run tests/throughput.py target/release/velk tests/fixtures/go_probe
```
