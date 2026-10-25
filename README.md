<div align="center">

<img width="200" height="200" alt="velk" src="https://github.com/user-attachments/assets/31a1c0c1-3ca4-4d9f-8d88-917cc43bd49e" />

# velk

**機械語を、そのままコンパイルできる C に。**

ELF・PE・Mach-O を読み、元のバイナリと同じ計算をする読みやすい C を出力するデコンパイラ。<br>
人のためのコマンドラインと、LLM エージェントのためのスクリプト API・MCP サーバを備えています。

[![Rust](https://img.shields.io/badge/Rust-2024-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Formats](https://img.shields.io/badge/formats-ELF%20%7C%20PE%20%7C%20Mach--O-4c6ef5)](#対応範囲)
[![Arch](https://img.shields.io/badge/arch-x86--64%20%7C%20AArch64-0ca678)](#対応範囲)
[![MCP](https://img.shields.io/badge/MCP-ready-f76707)](#エージェントから使う)
[![License](https://img.shields.io/badge/license-TBD-lightgrey)](#ライセンス)

[はじめかた](#はじめかた) ·
[特徴](#特徴) ·
[エージェントから使う](#エージェントから使う) ·
[CLI](#cli) ·
[対応範囲](#対応範囲) ·
[検証](#検証) ·
[ドキュメント](#ドキュメント)

</div>

---

```c
/* velk pseudo-C: sum_until_zero @ 0x201210 */
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

<sub>`-O2` でビルドした x86-64 の関数を velk でデコンパイルした出力そのままです。デバッグ情報から引数の名前と型を取り、ループ・配列・`break` を復元しています。</sub>

## 特徴

|   |   |
|---|---|
| ✅ **正しさを最優先** | 出力した C を実際にコンパイル・実行し、IR の解釈実行と結果を照合。命令の意味は実機と比較し、ランダム生成プログラムでの差分テストを継続的に回しています。 |
| 🧩 **そのままコンパイルできる** | すべての fixture のすべての関数が、標準ヘッダとともに新旧のコンパイラでコンパイルできることをテストで保証。補助関数はファイル先頭に 1 度だけ出力します。 |
| 📖 **読みやすい出力** | スタック上の構造体・共用体、型付きポインタ、`for` と複合代入、`switch`、`va_arg`、宣言されたプロトタイプでの呼び出し、`i` / `result` などの役割に応じた名前。 |
| 🌐 **多くの言語と形式** | C / C++ / Rust / Go / Objective-C を、デバッグ情報（DWARF・PDB）があってもなくても扱います。 |
| 🤖 **エージェントのための API** | 関数の要約（card）、JavaScript のスクリプト API、MCP サーバ。必要な情報だけを小さく取り出せます。 |
| ⚡ **速い** | 1 関数のデコンパイルは数十〜数百ミリ秒。解析結果はセッション内でキャッシュします。 |

## はじめかた

Rust のツールチェーンと C コンパイラがあればビルドできます。

```bash
cargo build --release --locked
```

リポジトリに含まれるサンプルで試せます。

```bash
./target/release/velk --functions tests/fixtures/arm64.o         # 関数の一覧
./target/release/velk --decompile tests/fixtures/arm64.o sum3    # 疑似 C
./target/release/velk --disasm    tests/fixtures/arm64.o sum3    # 逆アセンブル
```

自分のファイルは、パスと関数名（またはアドレス）を指定します。`'*'` ですべての関数をまとめて出力します。

```bash
velk --decompile path/to/binary main
velk --decompile path/to/binary 0x401000
velk --decompile path/to/binary '*' > all.c
```

## エージェントから使う

velk は [MCP](https://modelcontextprotocol.io/) サーバとして動きます。クライアントに `--mcp` 付きで登録してください。

```json
{
  "mcpServers": {
    "velk": { "command": "/absolute/path/to/velk", "args": ["--mcp"] }
  }
}
```

| ツール | 内容 |
|---|---|
| `velk_run_script` | JavaScript を実行し、`console.log` の出力と最後の式の値を返す |
| `velk_read_api` | API の概要、または `binary` / `func` / `types` の宣言を読む |

スクリプトの中で絞り込み、必要な結果だけを返します。開いたファイルと解析結果はサーバの実行中キャッシュされます。

```js
const b = velk.open("/absolute/path/to/binary");
b.functions({ named: true }).slice(0, 5).map(f => ({ addr: f.addr, name: f.name }));
```

<details>
<summary>出力の上限とスクリプトの制約</summary>

- 結果の本文は既定で 4,000 文字まで。`max_output_chars` に 256〜20,000 を指定して変更できます。
- `card({ budget })` は概算のトークン数に合わせた要約で、厳密な上限ではありません。
- JavaScript は同期実行です。Node.js の API や `await`・`import` は使えません。
- 同じ API は `velk --run script.js` でも使えます。詳しくは [API の概要](src/script/api/index.md) を参照してください。

</details>

## CLI

| オプション | 用途 |
|---|---|
| `-f`, `--functions` | 関数の一覧と発見元（`--json` で JSON） |
| `-s`, `--sections` | セクションの一覧 |
| `-D`, `--decompile` | 疑似 C（複数の関数、または `'*'` で全関数） |
| `-d`, `--disasm` | 逆アセンブル |
| `-i`, `--ir` | 最適化後の中間表現 |
| `-c`, `--card` | 関数の要約を JSON で表示 |
| `-b`, `--build-signatures` | 名前付き関数からシグネチャ DB を作成 |
| `-I`, `--identify` | シグネチャ DB と形が一致する関数を検索 |
| `-r`, `--run` | JavaScript API を実行 |
| `-m`, `--mcp` | MCP サーバを起動 |

詳細は `velk --help` を参照してください。端末では色付きで表示し、パイプやファイル、`NO_COLOR`・`TERM=dumb` の環境では装飾しません。

## 対応範囲

| | |
|---|---|
| **入力形式** | ELF · PE / COFF · Mach-O（実行ファイル・共有ライブラリ・オブジェクト） |
| **命令セット** | x86-64 · AArch64（SIMD・アトミック・暗号命令を含む） |
| **呼び出し規約** | System V x86-64 · Windows x64 · AAPCS64（Linux / Apple）· Go |
| **デバッグ情報** | DWARF · CodeView / PDB |
| **言語メタデータ** | Go の関数表と型 · Rust / C++ の名前 · C++ の vtable · Objective-C のクラスとセレクタ |
| **例外処理** | DWARF の landing pad · Windows SEH（注釈） |
| **出力** | 疑似 C · IR · 逆アセンブル · 引数と戻り値 · 文字列とデータ参照 · 関数の要約 |

> [!NOTE]
> 型や名前は推定を含みますが、計算の内容は機械語と一致させます。一致を保証できない箇所（機械の状態を読む命令、解決できない間接ジャンプなど）は、組み込み関数や明示的なアダプタとして書き出します。境界を証明できない配列はバイトオフセットでアクセスし、未対応の命令は `unsupported` と表示します。

## 検証

velk の出力の変更は、すべて次の検査を通ってから取り込みます。

| 検査 | 確かめること |
|---|---|
| 再コンパイル比較 | 出力した C をコンパイル・実行し、IR の解釈実行と同じ値になるか（レジスタ・メモリ） |
| 全関数のコンパイル | すべての fixture のすべての関数が、標準ヘッダとともにコンパイルできるか |
| 命令の実機比較 | 持ち上げた命令の意味が実際の CPU と一致するか |
| 差分テスト | ランダム生成した C プログラムの関数を velk の出力に置き換えても、結果が変わらないか（arm64 / x86-64） |
| golden | fixture ごとの出力と、行数・変数・キャスト・goto などの読みやすさの指標 |

```bash
cargo nextest run --release
cargo fmt -- --check
cargo clippy --release --all-targets -- -D warnings
```

再コンパイル比較には clang、性能確認には uv、fixture の再生成には Docker を使います。詳しくは [Testing](docs/TESTING.md) へ。

## ドキュメント

- 📘 [API の概要](src/script/api/index.md) — スクリプトの書き方とトピック別の宣言
- 🏗️ [アーキテクチャ](docs/ARCHITECTURE.md) — 解析の流れと各モジュールの責務
- 🧭 [ロードマップ](docs/ROADMAP.md) — 目指す設計と進める順序
- 🧪 [Testing](docs/TESTING.md) — 検証方法、必要なツール、fixture の再生成、測定値

## ライセンス

未定です。
