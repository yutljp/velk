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
- バイトシグネチャによる、シンボルを削除したライブラリ関数の識別。
- macOS、Windows（Win32 と C ランタイム）、Linux（glibc）の生成済み C API 型ライブラリ。
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
velk --decompile path/to/binary '*'      # すべての関数
velk --disasm    path/to/binary 0x1000   # 逆アセンブル
velk --xrefs     path/to/binary main     # main への参照
velk --strings   path/to/binary          # 参照付きの文字列
```

そのほかの操作は `velk --help` を参照してください。

ユニバーサル Mach-O はこのマシンのアーキテクチャを開きます。別のものは `--arch x86_64`（または `arm64`、`arm64e`）で選びます。

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

## ドキュメント

- [API の概要](src/script/api/index.md)
- [アーキテクチャ](docs/ARCHITECTURE.ja.md)
- [テスト](docs/TESTING.ja.md)

## ライセンス

MIT ライセンスです。[LICENSE](LICENSE) を参照してください。
