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
- vtable を通じた C++ 仮想呼び出しの解析。

## 使い方

```bash
cargo build --release --locked

velk --functions path/to/binary          # 関数の一覧
velk --decompile path/to/binary main     # 疑似 C
velk --decompile path/to/binary '*'      # すべての関数
velk --disasm    path/to/binary 0x1000   # 逆アセンブル
velk --xrefs     path/to/binary main     # main への参照
velk --strings   path/to/binary          # 参照付きの文字列
```

そのほかの操作は `velk --help` を参照してください。

## エージェントから使う

MCP クライアントに `--mcp` 付きで登録します。

```json
{
  "mcpServers": {
    "velk": { "command": "/absolute/path/to/velk", "args": ["--mcp"] }
  }
}
```

JavaScript のスクリプトで解析し、必要な結果だけを返します。同じ API は `velk --run script.js` でも使えます。

```js
const b = velk.open("/absolute/path/to/binary");
b.functions({ named: true }).slice(0, 5).map(f => ({ addr: f.addr, name: f.name }));
```

## ドキュメント

- [API の概要](src/script/api/index.md)
- [アーキテクチャ](docs/ARCHITECTURE.ja.md)
- [テスト](docs/TESTING.ja.md)

## ライセンス

未定です。
