# C++ のクラスと例外テーブル

`velk --classes app.elf` は実行時型情報（RTTI）で記述されたクラスを JSON で一覧表示します。
JavaScript の `velk.open("app.elf").classes()` も同じ配列を返します。
MCP ツール `velk_classes` は `path` と、省略可能な Mach-O の `arch` を受け取ります。
大きな一覧は `velk_run_script` 内で絞り込んだり、一部を取り出したりできます。

各クラスには `name`、16 進数の `typeInfo` アドレス、`bases`、`vtables` があります。
各テーブルにはアドレスポイント（最初のメソッドポインタ）、サブオブジェクトのバイトオフセット、
スロット順のメソッドがあります。バイナリにないメソッド名は `null` です。
副テーブルのメソッドアドレスでは、ポインタ調整用のサンクをそのまま保持します。
リンク済みイメージでは、シンボルやアンワインドテーブルにないメソッドの入口も RTTI から関数一覧に追加し、
検出元を `rtti` とします。メソッド名は推測しません。

各基底クラスには名前、公開アクセスの有無、仮想継承かどうかを記録します。
固定バイトオフセットは `offset` で、不明なら `null` です。
Itanium の仮想継承では `vtableOffset` がアドレスポイントから仮想基底オフセットの格納場所までの
符号付きバイト変位です。主テーブル間で値が一致すると、そのオブジェクト配置での結果を `offset` に示します。
MSVC の仮想継承では `vbtable` に vbptr の位置、vbtable エントリのバイト位置、固定メンバー変位を記録します。
固定のオブジェクトオフセットは仮定しません。MSVC のテーブルの `constructionDisplacement` は
構築時の vtordisp フィールドへの変位です。Itanium ではこのフィールドは `null` です。

クラス復元は、リトルエンディアンの 32 ビットおよび 64 ビット ELF/Mach-O の Itanium 記述子
（`__class_type_info`、`__si_class_type_info`、`__vmi_class_type_info`）と、
PE の MSVC の x86 の絶対アドレス形式または x64 のイメージ相対形式の complete object locator およびクラス階層に対応します。
Itanium の実行時記述子の種類は、シンボルまたは再配置・バインドの名前で識別できる必要があります。
Mach-O の従来のバインドストリームに対応します。64 ビットのイメージでは、クラス復元の前に
チェーン形式のポインタ修正を正規化します。
MSVC の単純なクラス名と名前空間名に対応し、未対応の装飾名は省略します。
不明・不正な記述子からクラス配置を推測しません。

テーブルの所属が一意に分かる仮想呼び出しでは、64 ビットのポインタ読み出しに
クラス名を使った C の構造体ビューを使用できます。このビューは 32 ビットのオブジェクト配置を表しません。
基底メンバーは、記録された重ならないオフセットに置きます。このバイト単位のビューは
ポインタ幅の先頭部分のみを記述し、C++ オブジェクト全体の大きさやデータメンバーを表しません。
不明または整列していない基底位置は C のビューから省略します。テーブルの書き込みにもクラス名を使い、
オブジェクトの初期化または破棄を示します。書き込みだけではコンストラクタとデストラクタを区別できません。

例外テーブルは次のようなコメントとして表示します。

```c
/* try { protected code [0x201c33, 0x201c38) }
   catch (Error) { handler L_201c3f; }
   catch (int) { handler L_201c3f; }
   catch (...) { handler L_201c3f; }
   Exception dispatch is described by unwind metadata. */
```

範囲は終端を含まない機械語の区間です。Itanium の各節はセレクタで分岐するランディングパッドを示し、
複数の節が同じパッドを共有することがあります。クリーンアップ処理は catch と区別します。クリーンアップのみの区間ではランディングパッドの注記を保持します。
ソース上で入れ子になった try が同じ呼び出し位置エントリを共有する場合があるため、
コメントではソースのスコープを推測せず、テーブルの範囲とアクション順序を保持します。
Mach-O の compact unwind の LSDA 索引と、ELF/Mach-O のフレームの LSDA 参照に対応します。
Windows x64 の `__CxxFrameHandler3` FuncInfo は IP と状態の対応表を使って保護区間と型付きハンドラーを復元します。
圧縮された `__CxxFrameHandler4` テーブルは未対応です。
コメントにすることで C の構文と既存の機械語レベルのハンドラーコードを保持します。
標準 C は C++ の例外振り分け機能を持ちません。

`tests/cases/cpp/rtti.cpp` は単一・多重・仮想継承と、型付き・全例外・入れ子・クリーンアップのハンドラーを含みます。
`bash tests/make_cpp_fixtures.sh` は clang と `ld.lld` で ELF を、利用可能なら clang の MSVC ターゲットと
`lld-link` で PE を、macOS では Mach-O を作成します。デバッグ版とシンボル削除版について、
`tests/cpp_classes.rs` が名前、オフセット、例外コメント、検出した全関数のコンパイルを検証します。

配置の根拠は [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html)、
[LLVM の MSVC RTTI 出力](https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/MicrosoftCXXABI.cpp)、
[LLVM の Windows 例外出力](https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/AsmPrinter/WinException.cpp)です。
