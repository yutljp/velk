# シンボリック実行

シンボリック実行は、指定した入力をビットベクトルとして表し、指定した命令アドレスに到達する値を探索します。実行用のリフタと既存の IR から SMT への式変換を使います。具体値だけのスカラー式には IR 評価器を使います。外部 SMT ソルバが必要です。PATH 上に `z3` または `bitwuzla` をインストールするか、`VELK_SOLVER` に `z3 -in` などのコマンドラインを設定してください。引数の引用符に対応していますが、シェルは起動しません。他の操作はソルバを起動しません。

関数一覧と逆アセンブル結果から仮想アドレスを選び、次のように実行します。

```sh
velk --explore check --find 0x401100 --avoid 0x401120 --stdin 8 app.elf
velk --explore check --find 0x401100 --stdin 8 --json app.elf
velk --api-docs symbolic
```

対象命令を実行する前に到達を判定します。同じアドレスが find と avoid の両方にあれば avoid を優先します。成功時には、標準入力、argv のバイト列、引数、メモリ、レジスタの具体値と、通過した命令アドレスを返します。上限付き探索の失敗は、到達不能の証明にはなりません。未対応の操作やアドレス列挙の打ち切りは診断に含まれます。

JavaScript では `b.explore(start, options)` と `b.symbolic(start, options)` を使えます。オプションと状態 API の詳細は `velk --api-docs symbolic` を参照してください。

```js
const b = velk.open("app.elf");
const s = b.symbolic("check", {arguments: [0]});
const x = s.readRegister(7); // x86-64 System V の第1引数 rdi
s.constrain(x, "eq", s.constant(42));
s.evaluate(x); // ["0x2a"]
```

`Symbolic` はレジスタとメモリの項の読み書き、比較制約の追加、充足可能性判定、符号なし値の列挙、符号なし最小値・最大値の取得、`fork()` による複製、分岐または指定アドレスまでの実行に対応します。`step()` は分岐ごとに制約を持つ後続状態を返します。項はソルバのセッションに属し、複製した状態はそのセッションを共有します。使い終わった JavaScript の状態は `dispose()` で解放できます。Rust API は `velk::symbolic::{State, Term, Step, Options, explore}`、MCP ツールは `velk_explore` です。MCP には `path`、`start`、`options` を渡します。

初期物理レジスタは、具体実行と同様にスタックポインタ以外をゼロにします。`arguments` はシンボリックにするスカラー引数の添字、`argumentValues` は具体値を指定します。`argv` は argv[0] を含む各文字列の長さです。文字列のバイトはゼロ以外、終端は具体値のゼロです。`memory` は書き込み可能なメモリ範囲を選びます。レジスタ入力には物理レジスタの添字を使います。64 ビットの精度を保つにはアドレスを文字列で渡してください。

上限は決定的です。`stepLimit` の既定値は経路ごとに IR 文 100000 個、`pathLimit` は状態 256 個、`addressLimit` はシンボリックアドレスの候補 8 個です。アドレスを符号なし昇順で列挙し、候補ごとに制約付き状態を作ります。候補が上限を超える場合は診断を返します。分岐先を先に深さ優先で探索します。具体入力は経路制約のもとで各入力の符号なし最小値を順に選ぶため、入力全体で整合します。実行時間による上限はありません。ソルバが応答しなければ呼び出しも待ち続ける場合があります。

対応対象はリトルエンディアンの x86-64 と AArch64 です。System V x86-64 と AAPCS64 の整数スタック引数、switch IR、上限付きの間接ジャンプにも対応します。

`b.solve("check", {arguments: [0], returns: {eq: 1}})` は最外側の戻り値を条件に探索します。条件は `eq`、`ne`、`lt`、`gt` です。大小比較は符号付き64ビット、等値比較は戻り値レジスタの全ビットを使います。32ビットの負の C 戻り値はレジスタ内でゼロ拡張される場合があります。CLI は `velk --solve check --returns eq:1 --stdin 8 app.elf`、追加オプションは `--symbolic-options '{"arguments":[0]}'` で指定します。Rust は `symbolic::solve`、MCP は `velk_solve` です。

`b.branchFeasibility("check", {arguments: [0]})`、Rust の `symbolic::branch_feasibility`、MCP の `velk_branch_feasibility`、CLI の `velk --opaque check --symbolic-options '{"arguments":[0]}' app.elf` で条件分岐を調べられます。全経路の探索が完了し、どの文脈でも実行可能でない側を `unsat` として報告します。上限、ソルバーの失敗、未対応処理で探索が不完全になった場合は、証拠のない側を理由付きの `unknown` とします。両側に実行可能な経路がある通常の分岐は省きます。一度も訪れなかった条件分岐は、探索完了時には両側が到達不能として報告され、不完全な探索では実行可能な証拠のない側が unknown になります。find、avoid、returns は指定できません。具体的な引数やメモリによる仮定に加え、Rust では State の制約を追加してから解析できます。

libc モデルはエミュレーターのインポート表と入力消費ヘルパーを共有します。入力は `getchar`、`read`、`fgets`、`gets`、`getline`、`scanf`/`fscanf`/`sscanf` に対応します。scanf は `%d`、`%u`、`%x`、`%s`、`%c`、幅指定、代入抑制に対応します。ストリーム入力は stdin のみです。`read` は記述子0と `stdinDescriptors` に明示した記述子を同じ入力に結び付けます。文字列・メモリは `strlen`、`strnlen`、`strcmp`、`strncmp`、`memcmp`、`memcpy`、`memmove`、`memset`、`strcpy`、`strncpy`、`strchr` に対応します。整数変換は `atoi` と基数10/16の `strtol`、大小文字変換は ASCII です。`puts` と `printf` は出力を記録します。printf は具体値・シンボリック値の `%d`、`%u`、`%x`、`%s`、`%c` と `%%` に対応します。出力バイトは入力と同じ充足代入で `inputs.stdout` に格納します。文字列比較の非ゼロ値はバイト差です。libc が保証するのはその符号です。確保容量と puts の成功時戻り値はモデルの選択で、ホスト libc の詳細とは限りません。

AArch64 の可変長引数 I/O は ELF のみ対応し、Windows のデータモデルでは strtol を拒否します。モデルは命令数上限を消費します。メモリ処理は65536バイトまで、文字列探索は入力サイズに基づく4096〜65536バイトの有限範囲です。未対応インポート・書式、シンボリック引数の Apply、機械固有処理、フラグのみの分岐、末尾呼び出しは診断で停止します。インポート先での停止指定はできません。呼び出し命令のアドレスを使ってください。コードは64 KiB、シンボリック入力は65536バイトまでです。ゼロ除算の可能性がある演算は停止します。ループと再帰にも経路ごとの命令数上限が適用されます。
