# 読み込んだコードの実行

[English](EMULATION.md) | 日本語

`--emulate` は持ち上げた命令を IR インタープリターで実行します。x86-64、
AArch64、x86-32、リトルエンディアンの ARM32（A32/T32）に対応します。
バイナリー内のコードをホスト上で直接実行しません。毎回、新しいイメージから
開始し、ファイルやキャッシュ済みの解析結果は変更しません。

## Linux ELF ファイルの展開

解析操作に `--unpack` を付けると、Linux ELF の入口からエミュレーションを実行し、
復元したイメージをそのまま解析します。

```sh
velk --unpack -D packed.elf main
velk --unpack --iocs packed.elf
velk --unpack --strings packed.elf
velk --unpack --save-unpacked recovered.elf --sections packed.elf
velk --unpack --unpack-at 0x401200 -D packed.elf main
```

`--unpack-at` を指定しない場合、実行中に書き込んだアドレスを実行する直前に停止します。
停止アドレスはマップ済み領域内である必要があり、その命令の実行前に停止します。
レポートには入口、停止アドレス、ステップ数、停止理由、マップ済み領域、書き込み領域、
実行されたマップ済み領域が含まれます。書き込み済みコードまたは指定アドレスに到達すると
`newEntry` が設定されます。CLI はレポートを標準エラーに表示します。`--save-unpacked` は
まだ存在しないパスに再構成した ELF を保存します。

JSON レポートは JavaScript、MCP、`--serve` から `b.unpacking` として取得できます。

`stopAddress` は任意の仮想アドレスです。既定値は IR 文 1,000,000 個、個別の書き込み済み
バイト数と保存イメージのマップ領域に対する上限 64 MiB、実行時間 5,000 ミリ秒です。
上限は小さくできます。最大値はそれぞれ
10,000,000 個、256 MiB、60,000 ミリ秒です。上限に達するまでに書き込み済みコードまたは指定アドレスに
到達しない場合、`no unpacking observed` と報告します。ELF の再構成では入力のロード領域を
保持し、エミュレーション中の書き込みを反映します。書き込みがあったヒープのページは実行可能な
ロード領域として追加します。スタックと TLS のデータは保存 ELF に含めません。展開時はマップ済み
イメージへの書き込みを許可し、`mprotect` はホストのメモリー保護を変更せずにモデル化します。
命令は解釈され、ホスト上で実行されません。現在は x86-64、i386、AArch64 の Linux ELF に対応します。

各バイトとキーの XOR を取る `decode(unsigned char *buffer, unsigned count,
unsigned key)` を実行する例です。符号化されたバッファーをヒープに配置し、
その仮想アドレスを第1引数に渡します。

この例は `app.elf` にその関数が含まれ、ヒープが `0x10000000` から始まる場合です。
イメージがその範囲を占める場合は、後述の方法で `heapBase` を確認してください。

```sh
velk --emulate app.elf decode --emulation-options '{"arguments":["0x10000000",6,93],"memory":[{"address":"0x10000000","bytes":[53,56,49,49,50,93]}],"reads":[{"address":"0x10000000"}],"stepLimit":100000,"timeLimitMs":1000}'
```

結果は既定でテキスト（`--json` で JSON） です。`memory` は変更された連続領域ごとに `address`、最終的な
`bytes`、`hex` ダンプを示します。この例の復号結果は `68 65 6c 6c 6f 00`
（"hello"）です。初期書き込み後の状態と比較し、実行による変更だけを返します。
変更されなかったバイトは省略します。

JavaScript API も同じオプションを受け付けます。2^53 - 1 を超える値は、
JavaScript で精度が失われないよう文字列で渡してください。

```js
const b = velk.open("app.elf");
const r = b.emulate("decode", {
  arguments: ["0x10000000", 6, 93],
  memory: [{address: "0x10000000", bytes: [53, 56, 49, 49, 50, 93]}],
  reads: [{address: "0x10000000"}],
  trace: true
});
if (r.reason !== "return") throw new Error(r.error ?? r.reason);
r.reads[0].value;
```

`velk.open` の `unpack` オプションで上限を渡します。

```js
const b = velk.open("packed.elf", {
  cache: false,
  unpack: {stepLimit: 1000000, memoryLimit: 67108864, timeLimitMs: 5000}
});
JSON.stringify(b.unpacking, null, 2);
```

`b.getFunction("decode").emulate(options)` でも実行できます。`b.emulate()` の
名前を任意の命令アドレスに置き換えられます。`end: ["0x401020", "0x401040"]`
を指定すると、いずれかの命令を実行する直前に停止します。関数が見つからない
範囲では最大の終了アドレスまでを持ち上げます。終了アドレスは命令境界である
必要があります。関数の途中から開始する場合、それ以前の命令が作るはずの
レジスターとメモリーを設定してください。

MCP では `velk_emulate` に `{path, start, options, arch?}` を渡します。
完全な JSON レポートをテキストで返します。大きなダンプを絞るには
`velk_run_script` を使います。`velk_read_api` の `topic: "emulation"` で
すべてのオプションと結果の型を確認できます。

ELF と Mach-O では、実行ごとに独立した 4 KiB のスレッドローカル領域をマップします。`tlsBase` で
自動選択されるベースを上書きでき、重複やアドレスのオーバーフローは拒否します。
x86-64 の FS ベース、i386 の GS ベース、AArch64 の `tpidr_el0` をこの領域に設定します。
固定のスタックガードは `0x6a09e667bb67ae00`（i386 は下位 32 ビット）で、`canary`
で上書きできます。格納先は FS + `0x28`、GS + `0x14`、およびこのオフセットを使う
AArch64 sysreg ビルドの TP + `0x28` です。AArch64 glibc はグローバルガードを使い、
定義された `__stack_chk_guard` データシンボルも初期化します。x86 の自己ポインターを
除き、残りはゼロです。これはスタック保護の初期状態であり、TLS ローダーではありません。
明示したレジスター値とメモリー入力を優先します。`__stack_chk_fail` または
`__stack_chk_fail_local` の呼び出しで `stack check failed` として停止し、
シンボリック探索では診断にこの理由を含めます。

## 状態と制限

- `registers` は完全なレジスター名と符号なし値の対応です。例は `rax`、
  x86-32 の `eax`、`x0`、`sp`、`r0` です。スタックポインター以外はゼロで
  開始し、x86 の方向フラグはクリアします。`al` などの部分名は受け付けません。
  ベクトルレジスターはインタープリターの64ビット半分の名前を使います。
- `arguments` は復元された呼び出し規約に従い、マシンワードの整数やポインターを
  レジスターとスタックに渡します。レジスター設定の後に引数を設定します。
  浮動小数点、集成型、複数ワードの引数、Go の引数には明示的な設定が必要です。
  初期メモリーの書き込みは最後に行うため、スタック引数のバイトを置き換えられます。
- 読み込んだセクションの仮想アドレスと書き込み保護を維持します。ファイルデータが
  ない領域はゼロです。実行可能セクションは変更できません。Windows のプロセス設定は
  後述します。それ以外の形式では、スタックガードとここで説明するライブラリーモデルを
  用意しますが、実行時ローダーは用意しません。
- 書き込み可能なスタックは初期ポインター周辺の1 MiB、ヒープは `0x10000000`
  から16 MiBを確保します。イメージと重複する場合は空いている範囲を選びます。
  どちらもゼロで開始し、結果に `heapBase`、`heapSize`、初期 `stackPointer` を含めます。
  初期入力の準備前に `end` で入口アドレスに停止するとヒープの位置を確認できます。
  スタックとの重複、またはヒープの空き領域がない場合は入力エラーです。
- `memory` は `bytes`、または `value` と `width`（1、2、4、8バイト、
  リトルエンディアン）を受け付けます。書き込み先は書き込み可能なマップ領域で、
  初期書き込みは合計16 MiBまでです。呼び出し側が置いたヒープデータの後で割り当てます。
- `stepLimit` の既定値は100000で、IR文とフックのバイト単位処理を数えます。
  `timeLimitMs` の既定値は1000ミリ秒です。実行中と持ち上げ後に確認するため、
  厳密な実時間の上限ではありません。持ち上げるコード範囲は64 KiB、呼び出しの
  深さは128までです。
  フックの個々のメモリー操作は16 MiBまでです。
- `trace: true` は訪れた命令アドレスを含めます。反復文字列命令では、
  同じ命令アドレスが繰り返し現れることがあります。

## 呼び出しと停止

フック表は `memcpy`、`memmove`、`memset`、`memchr`、`memrchr`、`strlen`、
`strnlen`、`strcmp`、`strncmp`、`strcasecmp`、`strncasecmp`、`strchr`、
`strrchr`、`strstr`、`memcmp`、`strcpy`、`strncpy`、`strdup`、`strndup`、
`atoi`、`atol`、`strtol`、`strtoll`、`strtoul`、`strtoull`、`malloc`、
`calloc`、`realloc`、`free` を実装しています。整数変換は基数0〜36を扱い、
指定時には終端ポインターを書き込み、オーバーフロー時には `errno` を `ERANGE` にします。
それ以外の変換結果では `errno` を変更しません。`qsort` と `bsearch` はエミュレートした
比較関数を呼び出します。メモリー関数はマップと保護を確認し、重複する `memcpy` は拒否します。
文字列比較は libc と符号が一致するバイト差を返します。割り当てはヒープ内で整列し、
容量不足ならゼロを返します。`realloc` は旧サイズと要求サイズの小さい方をコピーします。
`free` はポインターを検証しますが、領域を再利用しません。

`sleep`、`usleep`、`nanosleep` は指定時間だけ決定的なクロックを進めます。各リソースの
`getrlimit` は `RLIM_INFINITY` から始まり、`setrlimit` はその実行内の値を更新します。
`setlocale` は `C` と `POSIX` を受け付けます。`socket`、`connect`、`bind`、`listen`、
`accept`、`send`、`recv`、`close` は `socketPeer` のメモリー内ピアを使い、ホストの
ソケットは開きません。

内部関数の呼び出しは持ち上げたコードを実行します。インポートスロットへの
書き込みは呼び出し先を指定したアドレスに変更します。未対応のインポート呼び出しは
エラーで停止します。`callReturns: {"external_name": 7}` またはアドレスのキーで
結果を指定できます。`skipCalls: true` は未処理の呼び出しをゼロで返します。
明示的に指定した結果はライブラリのフックより優先され、その副作用も省略します。
これらは整数結果だけを指定し、その他の副作用は再現しません。規約上、呼び出しが
変更できるレジスターは、定義した結果以外を `"unknown"` として返します。その値を
必要とする操作は停止します。部分書き込みでは既知のビットを維持します。`free` など戻り値がない呼び出しでは整数結果も不明になります。
`skipCalls` 指定時もフックは実行します。未対応のシステムコールでは停止します。

結果には最終 `registers`、整数 `returnValue`、変更メモリー、`steps`、停止
`address`、`reason`、`error`、任意の `trace` を含めます。停止理由は `return`、`exit`、
`end address`、`trap`、`stack check failed`、`step limit`、`time limit`、`error` です。CLI は復帰か
終了アドレスの場合だけ成功します。MCP は他の停止をエラーとし、レポートを維持します。
不正な初期設定は入力エラーです。

未マップ読み取り、保護メモリーへの書き込み、不明なフラグ、未対応命令、外部の
マシン状態が必要な操作は明示的に停止します。エラーに命令アドレスを含め、メモリー
エラーにはアクセス先も含めます。欠けている値や呼び出し結果は推測しません。

## テスト

`cargo test --release --test emulation -- --test-threads 3` は
`tests/make_emulation_fixtures.sh` で C のテスト用バイナリーをビルドします。
ルーチンのテストでは自動ベクトル化を無効にして `-O0` と `-O2` を使い、
x86-64、AArch64、x86-32、ARM32、Thumb を対象にします。戻り値とバッファーを
コンパイルした C の実行結果と比較し、ライブラリ、CLI、JavaScript の両方の
実行方法、MCP の完全なレポートも比較します。macOS では参照用の arm64 と
x86-64 の実行ファイル自体もエミュレートします。この文書の CLI と JavaScript の
例、README ファイルのエミュレーションコマンドもテストとして実行します。

## 標準入出力と実行後のメモリ

CLI は停止理由、戻り値、stdout、stderr、指定したメモリをテキストで表示します。
`--json` を付けると完全な JSON を表示します。JavaScript と MCP は同じデータを返します。

```sh
velk --emulate app.elf check_flag --emulation-options '{"stdin":{"text":"flag{input}\n"}}'
velk --emulate app.elf main --emulation-options '{"argv":["app","candidate"]}'
velk --emulate app.elf decode_buffer --emulation-options '{"reads":[{"symbol":"decoded"}]}'
```

`stdin` は `text`（UTF-8）、`hex`（空白を含められる16進バイト列）、`file`
（実行前にホストで読むファイル）のいずれか一つです。上限は16 MiBで、未指定なら EOF
になります。入力フックは一つの入力列を順に消費します。`argv` はプログラム名を含み、
argc と末尾がヌルポインタの argv を設定します。`arguments` や Go 関数とは併用できません。
`socketPeer` も同じ入力形式を受け付け、決定的なメモリー内ピアから `recv` に
渡すバイト列を指定します。全ソケットが同じ入力列を使い、送信は成功し、
`close` はエミュレートしたディスクリプターを解放します。

`stdout` と `stderr` は各16 MiBまでです。不正な UTF-8 は置換文字になります。
`printf`、`fprintf`、`sprintf`、`snprintf` は `%d %i %u %x %X %o %c %s %p %%`、
整数の長さ `hh h l ll j z t`、フラグ `- + # 0`、幅と精度（`*` を含む）に対応します。
`%p` は `0x` 付き16進数、ゼロは `(nil)` です。浮動小数点、ワイド文字、位置指定、
`%n` はエラーになります。printf と scanf の v で始まる関数は対象の va_list を読み取ります。AArch64 Mach-O の直接の可変引数 I/O は引数配置が未実装のため停止します。アーキテクチャのテスト行列は ELF を使います。`snprintf` は切り詰め前の長さを返します。

入力は fd 0 の `read`、`fread`、`fgets`、`gets`、`getchar`、`scanf`、`fscanf`、
`sscanf`（`__isoc99_` 名も含む）に対応します。走査は `d i u x X o s c`、幅、
代入抑制に対応し、未対応の変換は指定子を含むエラーになります。定義またはインポートされた
`stdin`、`stdout`、`stderr` に標準ストリームを用意します。それ以外のストリームには明示したファイル入力が必要です。
`puts`、`putchar`、`fputs`、`fwrite`、fd 1 と2の `write` は出力を記録します。
その他のファイル操作とシステムコールは実行しません。

`reads` はエラーや制限で停止した場合も実行後のメモリを読みます。各項目に `address`、
定義済みデータの `symbol`、最終ポインタを含む完全な `register` 名のいずれか一つを指定します。
バイト数 `length` を省略すると NUL まで読みます。合計の上限は16 MiBです。
`format` は `string`（既定）、`bytes`、`hex`（空白区切り）、`integers` です。
整数は `width` 1、2、4、8が必須で、長さは幅の倍数にします。符号なしリトルエンディアンを
10進文字列で返します。結果の `reads` に `address`、`bytes`、`value` が入ります。
未マップメモリ、不明なレジスタやシンボル、NUL のない文字列はエラーになります。
読み取りの上限は実行ステップ数とは独立しています。

ストリームと argv は malloc より前にヒープ領域を確保します。先行するフックが不明にした
未使用レジスタを後続の可変引数関数が保存しようとすると、実行が停止する場合があります。

自動的な文字列復元では stdin の設定も I/O フックの実行もしません。入力に依存する復号は明示的にエミュレーションします。

Windows ARM64 の幅のフィクスチャは、64ビットのポインタと32ビットの `long` の出力と走査を検査します。インポート先を明示してフックを呼びます。Windows プロセス状態の自動設定は x86-64 と i386 が対象です。

## Windows プロセスの設定

x86-64 と i386 の PE では `tlsBase` に 8 KiB の TEB を用意し、それぞれ GS と FS
から参照します。PEB にはメインイメージのベース、プロセスパラメーター、メインモジュール、
ntdll、kernel32、kernelbase、およびインポートした DLL のローダーリストを設定します。
モデル化した DLL は読み取り専用の PE ヘッダーとエクスポートディレクトリーを持ちます。
名前付き IAT、エクスポート表の走査、`GetProcAddress`（名前またはモデルの序数）、
`GetModuleHandleA/W`、`LoadLibraryA/W` は同じアドレスを使います。ライブラリーのロードは
モデル内のモジュールだけを解決し、ホストの DLL を開きません。未知の API は
`callReturns` または `skipCalls` で明示的に上書きしなければ、DLL 名を含む診断で停止します。
メインモジュールの転送エクスポートと序数だけのインポートには未対応です。

メインイメージの静的 TLS テンプレートとゼロ領域を用意してから、TLS コールバックを
`DLL_PROCESS_ATTACH` で呼び出します。各エミュレーションで選択した関数の前に1回実行し、
そのメモリー変更を結果に含めます。`TlsAlloc`、`TlsFree`、`TlsGetValue`、`TlsSetValue`
は TEB の64スロットを扱います。DLL 初期化ルーチンには未対応です。
`ExitProcess` は終了コードを記録する前に、メインイメージのコールバックを
`DLL_PROCESS_DETACH` と非 NULL の予約引数で呼び出します。モデル化した CRT を読み込んだ
場合、その前に CRT のファイルストリームをフラッシュして閉じます。終了後の CRT 標準入出力
は出力せず、CRT が所有する Windows 標準ハンドルも閉じます。別に開いた Windows の
ファイルハンドルは終了コールバック内でも使用できます。`exit` は先に `atexit` と `_onexit`
のハンドラーを登録の逆順で呼び出します。直接の `ExitProcess` はこれらを呼び出しません。
終了コールバック内の API 呼び出しは、失敗した書き込みも含めて `apiCalls` に残ります。
選択した関数からの通常の
復帰ではプロセスを終了せず、終了時のコールバックも実行しません。
`CreateThread` は NULL のセキュリティー記述子、既定のスタックサイズ、ゼロの作成フラグに
対応します。待機中のスレッドは、そのハンドルを `WaitForSingleObject` に `INFINITE` と
ともに渡すと実行します。タイムアウトがゼロなら実行せずに待機中と返します。実行は逐次的です。
各ワーカーは別のスタック、TEB、最終エラー値、静的 TLS テンプレート、動的 TLS スロットを
持ちます。開始関数の前に `DLL_THREAD_ATTACH`、復帰または `ExitThread` の後に
`DLL_THREAD_DETACH` でコールバックを呼び、予約引数は両方とも NULL です。
`GetExitCodeThread` は完了まで `STILL_ACTIVE` を返します。有限時間の待機、スレッド内からの
別スレッドの待機、待機中のスレッドハンドルのクローズ、初期スレッドからの `ExitThread`
は診断を出して停止します。開始前のスレッドはプロセス終了時にコールバックを受けません。
プロセス終了時のコールバック内の `ExitProcess` は診断を出して停止します。

`GetCurrentProcessId` と `GetCurrentThreadId` は1000と1001を返します。プロセスとスレッドの
疑似ハンドル、`ExitProcess`、TEB の最終エラー値をモデル化しています。`Sleep` は実際には
待機せず、時計を指定したミリ秒だけ進めます。`Sleep(INFINITE)` は停止します。
`GetTickCount`、`GetTickCount64`、`QueryPerformanceCounter/Frequency`、
`GetSystemTimeAsFileTime` は命令数に基づく同じ時計を使います。周波数は1 GHzで、
`time` オプションが FILETIME の Unix 時刻の基準を設定します。
`CheckRemoteDebuggerPresent` と PEB の `BeingDebugged` は `antiAnalysis.debuggerPresent`
を使い、既定値は false です。`IsDebuggerPresent` はプログラムによる書き換えも含め、
現在の PEB の値を読みます。`NtGlobalFlag` はゼロで開始します。PEB のデバッグ情報の
読み取りとデバッガー・時刻 API の呼び出しは `antiAnalysis` に記録します。

`windows: {commandLine, imagePath, environment}` でプロセスパラメーターを設定します。
既定値は `program.exe`、`C:\\program.exe`、空の環境変数です。文字列は UTF-16 を使い、
ANSI のモジュール名と `GetCommandLineA` は ASCII に限定します。環境変数名は大文字と
小文字を区別せず、重複する名前と埋め込まれた NUL は拒否します。`GetCommandLineA/W`、
`GetEnvironmentStringsW`、`FreeEnvironmentStringsW` から参照できます。CLI、JavaScript、
MCP、`--serve` で同じオプションを使います。
プロセスの管理情報はプログラムの割り当てより前にヒープ領域を使います。ヒープ上の
バッファーのアドレスを引数で渡す場合は、初期 `memory` 書き込みでその領域を確保してください。
`sh tools/make_windows_emulation_fixtures.sh` で構築したフィクスチャの例です。

```sh
velk --emulate target/windows-emulation-fixtures/x86_64.O0.exe process_parameters --emulation-options '{"windows":{"commandLine":"program.exe sample","environment":{"NAME":"value"}}}' --json
```

`apiCalls` は DLL 名付きの API 名と16進数のスカラー引数を実行順に記録します。
CRT の可変引数関数は固定引数だけを記録し、シグネチャが不明な関数の引数配列は空です。
インポートした msvcrt/ucrt の関数は、既存の C ライブラリーフックとその制限に従います。
エクスポート表にはメモリー・文字列操作、割り当て、整数の書式付き入出力とファイルストリームの
関数を含みます。`__acrt_iob_func` は UCRT の三つの標準ストリームを返します。
UCRT の書式付き出力は `__stdio_common_vfprintf` と `__stdio_common_vsprintf`、
入力は長さ制限のない NUL 終端文字列に対する `__stdio_common_vsscanf` で処理します。
これらの関数は既定のロケールを使い、未対応のオプションビットを拒否します。
文字列への出力は、切り詰めない場合の従来の終端オプションと、切り詰める場合の
標準の `snprintf` オプションに対応します。
`_crt_atexit` は UCRT の終了コールバックを登録します。モデルの UCRT エクスポート表には
`printf`、`sprintf`、`sscanf`、`atexit` などのインラインラッパーを含めず、
これらの名前のインポートはプロセスの初期化時に失敗します。
Windows CRT のファイルストリームはバイナリーモードに限定します。テキスト変換、
`strtol` の Windows データモデル、`realloc`、CRT の起動・即時終了関数には未対応です。

`GetProcessHeap` は PEB に記録したプロセスヒープのハンドルを返します。`HeapAlloc`、
`HeapReAlloc`、`HeapFree` はブロックのサイズを管理し、サイズ 0 の割り当ても扱います。
再割り当てでは保持するバイトを保存し、`HEAP_ZERO_MEMORY` は追加部分をゼロにします。
`HEAP_REALLOC_IN_PLACE_ONLY` は移動を拒否します。割り当て失敗時は元のブロックと
最終エラー値を保持します。既存の 16 MiB のヒープ領域を使い、解放した領域は再利用しません。
不正なヒープハンドル、ブロックポインター、未対応のフラグではエラーで停止します。
ヒープの例外は未対応です。

`VirtualAlloc` は `MEM_RESERVE`、`MEM_COMMIT` とその組み合わせに対応し、ページは
4 KiB、予約開始アドレスのアラインメントは 64 KiB です。仮想領域の予約にはヒープと別に
合計 16 MiB の上限があります。`VirtualFree` はデコミットと元の割り当てアドレスを指定した
予約全体の解放に対応し、別の解放アドレスでは未対応として停止します。
再コミットしたページはゼロにします。`VirtualProtect` は一つの仮想予約内のコミット済み
ページの保護を変更し、最初のページの以前の保護値を返します。
以前の保護値を受け取るポインターが null なら API の失敗を返し、その他の不正な
出力ポインターでは API 境界でエミュレーションを停止します。`PAGE_NOACCESS`、
`PAGE_READONLY`、`PAGE_READWRITE` と各実行属性付きの値について読み書きの権限を
検査します。仮想領域のコード実行、イメージやヒープの保護変更、変更領域内の出力ポインター、
ガードページ、その他の割り当て・保護フラグは未対応で、成功を返さず停止します。
仕様は [HeapReAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc)
と [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) を参照してください。
`lstrlenA/W` はバイト数または UTF-16 コード単位数を数えます。孤立サロゲートも数え、
NULL ポインターには 0 を返します。`MultiByteToWideChar` と `WideCharToMultiByte` は
UTF-8（65001）と、CP_ACP（0）または 1252 の ASCII 入力に対応します。その他の
コードページと非 ASCII の ANSI 変換は診断を出して停止します。明示した長さでは途中の
NUL を保持し、長さ -1 では終端も含めます。出力容量 0 では必要な長さを返します。
不正なフラグ・引数、容量不足、厳格な Unicode 検証の失敗は最終エラーを設定します。
厳格な検証を指定しない場合、不正な UTF-8/UTF-16 を U+FFFD に置換します。仕様は
[MultiByteToWideChar](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)
と [WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte) を参照してください。
`GetStdHandle` とプロセスパラメーターは仮想 stdin、stdout、stderr のハンドルを返します。
`WriteFile`、`ReadFile`、`CreateFileA/W`、`CloseHandle` は `files` 上の同期ファイルを扱い、
ハンドルを閉じた後は内容を CRT ストリームと共有できます。同じファイルを CRT と Windows の
ハンドルで同時に開く場合は診断を出して停止します。読み取りはバイトを保持し、EOF では短い読み取り数を返し、
各ハンドルの位置を進めます。書き込みは直ちにレポートに反映します。作成方法 1–5、
汎用読み書きアクセス、読み書きの共有モードに対応します。パスは ASCII に限定し、大小文字を
区別せず、スラッシュを同じ扱いにします。ホストへのアクセス、カレントディレクトリーの展開、
ディレクトリー、セキュリティー記述子、非同期 I/O、シークには未対応です。未対応のアクセス、
属性、共有フラグ、相対パス成分では診断を出して停止します。読み書きには処理数の出力ポインターが
必要です。`WriteConsoleA/W` は仮想出力ハンドルへの ASCII または正しい UTF-16 を記録し、
W の出力数は UTF-16 コード単位数です。仮想ハンドルはコンソールを表します。Wine との比較では
リダイレクトした出力に `WriteFile` を使います。仕様は
[CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) を参照してください。

レジストリーの内容は `windows.registry` に、例えば
`{"HKEY_CURRENT_USER\\Software\\Example":{"Count":{"type":4,"bytes":[37,0,0,0]}}}`
と指定します。`HKEY_CLASSES_ROOT`、`HKEY_CURRENT_USER`、`HKEY_LOCAL_MACHINE`、
`HKEY_USERS`、`HKEY_CURRENT_CONFIG` の五つのルートがあります。キー名と値名は ASCII に
限定し、大小文字を区別しません。指定したパスの親キーも存在します。型は Windows の
`REG_*` の番号で、データは生バイト列です。文字列型には UTF-16LE を使います。
`RegOpenKeyExA/W`、`RegQueryValueExA/W`、`RegCloseKey` は既定のビューの読み取りに対応します。
クエリーは型とバイト数を返し、容量不足には `ERROR_MORE_DATA` を返し、最終エラーを保持します。
ANSI 文字列のクエリーは ASCII に限定します。書き込み、列挙、別のビュー、`RegGetValue`
には未対応です。仕様は
[RegQueryValueEx](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa) を参照してください。
フィクスチャの `documented_registry` 関数は指定した DWORD を返します。

```sh
velk --emulate target/windows-emulation-fixtures/x86_64.registry.O0.exe documented_registry --emulation-options '{"windows":{"registry":{"HKEY_CURRENT_USER\\Software\\Example":{"Count":{"type":4,"bytes":[37,0,0,0]}}}}}' --json
```

メモリーの読み書きによるアクセス違反、整数のゼロ除算、`int3` は i386 の `fs:[0]` ハンドラーまたは x64 の
`.pdata` ハンドラーにディスパッチします。ハンドラーは検索を続行するか、`CONTEXT` の
整数・XMM レジスターと命令ポインターを変更して実行を再開できます。登録チェーンと
アンワインド検索の上限は128フレームです。x64 の検索はバージョン1のスタック割り当て、
保存した整数レジスター、フレームポインターに対応します。連鎖したアンワインドレコード、
プロローグ・エピローグ内の例外、反復命令、スケールしない大きな割り当て、遠いオフセットの
保存レジスター、XMM のアンワインド保存、マシンフレーム、入れ子の例外、言語固有のクリーンアップ・アンワインド
ハンドラー、その他の disposition は診断を出して停止します。未モデル化のコンテキスト
フィールド（フラグ、セグメントセレクター、デバッグレジスター、x87 状態など）の読み取りや
変更も停止します。
ディスパッチャーの仮想 `ContextRecord` は公開しません。フックへの不正なポインターは
API 境界で停止し、DLL 内の例外位置を作りません。
ディスパッチ前に未定義だったコンテキストのビットは、ハンドラーによる変更後も未定義として
扱います。
戻りアドレスの検索には呼び出し後の継続命令のアドレスを使います。継続命令が認識可能な
x64 エピローグの先頭なら、そのフレームのハンドラーを呼びません。

テストは両アーキテクチャを `-O0` と `-O2` でコンパイルし、プロセス状態、エクスポート
経由の呼び出し、ヒープの内容、仮想メモリーの状態遷移、不正アクセスの拒否、および
各実行インターフェースのレポートを検査します。ページの丸めには SMT 検査と具体的な
オーバーフローのテストがあります。`windows_matches_wine` テストは、
プロセス、メモリー、文字列、ファイル、レジストリー、CRT のフィクスチャの標準出力、標準エラー、
終了コード、ファイルのバイト列を Wine と比較します。出力にはメモリーのチェックサムや変換結果を
含みます。レジストリーを開くオプションのビット `1`、レジストリーキーとして開かれていない
ハンドルのクローズ、直接指定した終端のないデータの取得は、個別のエミュレーションテストで検査します。
[RegOpenKeyEx](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa)
で指定できるオプションはゼロまたは `REG_OPTION_OPEN_LINK` です。
[RegCloseKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey)
には開かれたキーのハンドルが必要です。
[RegSetValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw)
では、文字列データとバイト数に終端文字を含める必要があります。共通のフィクスチャでは
これらの入力を Wine に渡しません。Wine が Windows より寛容な、仕様で定められた
文字変換の引数検査も比較から除外します。
テキストの CRLF は正規化します。`target/` 以下にプレフィックスと実行時ディレクトリーを初期化します。
Wine の起動を検査し、初期化や起動ができない環境では理由を出して比較をスキップします。
プレフィックスではクラッシュデバッガーを無効にし、Wine の各呼び出しに45秒の制限を
設けます。出力はファイルに記録します。
テストは全フィクスチャの差分を集めてから失敗を報告します。
実行ファイルと、その隣に保存した `.exe.stdout`、`.exe.status` を比較するには、
`uv run tools/compare_windows_reference.py target/wine-reference` を実行します。
全実行ファイルの標準出力と終了コードを検査し、すべての差分を報告します。
レジストリーの保存結果に上記の三つの個別検査が含まれる場合は、共通の検査だけを比較します。

C++ ストリームのモデルは、64 ビットの ELF と Mach-O を対象に、libstdc++ と libc++ の
マングル名を認識します。`std::cout` への C 文字列、`std::string`、文字、十進整数、
`endl`、`flush` の出力を記録し、`std::cin` から単語、行、十進整数を読みます。
libstdc++ の小文字列とヒープ形式、libc++ の短形式と長形式に対応し、Mach-O では
代替レイアウトを選択します。文字列操作は既存のメモリと出力の 16 MiB 上限と
ヒープを使います。シンボリック実行では既存の 4,096〜65,536 バイトの上限を使います。文字列の構築・破棄、`std::ios_base::Init`、`__cxa_atexit` の登録もモデル化
しています。ストリームの書式変更、入力失敗、整数のオーバーフロー、未対応の
C++ 呼び出しは診断を出して停止します。既定の書式が対象で、独自のロケールや
一般の文字列操作には対応していません。文字列の確保容量はモデルが選びます。

Linux ELF の `read`、`write`、`exit`、`exit_group` システムコールは、x86-64 (`syscall`)、i386 (`int 0x80`)、AArch64 (`svc 0`) で標準入出力のモデルを使います。未知のシステムコール番号では診断を出して停止します。

## ファイルストリーム

実行オプションの `files: {"input": [79, 75, 10], "output": []}` で仮想パスを
用意します。パスは完全一致です。出力先を含め、開くパスにはすべてエントリーが必要です。
ホストのディレクトリやファイルを暗黙に読みません。CLI では `--emulation-options`、
JavaScript ではオプション引数、`velk_emulate` では `options` に渡します。
`input` を開く関数の例です。

```sh
velk --emulate app.elf read_file --emulation-options '{"files":{"input":[79,75,10]}}' --json
```

仮想ファイルでは `fopen`、`fclose`、`fread`、`fwrite`、`fgets`、`fputs`、`fflush`、
`setvbuf`、`fileno`、`feof`、`ferror` に対応します。モードは `r`、`w`、`a`、`r+`、
`rb`、`wb`、`ab`、`r+b`、`rb+` です。テキスト・バイナリとも改行変換をせず、
NUL、CR、LF、UTF-8 でないバイトも保持します。パスは UTF-8 が必要です。
`w` は内容を空にし、`a` は現在の末尾に書き、`r+` は同じ位置で読み書きします。
末尾を超えて読もうとすると EOF を立てます。末尾にちょうど到達しただけでは立てません。
書き込み専用のストリームからの読み取り、読み取り専用への書き込みはエラー指標を立てて
失敗を返します。サイズがゼロの転送はゼロを返します。`fread` は完全な要素数を返し、
最後の不完全な要素も消費します。`fgets` は改行を含めて読み、NUL を付けます。
サイズ1では読み取らず NUL を書きます。`fputs` の成功値は、非負の許容値であるゼロです。

`setvbuf` はモードを記録し、転送動作は変えません。`fflush(file)`、`fflush(NULL)`、
`fclose` は内容をレポートの `files` に反映します。最外側の関数から戻るだけでは
ファイルを閉じません。未反映の書き込みも他の仮想ストリームからは読めますが、
反映するまではレポートには出ません。ホストには書き込みません。内容の合計上限は16 MiBです。
記述子は3から割り当て、再利用しません。Linux ELF の `open` は読み取り専用ファイルに
対応し、`O_CLOEXEC` と `O_LARGEFILE` も指定できます。`read` と `close` はこの記述子を
受け付けます。他のフラグ、記述子による `write`、書式付き入出力、シーク、指標のクリア、
`getline` には未対応です。未知のパス、未対応の
モード、不正または閉じた `FILE *` では、パスや値を示す診断で停止します。

`rand` と `srand` は glibc の既定の乱数列を使い、初期シードは 1 です。
実行ごとに独立した乱数状態を持ちます。`time` は固定の Unix 時刻（既定値 0）を返し、
`time` オプションで変更できます。引数が null でなければ、対象のポインター幅で同じ値を格納します。
`signal` は Linux のシグナルハンドラーを記録し、直前のハンドラーを返します。
`alarm` は保留中のタイマーを置き換えて直前の秒数を返します。
`setbuf` は標準ストリームまたは仮想ファイルで null バッファーを受け付けます。呼び出し側が所有するバッファーには対応しません。

エミュレーションオプションの `antiAnalysis` で、解析対策チェックへの回答を設定できます。
既定では `ptrace(PTRACE_TRACEME)` は1回成功し、2回目以降は失敗します。`getppid` は1を返し、
`prctl(PR_SET_DUMPABLE)` は成功し、`getenv("LD_PRELOAD")` は未設定を返します。
`/proc/self/status` と `/proc/self/maps` は仮想内容を返します。デバッガー検出APIは既定で false を返します。
`rdtsc`、`rdtscp`、`cntvct_el0`、`clock_gettime`、`gettimeofday`、`GetTickCount`、
`QueryPerformanceCounter` は実行済み命令数に応じて進み、`clockTicksPerInstruction` の既定値は1です。
レポートの `antiAnalysis` 配列には処理したチェックを記録します。たとえば
`{"antiAnalysis":{"debuggerPresent":true,"parentProcessId":42,"preload":"/lib/example.so"}}`
で回答を変更できます。設定項目は `debuggerPresent`、`ptraceTracemeSucceeds`、`parentProcessId`、
`tracerProcessId`、`dumpable`、`preload`、`clockTicksPerInstruction` です。
x86-64 ELF では `SIGTRAP` ハンドラー登録後の `int3` がハンドラーを呼び出し、ブレークポイントの次から再開します。
シンボリック実行でも親プロセスID、デバッガー回答、ダンプ可能設定、最初の `PTRACE_TRACEME` の結果を使います。

`exit` は仮想ファイルのストリームをフラッシュして実行を終了します。終了時ハンドラーの登録関数に名前があるか、インポートする場合は診断を出して停止します。libc の `_exit` 呼び出しには対応しません。
