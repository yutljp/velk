#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
out=${1:-target/windows-emulation-fixtures}
mkdir -p "$out"
cat > "$out/kernel32.def" <<'DLL'
LIBRARY kernel32.dll
EXPORTS
GetCurrentProcessId
GetCurrentThreadId
GetCurrentProcess
GetCurrentThread
ExitProcess
CreateThread
ExitThread
WaitForSingleObject
GetExitCodeThread
GetLastError
SetLastError
Sleep
GetTickCount
GetTickCount64
QueryPerformanceCounter
QueryPerformanceFrequency
GetSystemTimeAsFileTime
IsDebuggerPresent
CheckRemoteDebuggerPresent
GetModuleHandleA
GetModuleHandleW
LoadLibraryA
LoadLibraryW
GetProcAddress
GetCommandLineA
GetCommandLineW
GetEnvironmentStringsW
FreeEnvironmentStringsW
TlsAlloc
TlsFree
TlsGetValue
TlsSetValue
GetProcessHeap
HeapAlloc
HeapReAlloc
HeapFree
VirtualAlloc
VirtualProtect
VirtualFree
lstrlenA
lstrlenW
MultiByteToWideChar
WideCharToMultiByte
GetStdHandle
WriteFile
ReadFile
WriteConsoleA
WriteConsoleW
CreateFileA
CreateFileW
CloseHandle
UnknownWindowsApi
DLL
cat > "$out/msvcrt.def" <<'DLL'
LIBRARY msvcrt.dll
EXPORTS
printf
atexit
_onexit
exit
fprintf
sprintf
snprintf
vprintf
vsprintf
vsnprintf
puts
putchar
malloc
calloc
free
memcpy
memmove
memset
memcmp
memchr
strlen
strnlen
strcmp
strncmp
strcpy
strncpy
strchr
strcspn
atoi
strtol
toupper
tolower
sscanf
fopen
fclose
fflush
setbuf
setvbuf
fputs
fwrite
fread
fgets
feof
ferror
rand
DLL
sed -e 's/LIBRARY msvcrt.dll/LIBRARY ucrtbase.dll/' \
    -e '/^printf$/d' -e '/^fprintf$/d' -e '/^sprintf$/d' -e '/^snprintf$/d' \
    -e '/^vprintf$/d' -e '/^vsprintf$/d' -e '/^vsnprintf$/d' -e '/^sscanf$/d' \
    -e '/^atexit$/d' -e '/^_onexit$/d' "$out/msvcrt.def" > "$out/ucrtbase.def"
cat >> "$out/ucrtbase.def" <<'DLL'
__acrt_iob_func
__stdio_common_vfprintf
__stdio_common_vsprintf
__stdio_common_vsscanf
_crt_atexit
DLL
cat > "$out/advapi32.def" <<'DLL'
LIBRARY advapi32.dll
EXPORTS
RegOpenKeyExA
RegOpenKeyExW
RegQueryValueExA
RegQueryValueExW
RegCloseKey
RegCreateKeyExW
RegSetValueExW
RegDeleteKeyW
DLL
for architecture in x86_64 i386; do
    case "$architecture" in
        x86_64) target=x86_64-windows-msvc; machine=x64 ;;
        i386) target=i686-windows-msvc; machine=x86 ;;
    esac
    # stdcall import libraries retain decoration in COFF and use undecorated PE names.
    if [ "$machine" = x86 ]; then
        awk '
            /^GetCurrentProcessId$|^GetCurrentThreadId$|^GetCurrentProcess$|^GetCurrentThread$|^GetLastError$|^GetTickCount$|^GetTickCount64$|^IsDebuggerPresent$|^GetCommandLineA$|^GetCommandLineW$|^GetEnvironmentStringsW$|^TlsAlloc$|^GetProcessHeap$|^UnknownWindowsApi$/ { print "_" $0 "@0 EXPORTAS " $0; next }
            /^CheckRemoteDebuggerPresent$|^GetProcAddress$|^TlsSetValue$/ { print "_" $0 "@8 EXPORTAS " $0; next }
            /^WaitForSingleObject$|^GetExitCodeThread$/ { print "_" $0 "@8 EXPORTAS " $0; next }
            /^CreateThread$/ { print "_" $0 "@24 EXPORTAS " $0; next }
            /^HeapAlloc$|^HeapFree$|^VirtualFree$/ { print "_" $0 "@12 EXPORTAS " $0; next }
            /^HeapReAlloc$|^VirtualAlloc$|^VirtualProtect$/ { print "_" $0 "@16 EXPORTAS " $0; next }
            /^MultiByteToWideChar$/ { print "_" $0 "@24 EXPORTAS " $0; next }
            /^WideCharToMultiByte$/ { print "_" $0 "@32 EXPORTAS " $0; next }
            /^WriteFile$|^ReadFile$|^WriteConsole[AW]$/ { print "_" $0 "@20 EXPORTAS " $0; next }
            /^CreateFile[AW]$/ { print "_" $0 "@28 EXPORTAS " $0; next }
            /^lstrlen[AW]$/ { print "_" $0 "@4 EXPORTAS " $0; next }
            /^[A-Z][a-z]/ { print "_" $0 "@4 EXPORTAS " $0; next }
            { print }
        ' "$out/kernel32.def" > "$out/kernel32.x86.def"
        definition="$out/kernel32.x86.def"
    else
        definition="$out/kernel32.def"
    fi
    lld-link /lib /def:"$definition" /machine:"$machine" /out:"$out/kernel32.$architecture.lib"
    lld-link /lib /def:"$out/msvcrt.def" /machine:"$machine" /out:"$out/msvcrt.$architecture.lib"
    lld-link /lib /def:"$out/ucrtbase.def" /machine:"$machine" /out:"$out/ucrtbase.$architecture.lib"
    if [ "$machine" = x86 ]; then
        awk '
            /^RegOpenKeyEx[AW]$/ { print "_" $0 "@20 EXPORTAS " $0; next }
            /^RegQueryValueEx[AW]$|^RegSetValueExW$/ { print "_" $0 "@24 EXPORTAS " $0; next }
            /^RegCloseKey$/ { print "_" $0 "@4 EXPORTAS " $0; next }
            /^RegCreateKeyExW$/ { print "_" $0 "@36 EXPORTAS " $0; next }
            /^RegDeleteKeyW$/ { print "_" $0 "@8 EXPORTAS " $0; next }
            { print }
        ' "$out/advapi32.def" > "$out/advapi32.x86.def"
        definition="$out/advapi32.x86.def"
    else
        definition="$out/advapi32.def"
    fi
    lld-link /lib /def:"$definition" /machine:"$machine" /out:"$out/advapi32.$architecture.lib"
    clang --target="$target" -fno-stack-protector -c tests/emulation/windows_probe.c -o "$out/$architecture.probe.obj"
    lld-link /entry:entry /subsystem:console /nodefaultlib /fixed /Brepro \
        /out:"$out/$architecture.probe.exe" "$out/$architecture.probe.obj" "$out/kernel32.$architecture.lib"
    clang --target="$target" -O0 -fno-stack-protector -c tests/emulation/windows_unknown.c -o "$out/$architecture.unknown.obj"
    lld-link /dll /noentry /nodefaultlib /Brepro /out:"$out/$architecture.unknown.dll" \
        "$out/$architecture.unknown.obj" "$out/kernel32.$architecture.lib"
    for optimization in O0 O2; do
        clang --target="$target" -c tests/emulation/windows_seh.S -o "$out/$architecture.seh.asm.obj"
        clang --target="$target" -"$optimization" -fno-stack-protector -c tests/emulation/windows_seh.c -o "$out/$architecture.seh.obj"
        lld-link /entry:entry /subsystem:console /nodefaultlib /fixed /Brepro /safeseh:no \
            /out:"$out/$architecture.seh.$optimization.exe" "$out/$architecture.seh.obj" "$out/$architecture.seh.asm.obj" \
            "$out/kernel32.$architecture.lib" "$out/msvcrt.$architecture.lib"
        clang --target="$target" -"$optimization" -fno-builtin -fno-stack-protector \
            -fno-vectorize -fno-slp-vectorize -fno-optimize-sibling-calls \
            -c tests/emulation/windows.c -o "$out/$architecture.$optimization.obj"
        lld-link /entry:entry /subsystem:console /nodefaultlib /fixed /Brepro \
            /out:"$out/$architecture.$optimization.exe" "$out/$architecture.$optimization.obj" \
            "$out/kernel32.$architecture.lib" "$out/msvcrt.$architecture.lib"
        for group in memory strings files registry crt ucrt exit ucrt_exit threads; do
            case "$group" in
                ucrt) source=crt; flags=-DUCRT; library=ucrtbase ;;
                ucrt_exit) source=exit; flags=-DUCRT; library=ucrtbase ;;
                *) source="$group"; flags=; library=msvcrt ;;
            esac
            clang --target="$target" -"$optimization" -fno-builtin -fno-stack-protector \
                -fno-vectorize -fno-slp-vectorize -fno-optimize-sibling-calls \
                $flags -c "tests/emulation/windows_$source.c" -o "$out/$architecture.$group.$optimization.obj"
            case "$group" in registry) entry=native_entry ;; *) entry=entry ;; esac
            lld-link /entry:"$entry" /subsystem:console /nodefaultlib /fixed /Brepro \
                /out:"$out/$architecture.$group.$optimization.exe" "$out/$architecture.$group.$optimization.obj" \
                "$out/kernel32.$architecture.lib" "$out/$library.$architecture.lib" "$out/advapi32.$architecture.lib"
        done
    done
done
