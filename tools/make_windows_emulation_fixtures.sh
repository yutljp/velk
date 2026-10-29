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
UnknownWindowsApi
DLL
cat > "$out/msvcrt.def" <<'DLL'
LIBRARY msvcrt.dll
EXPORTS
printf
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
            /^HeapAlloc$|^HeapFree$|^VirtualFree$/ { print "_" $0 "@12 EXPORTAS " $0; next }
            /^HeapReAlloc$|^VirtualAlloc$|^VirtualProtect$/ { print "_" $0 "@16 EXPORTAS " $0; next }
            /^[A-Z][a-z]/ { print "_" $0 "@4 EXPORTAS " $0; next }
            { print }
        ' "$out/kernel32.def" > "$out/kernel32.x86.def"
        definition="$out/kernel32.x86.def"
    else
        definition="$out/kernel32.def"
    fi
    lld-link /lib /def:"$definition" /machine:"$machine" /out:"$out/kernel32.$architecture.lib"
    lld-link /lib /def:"$out/msvcrt.def" /machine:"$machine" /out:"$out/msvcrt.$architecture.lib"
    clang --target="$target" -O0 -fno-stack-protector -c tests/emulation/windows_unknown.c -o "$out/$architecture.unknown.obj"
    lld-link /dll /noentry /nodefaultlib /Brepro /out:"$out/$architecture.unknown.dll" \
        "$out/$architecture.unknown.obj" "$out/kernel32.$architecture.lib"
    for optimization in O0 O2; do
        clang --target="$target" -"$optimization" -fno-builtin -fno-stack-protector \
            -fno-vectorize -fno-slp-vectorize -fno-optimize-sibling-calls \
            -c tests/emulation/windows.c -o "$out/$architecture.$optimization.obj"
        lld-link /entry:entry /subsystem:console /nodefaultlib /fixed /Brepro \
            /out:"$out/$architecture.$optimization.exe" "$out/$architecture.$optimization.obj" \
            "$out/kernel32.$architecture.lib" "$out/msvcrt.$architecture.lib"
        clang --target="$target" -"$optimization" -fno-builtin -fno-stack-protector \
            -fno-vectorize -fno-slp-vectorize -fno-optimize-sibling-calls \
            -c tests/emulation/windows_memory.c -o "$out/$architecture.memory.$optimization.obj"
        lld-link /entry:entry /subsystem:console /nodefaultlib /fixed /Brepro \
            /out:"$out/$architecture.memory.$optimization.exe" "$out/$architecture.memory.$optimization.obj" \
            "$out/kernel32.$architecture.lib" "$out/msvcrt.$architecture.lib"
    done
done
