#include <winsock2.h>
#include <windows.h>

__attribute__((noinline)) DWORD windows_file(HANDLE file) {
    return GetFileType(file);
}

__attribute__((noinline)) HANDLE windows_process(DWORD process) {
    return OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process);
}

__attribute__((noinline)) void *windows_memory(SIZE_T size) {
    return VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

__attribute__((noinline)) LONG windows_registry(HKEY key) {
    return RegCloseKey(key);
}

__attribute__((noinline)) SOCKET windows_socket(void) {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

__attribute__((noinline)) DWORD windows_thread(void) {
    return GetCurrentThreadId();
}

__attribute__((noinline)) DWORD windows_time(FILETIME *time) {
    GetSystemTimeAsFileTime(time);
    return time->dwHighDateTime;
}

void fixture_entry(void) {}
