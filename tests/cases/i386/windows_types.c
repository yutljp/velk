__declspec(dllimport) unsigned int __stdcall GetFileType(void *file);
__declspec(dllexport) unsigned int windows_file(void *file) { return GetFileType(file); }
__declspec(dllimport) unsigned int __stdcall GetLastError(void);
__declspec(dllexport) unsigned int windows_error(void) { return GetLastError(); }
