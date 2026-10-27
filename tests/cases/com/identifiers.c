#include <initguid.h>
#include <objbase.h>
#include <shobjidl.h>

__declspec(dllexport) const IID *com_unknown_id(void) {
    return &IID_IUnknown;
}

__declspec(dllexport) const IID *com_stream_id(void) {
    return &IID_IStream;
}

__declspec(dllexport) const CLSID *com_file_dialog_class(void) {
    return &CLSID_FileOpenDialog;
}

__declspec(dllexport) const unsigned char *com_unknown_bytes(void) {
    static const unsigned char bytes[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x47};
    return bytes;
}
