#define COBJMACROS
#include <objbase.h>
#include <objidl.h>
#include <oaidl.h>

__declspec(dllexport) ULONG com_add_ref(IUnknown *object) {
    return IUnknown_AddRef(object);
}

__declspec(dllexport) ULONG com_release(IUnknown *object) {
    return IUnknown_Release(object);
}

__declspec(dllexport) HRESULT com_query(IUnknown *object, REFIID iid, void **result) {
    return IUnknown_QueryInterface(object, iid, result);
}

__declspec(dllexport) HRESULT com_read(IStream *stream, void *buffer, ULONG size, ULONG *read) {
    return IStream_Read(stream, buffer, size, read);
}

__declspec(dllexport) HRESULT com_write(IStream *stream, const void *buffer, ULONG size, ULONG *written) {
    return IStream_Write(stream, buffer, size, written);
}

__declspec(dllexport) HRESULT com_type_info_count(IDispatch *object, UINT *count) {
    return IDispatch_GetTypeInfoCount(object, count);
}

__declspec(dllexport) HRESULT com_create_stream(IStream **stream) {
    return CreateStreamOnHGlobal(0, 1, stream);
}
