/*
 * Copyright 2014 Andrew Eikum for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#define COBJMACROS
#include "initguid.h"
#include "windef.h"
#include "winbase.h"
#include "ole2.h"
#include "rpcproxy.h"
#include "shellapi.h"
#include "shlwapi.h"

#include "wine/debug.h"

#include "packager_classes.h"

WINE_DEFAULT_DEBUG_CHANNEL(packager);

static const CLSID CLSID_Package_Alt = {0x0003000c, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};

struct Package {
    IOleObject IOleObject_iface;
    IPersistStorage IPersistStorage_iface;
    IViewObject2 IViewObject2_iface;

    LONG ref;

    WCHAR filename[MAX_PATH];
    WCHAR label[MAX_PATH];
    WCHAR icon_path[MAX_PATH];
    WORD icon_index;

    /* contents of the \1Ole10Native stream, written back by Save */
    BYTE *data;
    DWORD data_size;
    BOOL dirty;

    IOleClientSite *clientsite;
    IOleAdviseHolder *advise_holder;

    IAdviseSink *view_sink;
    DWORD view_aspects, view_advf;
};

static inline struct Package *impl_from_IOleObject(IOleObject *iface)
{
    return CONTAINING_RECORD(iface, struct Package, IOleObject_iface);
}

static inline struct Package *impl_from_IPersistStorage(IPersistStorage *iface)
{
    return CONTAINING_RECORD(iface, struct Package, IPersistStorage_iface);
}

static inline struct Package *impl_from_IViewObject2(IViewObject2 *iface)
{
    return CONTAINING_RECORD(iface, struct Package, IViewObject2_iface);
}

/* The package is shown as its icon with the label below it. */
static HGLOBAL get_metafilepict(struct Package *This)
{
    HICON icon = ExtractIconW(NULL, This->icon_path, This->icon_index);
    HGLOBAL ret;

    if (icon == (HICON)1) icon = NULL;
    ret = OleMetafilePictFromIconAndLabel(icon ? icon : LoadIconW(NULL, (const WCHAR *)IDI_APPLICATION),
            This->label, NULL, 0);
    if (icon) DestroyIcon(icon);
    return ret;
}

static void free_metafilepict(HGLOBAL hmfp)
{
    METAFILEPICT *mfp = GlobalLock(hmfp);

    DeleteMetaFile(mfp->hMF);
    GlobalUnlock(hmfp);
    GlobalFree(hmfp);
}

static HRESULT WINAPI OleObject_QueryInterface(IOleObject *iface, REFIID riid, void **obj)
{
    struct Package *This = impl_from_IOleObject(iface);

    if(IsEqualGUID(riid, &IID_IUnknown) ||
            IsEqualGUID(riid, &IID_IOleObject)) {
        TRACE("(%p)->(IID_IOleObject, %p)\n", This, obj);
        *obj = &This->IOleObject_iface;
    }else if(IsEqualGUID(riid, &IID_IPersist) ||
            IsEqualGUID(riid, &IID_IPersistStorage)){
        TRACE("(%p)->(IID_IPersistStorage, %p)\n", This, obj);
        *obj = &This->IPersistStorage_iface;
    }else if(IsEqualGUID(riid, &IID_IViewObject) ||
            IsEqualGUID(riid, &IID_IViewObject2)){
        TRACE("(%p)->(IID_IViewObject2, %p)\n", This, obj);
        *obj = &This->IViewObject2_iface;
    }else {
        FIXME("(%p)->(%s, %p)\n", This, debugstr_guid(riid), obj);
        *obj = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*obj);
    return S_OK;
}

static ULONG WINAPI OleObject_AddRef(IOleObject *iface)
{
    struct Package *This = impl_from_IOleObject(iface);
    LONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    return ref;
}

static ULONG WINAPI OleObject_Release(IOleObject *iface)
{
    struct Package *This = impl_from_IOleObject(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    if(!ref){
        if(This->clientsite)
            IOleClientSite_Release(This->clientsite);
        if(This->advise_holder)
            IOleAdviseHolder_Release(This->advise_holder);
        if(This->view_sink)
            IAdviseSink_Release(This->view_sink);
        HeapFree(GetProcessHeap(), 0, This->data);

        if(*This->filename)
            DeleteFileW(This->filename);

        HeapFree(GetProcessHeap(), 0, This);
    }

    return ref;
}

static HRESULT WINAPI OleObject_SetClientSite(IOleObject *iface, IOleClientSite *pClientSite)
{
    struct Package *This = impl_from_IOleObject(iface);

    TRACE("(%p)->(%p)\n", This, pClientSite);

    if(This->clientsite)
        IOleClientSite_Release(This->clientsite);

    This->clientsite = pClientSite;
    if(pClientSite)
        IOleClientSite_AddRef(pClientSite);

    return S_OK;
}

static HRESULT WINAPI OleObject_GetClientSite(IOleObject *iface, IOleClientSite **ppClientSite)
{
    struct Package *This = impl_from_IOleObject(iface);

    TRACE("(%p)->(%p)\n", This, ppClientSite);

    *ppClientSite = This->clientsite;
    if(This->clientsite)
        IOleClientSite_AddRef(This->clientsite);

    return S_OK;
}

static HRESULT WINAPI OleObject_SetHostNames(IOleObject *iface, LPCOLESTR szContainerApp, LPCOLESTR szContainerObj)
{
    struct Package *This = impl_from_IOleObject(iface);
    TRACE("(%p)->(%s, %s)\n", This, debugstr_w(szContainerApp), debugstr_w(szContainerObj));
    return S_OK;
}

static HRESULT WINAPI OleObject_Close(IOleObject *iface, DWORD dwSaveOption)
{
    struct Package *This = impl_from_IOleObject(iface);

    TRACE("(%p)->(0x%lx)\n", This, dwSaveOption);

    if(dwSaveOption == OLECLOSE_SAVEIFDIRTY ||
            dwSaveOption == OLECLOSE_PROMPTSAVE)
        WARN("Saving unsupported\n");

    return S_OK;
}

static HRESULT WINAPI OleObject_SetMoniker(IOleObject *iface, DWORD dwWhichMoniker, IMoniker *pmk)
{
    struct Package *This = impl_from_IOleObject(iface);
    FIXME("(%p)->(%ld, %p)\n", This, dwWhichMoniker, pmk);
    return E_NOTIMPL;
}

static HRESULT WINAPI OleObject_GetMoniker(IOleObject *iface, DWORD dwAssign, DWORD dwWhichMoniker, IMoniker **ppmk)
{
    struct Package *This = impl_from_IOleObject(iface);
    FIXME("(%p)->(%ld, %ld, %p)\n", This, dwAssign, dwWhichMoniker, ppmk);
    return E_NOTIMPL;
}

static HRESULT WINAPI OleObject_InitFromData(IOleObject *iface, IDataObject *pDataObject, BOOL fCreation,
                                        DWORD dwReserved)
{
    struct Package *This = impl_from_IOleObject(iface);
    FIXME("(%p)->(%p, 0x%x, %ld)\n", This, pDataObject, fCreation, dwReserved);
    return E_NOTIMPL;
}

static HRESULT WINAPI OleObject_GetClipboardData(IOleObject *iface, DWORD dwReserved, IDataObject **ppDataObject)
{
    struct Package *This = impl_from_IOleObject(iface);
    FIXME("(%p)->(%ld, %p)\n", This, dwReserved, ppDataObject);
    return E_NOTIMPL;
}

static HRESULT do_activate_object(struct Package *This, HWND parent)
{
    ShellExecuteW(parent, L"open", This->filename, NULL, NULL, SW_SHOW);
    return S_OK;
}

static HRESULT WINAPI OleObject_DoVerb(IOleObject *iface, LONG iVerb, LPMSG lpmsg, IOleClientSite *pActiveSite,
                                        LONG lindex, HWND hwndParent, LPCRECT lprcPosRect)
{
    struct Package *This = impl_from_IOleObject(iface);

    TRACE("(%p)->(%ld)\n", This, iVerb);

    switch(iVerb){
    case 0:
        return do_activate_object(This, hwndParent);
    }

    return E_INVALIDARG;
}

static HRESULT WINAPI OleObject_EnumVerbs(IOleObject *iface, IEnumOLEVERB **ppEnumOleVerb)
{
    struct Package *This = impl_from_IOleObject(iface);
    FIXME("(%p)->(%p)\n", This, ppEnumOleVerb);
    return E_NOTIMPL;
}

static HRESULT WINAPI OleObject_Update(IOleObject *iface)
{
    struct Package *This = impl_from_IOleObject(iface);
    TRACE("(%p)\n", This);
    return S_OK;
}

static HRESULT WINAPI OleObject_IsUpToDate(IOleObject *iface)
{
    struct Package *This = impl_from_IOleObject(iface);
    TRACE("(%p)\n", This);
    return S_OK;
}

static HRESULT WINAPI OleObject_GetUserClassID(IOleObject *iface, CLSID *pClsid)
{
    struct Package *This = impl_from_IOleObject(iface);
    TRACE("(%p)->(%p)\n", This, pClsid);
    *pClsid = CLSID_Package_Alt;
    return S_OK;
}

static HRESULT WINAPI OleObject_GetUserType(IOleObject *iface, DWORD dwFormOfType, LPOLESTR *pszUserType)
{
    struct Package *This = impl_from_IOleObject(iface);
    TRACE("(%p)->(%ld, %p)\n", This, dwFormOfType, pszUserType);
    return OleRegGetUserType(&CLSID_Package, dwFormOfType, pszUserType);
}

static HRESULT WINAPI OleObject_SetExtent(IOleObject *iface, DWORD dwDrawAspect, SIZEL *psizel)
{
    struct Package *This = impl_from_IOleObject(iface);
    FIXME("(%p)->(%ld, %p)\n", This, dwDrawAspect, psizel);
    return E_NOTIMPL;
}

static HRESULT WINAPI OleObject_GetExtent(IOleObject *iface, DWORD dwDrawAspect, SIZEL *psizel)
{
    struct Package *This = impl_from_IOleObject(iface);
    TRACE("(%p)->(%ld, %p)\n", This, dwDrawAspect, psizel);
    return IViewObject2_GetExtent(&This->IViewObject2_iface, dwDrawAspect, -1, NULL, psizel);
}

static HRESULT WINAPI OleObject_Advise(IOleObject *iface, IAdviseSink *pAdvSink, DWORD *pdwConnection)
{
    struct Package *This = impl_from_IOleObject(iface);
    HRESULT hr;

    TRACE("(%p)->(%p, %p)\n", This, pAdvSink, pdwConnection);

    if(!This->advise_holder && FAILED(hr = CreateOleAdviseHolder(&This->advise_holder)))
        return hr;

    return IOleAdviseHolder_Advise(This->advise_holder, pAdvSink, pdwConnection);
}

static HRESULT WINAPI OleObject_Unadvise(IOleObject *iface, DWORD dwConnection)
{
    struct Package *This = impl_from_IOleObject(iface);

    TRACE("(%p)->(%ld)\n", This, dwConnection);

    if(!This->advise_holder)
        return OLE_E_NOCONNECTION;

    return IOleAdviseHolder_Unadvise(This->advise_holder, dwConnection);
}

static HRESULT WINAPI OleObject_EnumAdvise(IOleObject *iface, IEnumSTATDATA **ppenumAdvise)
{
    struct Package *This = impl_from_IOleObject(iface);

    TRACE("(%p)->(%p)\n", This, ppenumAdvise);

    *ppenumAdvise = NULL;
    if(!This->advise_holder)
        return S_OK;

    return IOleAdviseHolder_EnumAdvise(This->advise_holder, ppenumAdvise);
}

static HRESULT WINAPI OleObject_GetMiscStatus(IOleObject *iface, DWORD dwAspect, DWORD *pdwStatus)
{
    struct Package *This = impl_from_IOleObject(iface);

    TRACE("(%p)->(%ld, %p)\n", This, dwAspect, pdwStatus);

    if(!pdwStatus)
        return E_INVALIDARG;

    *pdwStatus = OLEMISC_ONLYICONIC;

    return S_OK;
}

static HRESULT WINAPI OleObject_SetColorScheme(IOleObject *iface, LOGPALETTE *pLogpal)
{
    struct Package *This = impl_from_IOleObject(iface);
    FIXME("(%p)->(%p)\n", This, pLogpal);
    return E_NOTIMPL;
}

static const IOleObjectVtbl OleObject_Vtbl = {
    OleObject_QueryInterface,
    OleObject_AddRef,
    OleObject_Release,
    OleObject_SetClientSite,
    OleObject_GetClientSite,
    OleObject_SetHostNames,
    OleObject_Close,
    OleObject_SetMoniker,
    OleObject_GetMoniker,
    OleObject_InitFromData,
    OleObject_GetClipboardData,
    OleObject_DoVerb,
    OleObject_EnumVerbs,
    OleObject_Update,
    OleObject_IsUpToDate,
    OleObject_GetUserClassID,
    OleObject_GetUserType,
    OleObject_SetExtent,
    OleObject_GetExtent,
    OleObject_Advise,
    OleObject_Unadvise,
    OleObject_EnumAdvise,
    OleObject_GetMiscStatus,
    OleObject_SetColorScheme
};

static HRESULT WINAPI PersistStorage_QueryInterface(IPersistStorage* iface,
        REFIID riid, void **ppvObject)
{
    struct Package *This = impl_from_IPersistStorage(iface);

    return OleObject_QueryInterface(&This->IOleObject_iface, riid, ppvObject);
}

static ULONG WINAPI PersistStorage_AddRef(IPersistStorage* iface)
{
    struct Package *This = impl_from_IPersistStorage(iface);

    return OleObject_AddRef(&This->IOleObject_iface);
}

static ULONG WINAPI PersistStorage_Release(IPersistStorage* iface)
{
    struct Package *This = impl_from_IPersistStorage(iface);

    return OleObject_Release(&This->IOleObject_iface);
}

static HRESULT WINAPI PersistStorage_GetClassID(IPersistStorage* iface,
        CLSID *pClassID)
{
    struct Package *This = impl_from_IPersistStorage(iface);
    TRACE("(%p)->(%p)\n", This, pClassID);
    *pClassID = CLSID_Package_Alt;
    return S_OK;
}

static HRESULT WINAPI PersistStorage_IsDirty(IPersistStorage* iface)
{
    struct Package *This = impl_from_IPersistStorage(iface);
    TRACE("(%p)\n", This);
    return This->dirty ? S_OK : S_FALSE;
}

static HRESULT WINAPI PersistStorage_InitNew(IPersistStorage* iface,
        IStorage *pStg)
{
    struct Package *This = impl_from_IPersistStorage(iface);
    TRACE("(%p)->(%p)\n", This, pStg);
    return S_OK;
}

/* read an ANSI zero-terminated string, truncated to MAX_PATH characters */
static HRESULT read_string(struct Package *This, IStream *stream, WCHAR *str)
{
    char buf[MAX_PATH];
    ULONG nbytes, len = 0;
    HRESULT hr;
    char chr = 0;

    do{
        hr = IStream_Read(stream, &chr, 1, &nbytes);
        if(FAILED(hr) || !nbytes){
            TRACE("Unexpected end of stream or Read failed with %08lx\n", hr);
            return (hr == S_OK || hr == S_FALSE) ? E_FAIL : hr;
        }
        if(len < ARRAY_SIZE(buf) - 1)
            buf[len++] = chr;
    }while(chr);
    buf[len] = 0;

    MultiByteToWideChar(CP_ACP, 0, buf, -1, str, MAX_PATH);
    return S_OK;
}

static HRESULT WINAPI PersistStorage_Load(IPersistStorage* iface,
        IStorage *pStg)
{
    struct Package *This = impl_from_IPersistStorage(iface);
    IStream *stream;
    DWORD size, payload_size, len, stream_filename_len, filenameA_len, i, bytes_read;
    ULARGE_INTEGER payload_pos;
    LARGE_INTEGER seek;
    HRESULT hr;
    HANDLE file = INVALID_HANDLE_VALUE;
    WCHAR filenameW[MAX_PATH];
    char filenameA[MAX_PATH];
    WCHAR *stream_filename;
    WCHAR *base_end, extension[MAX_PATH];

    TRACE("(%p)->(%p)\n", This, pStg);

    hr = IStorage_OpenStream(pStg, L"\1Ole10Native", NULL,
            STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &stream);
    if(FAILED(hr)){
        TRACE("OpenStream gave: %08lx\n", hr);
        return hr;
    }

    /* size of the rest of the stream */
    hr = IStream_Read(stream, &size, 4, NULL);
    if(FAILED(hr))
        goto exit;

    /* skip two unknown bytes */
    seek.QuadPart = 2;
    hr = IStream_Seek(stream, seek, STREAM_SEEK_CUR, NULL);
    if(FAILED(hr))
        goto exit;

    hr = read_string(This, stream, This->label);
    if(FAILED(hr))
        goto exit;

    hr = read_string(This, stream, This->icon_path);
    if(FAILED(hr))
        goto exit;

    hr = IStream_Read(stream, &This->icon_index, 2, NULL);
    if(FAILED(hr))
        goto exit;

    /* skip more unknown data */
    seek.QuadPart = 2;
    hr = IStream_Seek(stream, seek, STREAM_SEEK_CUR, NULL);
    if(FAILED(hr))
        goto exit;

    /* ASCIIZ filename */
    hr = IStream_Read(stream, &filenameA_len, 4, NULL);
    if(FAILED(hr))
        goto exit;

    hr = IStream_Read(stream, filenameA, filenameA_len, NULL);
    if(FAILED(hr))
        goto exit;

    /* skip payload for now */
    hr = IStream_Read(stream, &payload_size, 4, NULL);
    if(FAILED(hr))
        goto exit;

    seek.QuadPart = 0;
    hr = IStream_Seek(stream, seek, STREAM_SEEK_CUR, &payload_pos);
    if(FAILED(hr))
        goto exit;

    seek.QuadPart = payload_size;
    hr = IStream_Seek(stream, seek, STREAM_SEEK_CUR, NULL);
    if(FAILED(hr))
        goto exit;

    /* read WCHAR filename, if present */
    hr = IStream_Read(stream, &len, 4, &bytes_read);
    if(SUCCEEDED(hr) && bytes_read == 4 && len > 0){
        hr = IStream_Read(stream, filenameW, len * sizeof(WCHAR), NULL);
        if(FAILED(hr))
            goto exit;
    }else{
        len = MultiByteToWideChar(CP_ACP, 0, filenameA, filenameA_len,
                filenameW, ARRAY_SIZE(filenameW));
    }

    stream_filename = filenameW + len - 1;
    while(stream_filename != filenameW &&
            *stream_filename != '\\')
        --stream_filename;
    if(*stream_filename == '\\')
        ++stream_filename;
    stream_filename_len = len - (stream_filename - filenameW);

    len = GetTempPathW(ARRAY_SIZE(This->filename), This->filename);
    memcpy(This->filename + len, stream_filename, stream_filename_len * sizeof(WCHAR));
    This->filename[len + stream_filename_len] = 0;

    /* read & write payload */
    memcpy(&seek, &payload_pos, sizeof(seek)); /* STREAM_SEEK_SET treats as ULARGE_INTEGER */
    hr = IStream_Seek(stream, seek, STREAM_SEEK_SET, NULL);
    if(FAILED(hr))
        goto exit;

    base_end = PathFindExtensionW(This->filename);
    lstrcpyW(extension, base_end);
    i = 1;

    file = CreateFileW(This->filename, GENERIC_WRITE, FILE_SHARE_READ, NULL,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    while(file == INVALID_HANDLE_VALUE){
        if(GetLastError() != ERROR_FILE_EXISTS){
            WARN("CreateFile failed: %lu\n", GetLastError());
            hr = E_FAIL;
            goto exit;
        }

        /* file exists, so increment file name and try again */
        ++i;
        wsprintfW(base_end, L" (%u)", i);
        lstrcatW(base_end, extension);

        file = CreateFileW(This->filename, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    TRACE("Final filename: %s\n", wine_dbgstr_w(This->filename));

    while(payload_size){
        ULONG nbytes;
        BYTE data[4096];
        DWORD written;

        hr = IStream_Read(stream, data, min(sizeof(data), payload_size), &nbytes);
        if(FAILED(hr) || nbytes == 0){
            TRACE("Unexpected end of file, or Read failed with %08lx\n", hr);
            if(hr == S_OK || hr == S_FALSE)
                hr = E_FAIL;
            goto exit;
        }

        payload_size -= nbytes;

        WriteFile(file, data, nbytes, &written, NULL);
    }

    /* keep the whole stream for Save */
    HeapFree(GetProcessHeap(), 0, This->data);
    This->data_size = size + 4;
    if(!(This->data = HeapAlloc(GetProcessHeap(), 0, This->data_size))){
        hr = E_OUTOFMEMORY;
        goto exit;
    }
    seek.QuadPart = 0;
    hr = IStream_Seek(stream, seek, STREAM_SEEK_SET, NULL);
    if(FAILED(hr))
        goto exit;
    hr = IStream_Read(stream, This->data, This->data_size, &bytes_read);
    if(SUCCEEDED(hr) && bytes_read != This->data_size)
        hr = E_FAIL;
    if(FAILED(hr))
        goto exit;

    This->dirty = FALSE;
    hr = S_OK;

exit:
    if(file != INVALID_HANDLE_VALUE){
        CloseHandle(file);
        if(FAILED(hr))
            DeleteFileW(This->filename);
    }
    IStream_Release(stream);

    TRACE("Returning: %08lx\n", hr);
    return hr;
}

static HRESULT WINAPI PersistStorage_Save(IPersistStorage* iface,
        IStorage *pStgSave, BOOL fSameAsLoad)
{
    struct Package *This = impl_from_IPersistStorage(iface);
    IStream *stream;
    HRESULT hr;

    TRACE("(%p)->(%p, %u)\n", This, pStgSave, fSameAsLoad);

    hr = WriteClassStg(pStgSave, &CLSID_Package_Alt);
    if(SUCCEEDED(hr))
        hr = WriteFmtUserTypeStg(pStgSave, 0, (LPOLESTR)L"OLE Package");
    if(FAILED(hr))
        return hr;

    hr = IStorage_CreateStream(pStgSave, L"\1Ole10Native",
            STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &stream);
    if(FAILED(hr))
        return hr;

    if(This->data_size)
        hr = IStream_Write(stream, This->data, This->data_size, NULL);
    IStream_Release(stream);
    return hr;
}

static HRESULT WINAPI PersistStorage_SaveCompleted(IPersistStorage* iface,
        IStorage *pStgNew)
{
    struct Package *This = impl_from_IPersistStorage(iface);
    TRACE("(%p)->(%p)\n", This, pStgNew);
    This->dirty = FALSE;
    return S_OK;
}

static HRESULT WINAPI PersistStorage_HandsOffStorage(IPersistStorage* iface)
{
    struct Package *This = impl_from_IPersistStorage(iface);
    TRACE("(%p)\n", This);
    return S_OK;
}

static IPersistStorageVtbl PersistStorage_Vtbl = {
    PersistStorage_QueryInterface,
    PersistStorage_AddRef,
    PersistStorage_Release,
    PersistStorage_GetClassID,
    PersistStorage_IsDirty,
    PersistStorage_InitNew,
    PersistStorage_Load,
    PersistStorage_Save,
    PersistStorage_SaveCompleted,
    PersistStorage_HandsOffStorage
};

static HRESULT WINAPI ViewObject_QueryInterface(IViewObject2 *iface, REFIID riid, void **obj)
{
    struct Package *This = impl_from_IViewObject2(iface);
    return OleObject_QueryInterface(&This->IOleObject_iface, riid, obj);
}

static ULONG WINAPI ViewObject_AddRef(IViewObject2 *iface)
{
    struct Package *This = impl_from_IViewObject2(iface);
    return OleObject_AddRef(&This->IOleObject_iface);
}

static ULONG WINAPI ViewObject_Release(IViewObject2 *iface)
{
    struct Package *This = impl_from_IViewObject2(iface);
    return OleObject_Release(&This->IOleObject_iface);
}

static HRESULT WINAPI ViewObject_Draw(IViewObject2 *iface, DWORD aspect, LONG index, void *aspect_info,
        DVTARGETDEVICE *td, HDC hdc_target, HDC hdc, const RECTL *bounds, const RECTL *win_bounds,
        BOOL (STDMETHODCALLTYPE *cont)(ULONG_PTR), ULONG_PTR cont_arg)
{
    struct Package *This = impl_from_IViewObject2(iface);
    METAFILEPICT *mfp;
    HGLOBAL hmfp;
    int state;

    TRACE("(%p)->(%ld, %ld, %p, %p, %p, %p, %s, %s, %p, %#Ix)\n", This, aspect, index, aspect_info, td,
            hdc_target, hdc, wine_dbgstr_rect((const RECT *)bounds), wine_dbgstr_rect((const RECT *)win_bounds),
            cont, cont_arg);

    if(!bounds)
        return E_INVALIDARG;

    if(!(hmfp = get_metafilepict(This)))
        return E_OUTOFMEMORY;

    mfp = GlobalLock(hmfp);
    state = SaveDC(hdc);
    SetMapMode(hdc, mfp->mm);
    SetWindowExtEx(hdc, mfp->xExt, mfp->yExt, NULL);
    SetViewportExtEx(hdc, bounds->right - bounds->left, bounds->bottom - bounds->top, NULL);
    SetViewportOrgEx(hdc, bounds->left, bounds->top, NULL);
    PlayMetaFile(hdc, mfp->hMF);
    RestoreDC(hdc, state);
    GlobalUnlock(hmfp);
    free_metafilepict(hmfp);

    return S_OK;
}

static HRESULT WINAPI ViewObject_GetColorSet(IViewObject2 *iface, DWORD aspect, LONG index, void *aspect_info,
        DVTARGETDEVICE *td, HDC hdc_target, LOGPALETTE **colors)
{
    struct Package *This = impl_from_IViewObject2(iface);
    FIXME("(%p)->(%ld, %ld, %p, %p, %p, %p)\n", This, aspect, index, aspect_info, td, hdc_target, colors);
    return E_NOTIMPL;
}

static HRESULT WINAPI ViewObject_Freeze(IViewObject2 *iface, DWORD aspect, LONG index, void *aspect_info,
        DWORD *freeze)
{
    struct Package *This = impl_from_IViewObject2(iface);
    FIXME("(%p)->(%ld, %ld, %p, %p)\n", This, aspect, index, aspect_info, freeze);
    return E_NOTIMPL;
}

static HRESULT WINAPI ViewObject_Unfreeze(IViewObject2 *iface, DWORD freeze)
{
    struct Package *This = impl_from_IViewObject2(iface);
    FIXME("(%p)->(%ld)\n", This, freeze);
    return E_NOTIMPL;
}

static HRESULT WINAPI ViewObject_SetAdvise(IViewObject2 *iface, DWORD aspects, DWORD advf, IAdviseSink *sink)
{
    struct Package *This = impl_from_IViewObject2(iface);

    TRACE("(%p)->(%ld, %ld, %p)\n", This, aspects, advf, sink);

    if(sink)
        IAdviseSink_AddRef(sink);
    if(This->view_sink)
        IAdviseSink_Release(This->view_sink);
    This->view_sink = sink;
    This->view_aspects = aspects;
    This->view_advf = advf;

    return S_OK;
}

static HRESULT WINAPI ViewObject_GetAdvise(IViewObject2 *iface, DWORD *aspects, DWORD *advf, IAdviseSink **sink)
{
    struct Package *This = impl_from_IViewObject2(iface);

    TRACE("(%p)->(%p, %p, %p)\n", This, aspects, advf, sink);

    if(aspects)
        *aspects = This->view_aspects;
    if(advf)
        *advf = This->view_advf;
    if(sink){
        *sink = This->view_sink;
        if(*sink)
            IAdviseSink_AddRef(*sink);
    }

    return S_OK;
}

static HRESULT WINAPI ViewObject_GetExtent(IViewObject2 *iface, DWORD aspect, LONG index,
        DVTARGETDEVICE *td, SIZEL *size)
{
    struct Package *This = impl_from_IViewObject2(iface);
    METAFILEPICT *mfp;
    HGLOBAL hmfp;

    TRACE("(%p)->(%ld, %ld, %p, %p)\n", This, aspect, index, td, size);

    if(!(hmfp = get_metafilepict(This)))
        return E_OUTOFMEMORY;

    mfp = GlobalLock(hmfp);
    size->cx = mfp->xExt;
    size->cy = mfp->yExt;
    GlobalUnlock(hmfp);
    free_metafilepict(hmfp);

    return S_OK;
}

static const IViewObject2Vtbl ViewObject_Vtbl = {
    ViewObject_QueryInterface,
    ViewObject_AddRef,
    ViewObject_Release,
    ViewObject_Draw,
    ViewObject_GetColorSet,
    ViewObject_Freeze,
    ViewObject_Unfreeze,
    ViewObject_SetAdvise,
    ViewObject_GetAdvise,
    ViewObject_GetExtent
};

static HRESULT WINAPI PackageCF_QueryInterface(IClassFactory *iface, REFIID riid, void **obj)
{
    TRACE("(static)->(%s, %p)\n", debugstr_guid(riid), obj);

    if(IsEqualGUID(&IID_IUnknown, riid) ||
            IsEqualGUID(&IID_IClassFactory, riid))
        *obj = iface;
    else
        *obj = NULL;

    if(*obj){
        IUnknown_AddRef((IUnknown*)*obj);
        return S_OK;
    }

    FIXME("Unknown interface: %s\n", debugstr_guid(riid));
    return E_NOINTERFACE;
}

static ULONG WINAPI PackageCF_AddRef(IClassFactory *iface)
{
    TRACE("(static)\n");
    return 2;
}

static ULONG WINAPI PackageCF_Release(IClassFactory *iface)
{
    TRACE("(static)\n");
    return 1;
}

static HRESULT WINAPI PackageCF_CreateInstance(IClassFactory *iface, IUnknown *outer,
        REFIID iid, void **obj)
{
    struct Package *package;

    TRACE("(static)->(%p, %s, %p)\n", outer, wine_dbgstr_guid(iid), obj);

    package = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*package));
    if(!package)
        return E_OUTOFMEMORY;

    package->IOleObject_iface.lpVtbl = &OleObject_Vtbl;
    package->IPersistStorage_iface.lpVtbl = &PersistStorage_Vtbl;
    package->IViewObject2_iface.lpVtbl = &ViewObject_Vtbl;
    package->dirty = TRUE;

    return IOleObject_QueryInterface(&package->IOleObject_iface, iid, obj);
}

static HRESULT WINAPI PackageCF_LockServer(IClassFactory *iface, BOOL fLock)
{
    TRACE("(%p)->(%x)\n", iface, fLock);
    return S_OK;
}

static const IClassFactoryVtbl PackageCF_Vtbl = {
    PackageCF_QueryInterface,
    PackageCF_AddRef,
    PackageCF_Release,
    PackageCF_CreateInstance,
    PackageCF_LockServer
};

static IClassFactory PackageCF = {
    &PackageCF_Vtbl
};

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **obj)
{
    TRACE("(%s, %s, %p)\n", wine_dbgstr_guid(clsid), wine_dbgstr_guid(iid), obj);

    if(IsEqualGUID(clsid, &CLSID_Package))
        return IClassFactory_QueryInterface(&PackageCF, iid, obj);

    FIXME("Unknown CLSID: %s\n", wine_dbgstr_guid(clsid));

    return CLASS_E_CLASSNOTAVAILABLE;
}
