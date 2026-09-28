/*
 * Copyright 2022 Hans Leidekker for CodeWeavers
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
#include "windef.h"
#include "winbase.h"
#include "winioctl.h"
#include "wofapi.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wofutil);

HRESULT WINAPI WofIsExternalFile( const WCHAR *path, BOOL *result, ULONG *provider, void *ptr, ULONG *length )
{
    FIXME( "%s, %p, %p, %p, %p\n", debugstr_w(path), result, provider, ptr, length );
    if (result) *result = FALSE;
    if (provider) *provider = 0;
    if (length) *length = 0;
    return S_OK;
}

BOOL WINAPI WofShouldCompressBinaries( const WCHAR *volume, ULONG *alg )
{
    FIXME( "%s, %p\n", debugstr_w(volume), alg );
    return FALSE;
}

HRESULT WINAPI WofSetFileDataLocation( HANDLE file, ULONG provider, void *info, ULONG length )
{
    struct
    {
        WOF_EXTERNAL_INFO wof;
        FILE_PROVIDER_EXTERNAL_INFO_V1 file;
    } in;
    DWORD size;

    TRACE( "%p, %lu, %p, %lu\n", file, provider, info, length );

    if (provider != WOF_PROVIDER_FILE)
    {
        FIXME( "provider %lu not supported\n", provider );
        return E_NOTIMPL;
    }
    if (!info || length < sizeof(WOF_FILE_COMPRESSION_INFO)) return E_INVALIDARG;

    in.wof.Version = WOF_CURRENT_VERSION;
    in.wof.Provider = WOF_PROVIDER_FILE;
    in.file.Version = FILE_PROVIDER_CURRENT_VERSION;
    in.file.Algorithm = ((WOF_FILE_COMPRESSION_INFO *)info)->Algorithm;
    in.file.Flags = 0;
    if (!DeviceIoControl( file, FSCTL_SET_EXTERNAL_BACKING, &in, sizeof(in), NULL, 0, &size, NULL ))
        return HRESULT_FROM_WIN32( GetLastError() );
    return S_OK;
}
