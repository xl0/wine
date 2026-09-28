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

#define WOF_CURRENT_VERSION 1
#define WOF_PROVIDER_WIM 1
#define WOF_PROVIDER_FILE 2

typedef struct _WOF_EXTERNAL_INFO
{
    ULONG Version;
    ULONG Provider;
} WOF_EXTERNAL_INFO, *PWOF_EXTERNAL_INFO;

#define FILE_PROVIDER_CURRENT_VERSION 1

#define FILE_PROVIDER_COMPRESSION_XPRESS4K 0
#define FILE_PROVIDER_COMPRESSION_LZX 1
#define FILE_PROVIDER_COMPRESSION_XPRESS8K 2
#define FILE_PROVIDER_COMPRESSION_XPRESS16K 3

typedef struct _FILE_PROVIDER_EXTERNAL_INFO_V1
{
    ULONG Version;
    ULONG Algorithm;
    ULONG Flags;
} FILE_PROVIDER_EXTERNAL_INFO_V1, *PFILE_PROVIDER_EXTERNAL_INFO_V1;

typedef struct _WOF_FILE_COMPRESSION_INFO_V0
{
    ULONG Algorithm;
} WOF_FILE_COMPRESSION_INFO_V0, *PWOF_FILE_COMPRESSION_INFO_V0;

typedef WOF_FILE_COMPRESSION_INFO_V0 WOF_FILE_COMPRESSION_INFO, *PWOF_FILE_COMPRESSION_INFO;

typedef struct _WOF_FILE_COMPRESSION_INFO_V1
{
    ULONG Algorithm;
    ULONG Flags;
} WOF_FILE_COMPRESSION_INFO_V1, *PWOF_FILE_COMPRESSION_INFO_V1;

BOOL WINAPI WofShouldCompressBinaries(const WCHAR *, ULONG *);
HRESULT WINAPI WofSetFileDataLocation(HANDLE, ULONG, void *, ULONG);
