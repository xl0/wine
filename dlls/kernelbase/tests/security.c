/*
 * Copyright (C) 2023 Paul Gofman for CodeWeavers
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
#include <stdlib.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <winternl.h>
#include <winreg.h>

#include "wine/test.h"

static BOOL (WINAPI *pDeriveCapabilitySidsFromName)(const WCHAR *, PSID **, DWORD *, PSID **, DWORD *);

static HRESULT (WINAPI *pAppContainerRegisterSid)(PSID, const WCHAR *, const WCHAR *);
static HRESULT (WINAPI *pAppContainerUnregisterSid)(PSID);
static HRESULT (WINAPI *pAppContainerLookupMoniker)(PSID, WCHAR **);
static void (WINAPI *pAppContainerFreeMemory)(void *);

static NTSTATUS (WINAPI *pRtlDeriveCapabilitySidsFromName)(UNICODE_STRING *, PSID, PSID);
static BOOL (WINAPI *pCreateAppContainerToken)(HANDLE, SECURITY_CAPABILITIES *, HANDLE *);
static NTSTATUS (WINAPI *pNtCreateLowBoxToken)(HANDLE *, HANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES *, PSID, ULONG,
                                               SID_AND_ATTRIBUTES *, ULONG, HANDLE *);

static void test_DeriveCapabilitySidsFromName(void)
{
    BYTE auth_count_sid, auth_count_group_sid;
    PSID *check_group_sid, *check_sid;
    DWORD sid_count, group_sid_count;
    PSID *group_sids, *sids;
    UNICODE_STRING name_us;
    NTSTATUS status;
    DWORD size;
    BOOL bret;

    if (!pDeriveCapabilitySidsFromName)
    {
        win_skip ("DeriveCapabilitySidsFromName is not available.\n");
        return;
    }

    if (0)
    {
        /* Crashes on Windows. */
        pDeriveCapabilitySidsFromName(L"test", NULL, &group_sid_count, NULL, &sid_count);
    }

    sid_count = group_sid_count = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    bret = pDeriveCapabilitySidsFromName(L"test", &group_sids, &group_sid_count, &sids, &sid_count);
    ok(bret && GetLastError() == 0xdeadbeef, "got bret %d, err %lu.\n", bret, GetLastError());
    ok(group_sid_count == 1, "got %lu.\n", group_sid_count);
    ok(sid_count == 1, "got %lu.\n", sid_count);

    auth_count_sid = *RtlSubAuthorityCountSid(sids[0]);
    auth_count_group_sid = *RtlSubAuthorityCountSid(group_sids[0]);

    size = RtlLengthRequiredSid(auth_count_sid);
    check_sid = malloc( size );
    size = RtlLengthRequiredSid(auth_count_group_sid);
    check_group_sid = malloc( size );

    RtlInitUnicodeString(&name_us, L"test");
    status = pRtlDeriveCapabilitySidsFromName(&name_us, check_group_sid, check_sid);
    ok(!status, "failed, status %#lx.\n", status);
    ok(!memcmp(sids[0], check_sid, RtlLengthRequiredSid(auth_count_sid)), "mismatch.\n");
    ok(!memcmp(group_sids[0], check_group_sid, RtlLengthRequiredSid(auth_count_group_sid)), "mismatch.\n");

    free(check_sid);
    free(check_group_sid);

    LocalFree(group_sids[0]);
    LocalFree(group_sids);
    LocalFree(sids[0]);
    LocalFree(sids);
}

#define check_lowbox_token(a, b, c) check_lowbox_token_(__LINE__, a, b, c)
static void check_lowbox_token_(unsigned int line, HANDLE token, ACCESS_MASK access, PSID package_sid)
{
    char buffer[256];
    TOKEN_APPCONTAINER_INFORMATION *container = (TOKEN_APPCONTAINER_INFORMATION *)buffer;
    TOKEN_MANDATORY_LABEL *label = (TOKEN_MANDATORY_LABEL *)buffer;
    OBJECT_BASIC_INFORMATION info;
    TOKEN_TYPE type;
    DWORD size, value;
    NTSTATUS status;
    BOOL ret;

    status = NtQueryObject(token, ObjectBasicInformation, &info, sizeof(info), NULL);
    ok_(__FILE__, line)(!status, "got %#lx.\n", status);
    ok_(__FILE__, line)(info.GrantedAccess == access, "got access %#lx.\n", info.GrantedAccess);

    ret = GetTokenInformation(token, TokenType, &type, sizeof(type), &size);
    ok_(__FILE__, line)(ret, "got error %lu.\n", GetLastError());
    ok_(__FILE__, line)(type == TokenPrimary, "got type %u.\n", type);

    value = 0xdeadbeef;
    ret = GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &size);
    ok_(__FILE__, line)(ret, "got error %lu.\n", GetLastError());
    ok_(__FILE__, line)(value == 1, "got %lu.\n", value);

    ret = GetTokenInformation(token, TokenAppContainerSid, buffer, sizeof(buffer), &size);
    ok_(__FILE__, line)(ret, "got error %lu.\n", GetLastError());
    ok_(__FILE__, line)(container->TokenAppContainer && EqualSid(container->TokenAppContainer, package_sid),
                        "wrong app container SID.\n");

    ret = GetTokenInformation(token, TokenIntegrityLevel, buffer, sizeof(buffer), &size);
    ok_(__FILE__, line)(ret, "got error %lu.\n", GetLastError());
    ok_(__FILE__, line)(*GetSidSubAuthority(label->Label.Sid, 0) == SECURITY_MANDATORY_LOW_RID,
                        "got integrity %#lx.\n", *GetSidSubAuthority(label->Label.Sid, 0));
}

static void test_CreateAppContainerToken(void)
{
    SID_IDENTIFIER_AUTHORITY package_authority = {SECURITY_APP_PACKAGE_AUTHORITY};
    HANDLE process_token, token, query_token, impersonation_token;
    SID_AND_ATTRIBUTES capability;
    SECURITY_CAPABILITIES caps;
    static BYTE bad_revision_sid[] = {2, 2, 0, 0, 0, 0, 0, 15, 3, 0, 0, 0, 1, 0, 0, 0};
    TOKEN_APPCONTAINER_INFORMATION *container, no_container;
    PSID package_sid, capability_sid, short_capability_sid;
    NTSTATUS status;
    DWORD size;
    BOOL ret;

    if (!pCreateAppContainerToken)
    {
        win_skip("CreateAppContainerToken is not available.\n");
        return;
    }

    AllocateAndInitializeSid(&package_authority, SECURITY_APP_PACKAGE_RID_COUNT, SECURITY_APP_PACKAGE_BASE_RID,
                             1, 2, 3, 4, 5, 6, 7, &package_sid);
    AllocateAndInitializeSid(&package_authority, SECURITY_BUILTIN_CAPABILITY_RID_COUNT,
                             SECURITY_CAPABILITY_BASE_RID, 1 /* internetClient */, 0, 0, 0, 0, 0, 0,
                             &capability_sid);
    AllocateAndInitializeSid(&package_authority, 1, SECURITY_CAPABILITY_BASE_RID, 0, 0, 0, 0, 0, 0, 0,
                             &short_capability_sid);
    capability.Sid = capability_sid;
    capability.Attributes = SE_GROUP_ENABLED;

    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &process_token);
    ok(ret, "got error %lu.\n", GetLastError());

    status = pNtCreateLowBoxToken(&token, process_token, TOKEN_ALL_ACCESS, NULL, package_sid, 1, &capability, 0, NULL);
    ok(!status, "got %#lx.\n", status);
    check_lowbox_token(token, TOKEN_ALL_ACCESS, package_sid);

    status = pNtCreateLowBoxToken(&query_token, token, TOKEN_ALL_ACCESS, NULL, package_sid, 0, NULL, 0, NULL);
    ok(status == STATUS_ACCESS_DENIED, "got %#lx.\n", status);
    capability.Sid = package_sid;
    status = pNtCreateLowBoxToken(&query_token, process_token, TOKEN_ALL_ACCESS, NULL, package_sid, 1, &capability, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "got %#lx.\n", status);
    capability.Sid = short_capability_sid;
    status = pNtCreateLowBoxToken(&query_token, process_token, TOKEN_ALL_ACCESS, NULL, package_sid, 1, &capability, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "got %#lx.\n", status);
    capability.Sid = bad_revision_sid;
    status = pNtCreateLowBoxToken(&query_token, process_token, TOKEN_ALL_ACCESS, NULL, package_sid, 1, &capability, 0, NULL);
    ok(status == STATUS_INVALID_SID, "got %#lx.\n", status);
    capability.Sid = NULL;
    status = pNtCreateLowBoxToken(&query_token, process_token, TOKEN_ALL_ACCESS, NULL, package_sid, 1, &capability, 0, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "got %#lx.\n", status);
    capability.Sid = capability_sid;
    status = pNtCreateLowBoxToken(&query_token, process_token, TOKEN_ALL_ACCESS, NULL, package_sid, 1, NULL, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER_MIX, "got %#lx.\n", status);

    /* size queries */
    ret = GetTokenInformation(token, TokenAppContainerSid, NULL, 0, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got ret %d, error %lu.\n", ret, GetLastError());
    ok(size == sizeof(TOKEN_APPCONTAINER_INFORMATION) + GetLengthSid(package_sid), "got size %lu.\n", size);
    container = malloc(size);
    ret = GetTokenInformation(token, TokenAppContainerSid, container, size - 1, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got ret %d, error %lu.\n", ret, GetLastError());
    ret = GetTokenInformation(token, TokenAppContainerSid, container, size, &size);
    ok(ret, "got error %lu.\n", GetLastError());
    ok(container->TokenAppContainer && EqualSid(container->TokenAppContainer, package_sid), "wrong SID.\n");
    free(container);
    ret = GetTokenInformation(process_token, TokenAppContainerSid, NULL, 0, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got ret %d, error %lu.\n", ret, GetLastError());
    ok(size == sizeof(TOKEN_APPCONTAINER_INFORMATION), "got size %lu.\n", size);
    ret = GetTokenInformation(process_token, TokenAppContainerSid, &no_container, sizeof(no_container), &size);
    ok(ret, "got error %lu.\n", GetLastError());
    ok(!no_container.TokenAppContainer, "got %p.\n", no_container.TokenAppContainer);
    CloseHandle(token);

    /* access 0 means the access of the source handle */
    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &query_token);
    ok(ret, "got error %lu.\n", GetLastError());
    status = pNtCreateLowBoxToken(&token, query_token, 0, NULL, package_sid, 0, NULL, 0, NULL);
    ok(!status, "got %#lx.\n", status);
    check_lowbox_token(token, TOKEN_DUPLICATE | TOKEN_QUERY, package_sid);
    CloseHandle(token);
    CloseHandle(query_token);

    status = pNtCreateLowBoxToken(&query_token, process_token, TOKEN_QUERY, NULL, package_sid, 0, NULL, 0, NULL);
    ok(!status, "got %#lx.\n", status);
    check_lowbox_token(query_token, TOKEN_QUERY, package_sid);

    status = pNtCreateLowBoxToken(&token, query_token, TOKEN_QUERY, NULL, package_sid, 0, NULL, 0, NULL);
    ok(status == STATUS_ACCESS_DENIED, "got %#lx.\n", status);
    CloseHandle(query_token);

    status = pNtCreateLowBoxToken(&token, process_token, TOKEN_ALL_ACCESS, NULL, NULL, 0, NULL, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "got %#lx.\n", status);
    status = pNtCreateLowBoxToken(&token, process_token, TOKEN_ALL_ACCESS, NULL, capability_sid, 0, NULL, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "got %#lx.\n", status);

    ret = DuplicateTokenEx(process_token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation,
                           &impersonation_token);
    ok(ret, "got error %lu.\n", GetLastError());
    status = pNtCreateLowBoxToken(&token, impersonation_token, TOKEN_ALL_ACCESS, NULL, package_sid, 0, NULL, 0, NULL);
    ok(!status, "got %#lx.\n", status);
    check_lowbox_token(token, TOKEN_ALL_ACCESS, package_sid);
    CloseHandle(token);
    CloseHandle(impersonation_token);

    caps.AppContainerSid = package_sid;
    caps.Capabilities = &capability;
    caps.CapabilityCount = 1;
    caps.Reserved = 0;

    SetLastError(0xdeadbeef);
    ret = pCreateAppContainerToken(process_token, &caps, &token);
    ok(ret && GetLastError() == 0xdeadbeef, "got ret %d, error %lu.\n", ret, GetLastError());
    check_lowbox_token(token, TOKEN_ALL_ACCESS, package_sid);
    CloseHandle(token);

    SetLastError(0xdeadbeef);
    ret = pCreateAppContainerToken(NULL, &caps, &token);
    ok(ret && GetLastError() == 0xdeadbeef, "got ret %d, error %lu.\n", ret, GetLastError());
    check_lowbox_token(token, TOKEN_ALL_ACCESS, package_sid);
    CloseHandle(token);

    caps.AppContainerSid = capability_sid;
    SetLastError(0xdeadbeef);
    ret = pCreateAppContainerToken(process_token, &caps, &token);
    ok(!ret, "got ret %d.\n", ret);
    todo_wine ok(GetLastError() == ERROR_NOT_APPCONTAINER, "got error %lu.\n", GetLastError());

    CloseHandle(process_token);
    FreeSid(package_sid);
    FreeSid(capability_sid);
    FreeSid(short_capability_sid);
}

static void test_AppContainerRegisterSid(void)
{
    static const WCHAR mappings[] = L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows"
                                    L"\\CurrentVersion\\AppContainer\\Mappings\\"
                                    L"S-1-15-2-1-2-3-4-5-6-2166136261";
    SID_IDENTIFIER_AUTHORITY app_authority = {SECURITY_APP_PACKAGE_AUTHORITY}, nt_authority = {SECURITY_NT_AUTHORITY};
    PSID sid, system_sid;
    WCHAR *moniker, buffer[64];
    DWORD size;
    HRESULT hr;
    LSTATUS ret;
    HKEY key;

    if (!pAppContainerRegisterSid)
    {
        win_skip("AppContainerRegisterSid is not available.\n");
        return;
    }

    AllocateAndInitializeSid(&app_authority, SECURITY_APP_PACKAGE_RID_COUNT, SECURITY_APP_PACKAGE_BASE_RID,
                             1, 2, 3, 4, 5, 6, 2166136261, &sid);
    AllocateAndInitializeSid(&nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid);
    pAppContainerUnregisterSid(sid);

    moniker = (WCHAR *)0xdeadbeef;
    hr = pAppContainerLookupMoniker(sid, &moniker);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "got %#lx.\n", hr);
    ok(moniker == (WCHAR *)0xdeadbeef, "got %p.\n", moniker);

    hr = pAppContainerRegisterSid(sid, L"Wine.Test.Moniker", L"display");
    ok(hr == S_OK, "got %#lx.\n", hr);

    ret = RegOpenKeyExW(HKEY_CURRENT_USER, mappings, 0, KEY_READ, &key);
    ok(!ret, "got %ld.\n", ret);
    size = sizeof(buffer);
    ret = RegGetValueW(key, NULL, L"Moniker", RRF_RT_REG_SZ, NULL, buffer, &size);
    ok(!ret && !wcscmp(buffer, L"Wine.Test.Moniker"), "got %ld, %s.\n", ret, debugstr_w(buffer));
    size = sizeof(buffer);
    ret = RegGetValueW(key, NULL, L"DisplayName", RRF_RT_REG_SZ, NULL, buffer, &size);
    ok(!ret && !wcscmp(buffer, L"display"), "got %ld, %s.\n", ret, debugstr_w(buffer));
    RegCloseKey(key);

    hr = pAppContainerLookupMoniker(sid, &moniker);
    ok(hr == S_OK, "got %#lx.\n", hr);
    ok(!wcscmp(moniker, L"Wine.Test.Moniker"), "got %s.\n", debugstr_w(moniker));
    pAppContainerFreeMemory(moniker);

    /* The display name of an existing mapping is updated, the moniker is not. */
    hr = pAppContainerRegisterSid(sid, L"other", L"display2");
    ok(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "got %#lx.\n", hr);
    size = sizeof(buffer);
    ret = RegGetValueW(HKEY_CURRENT_USER, mappings, L"DisplayName", RRF_RT_REG_SZ, NULL, buffer, &size);
    ok(!ret && !wcscmp(buffer, L"display2"), "got %ld, %s.\n", ret, debugstr_w(buffer));
    hr = pAppContainerLookupMoniker(sid, &moniker);
    ok(hr == S_OK, "got %#lx.\n", hr);
    ok(!wcscmp(moniker, L"Wine.Test.Moniker"), "got %s.\n", debugstr_w(moniker));
    pAppContainerFreeMemory(moniker);

    hr = pAppContainerUnregisterSid(sid);
    ok(hr == S_OK, "got %#lx.\n", hr);
    ret = RegOpenKeyExW(HKEY_CURRENT_USER, mappings, 0, KEY_READ, &key);
    ok(ret == ERROR_FILE_NOT_FOUND, "got %ld.\n", ret);
    hr = pAppContainerUnregisterSid(sid);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "got %#lx.\n", hr);
    hr = pAppContainerLookupMoniker(sid, &moniker);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "got %#lx.\n", hr);

    hr = pAppContainerLookupMoniker(system_sid, &moniker);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_APPCONTAINER), "got %#lx.\n", hr);

    hr = pAppContainerRegisterSid(NULL, L"a", L"a");
    ok(hr == E_INVALIDARG, "got %#lx.\n", hr);
    hr = pAppContainerRegisterSid(sid, NULL, L"a");
    ok(hr == E_INVALIDARG, "got %#lx.\n", hr);
    hr = pAppContainerRegisterSid(sid, L"", L"a");
    ok(hr == E_INVALIDARG, "got %#lx.\n", hr);
    hr = pAppContainerRegisterSid(sid, L"a", NULL);
    ok(hr == E_INVALIDARG, "got %#lx.\n", hr);
    hr = pAppContainerUnregisterSid(NULL);
    ok(hr == E_INVALIDARG, "got %#lx.\n", hr);
    hr = pAppContainerLookupMoniker(NULL, &moniker);
    ok(hr == E_INVALIDARG, "got %#lx.\n", hr);

    FreeSid(sid);
    FreeSid(system_sid);
}

START_TEST(security)
{
    HMODULE hmod;

    hmod = LoadLibraryA("kernelbase.dll");
    pDeriveCapabilitySidsFromName = (void *)GetProcAddress(hmod, "DeriveCapabilitySidsFromName");
    pCreateAppContainerToken = (void *)GetProcAddress(hmod, "CreateAppContainerToken");
    pAppContainerRegisterSid = (void *)GetProcAddress(hmod, "AppContainerRegisterSid");
    pAppContainerUnregisterSid = (void *)GetProcAddress(hmod, "AppContainerUnregisterSid");
    pAppContainerLookupMoniker = (void *)GetProcAddress(hmod, "AppContainerLookupMoniker");
    pAppContainerFreeMemory = (void *)GetProcAddress(hmod, "AppContainerFreeMemory");

    hmod = LoadLibraryA("ntdll.dll");
    pRtlDeriveCapabilitySidsFromName = (void *)GetProcAddress(hmod, "RtlDeriveCapabilitySidsFromName");
    pNtCreateLowBoxToken = (void *)GetProcAddress(hmod, "NtCreateLowBoxToken");

    test_DeriveCapabilitySidsFromName();
    test_CreateAppContainerToken();
    test_AppContainerRegisterSid();
}
