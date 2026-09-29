/*
 * Windows hook functions
 *
 * Copyright 2002 Alexandre Julliard
 * Copyright 2005 Dmitry Timoshkov
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

#if 0
#pragma makedep unix
#endif

#include <assert.h>
#include "ntstatus.h"
#include "win32u_private.h"
#include "ntuser_private.h"
#include "wine/server.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(hook);

static const char * const hook_names[NB_HOOKS] =
{
    "WH_MSGFILTER",
    "WH_JOURNALRECORD",
    "WH_JOURNALPLAYBACK",
    "WH_KEYBOARD",
    "WH_GETMESSAGE",
    "WH_CALLWNDPROC",
    "WH_CBT",
    "WH_SYSMSGFILTER",
    "WH_MOUSE",
    "WH_HARDWARE",
    "WH_DEBUG",
    "WH_SHELL",
    "WH_FOREGROUNDIDLE",
    "WH_CALLWNDPROCRET",
    "WH_KEYBOARD_LL",
    "WH_MOUSE_LL",
    "WH_WINEVENT"
};

static const char *debugstr_hook_id( unsigned int id )
{
    if (id - WH_MINHOOK >= ARRAYSIZE(hook_names)) return wine_dbg_sprintf( "%u", id );
    return hook_names[id - WH_MINHOOK];
}

BOOL is_hooked( INT id )
{
    struct object_lock lock = OBJECT_LOCK_INIT;
    const queue_shm_t *queue_shm;
    BOOL ret = TRUE;
    UINT status;

    while ((status = get_shared_queue( &lock, &queue_shm )) == STATUS_PENDING)
        ret = queue_shm->hooks_count[id - WH_MINHOOK] > 0;

    if (status) return TRUE;
    return ret;
}

/* snapshot of the hooks of one chain that run in the current thread, valid as long as the
 * hooks_serial of the thread's queue doesn't change */
struct hook_chain
{
    UINT64 serial;        /* hooks_serial the snapshot was taken at */
    UINT   refs;          /* the thread's cache and each running chain hold a reference */
    INT    id;            /* hook id */
    UINT   count;
    struct
    {
        HHOOK  handle;
        void  *proc;
        BOOL   unicode;
        WCHAR *module;
    } hooks[];
};

static BOOL get_hooks_serial( UINT64 *serial )
{
    struct object_lock lock = OBJECT_LOCK_INIT;
    const queue_shm_t *queue_shm;
    UINT status;

    *serial = 0;
    while ((status = get_shared_queue( &lock, &queue_shm )) == STATUS_PENDING)
        *serial = queue_shm->hooks_serial;

    return !status;
}

static void release_hook_chain( struct hook_chain *chain )
{
    if (!--chain->refs) free( chain );
}

/* get the hooks of a chain, from the thread's cache if the hooks didn't change since */
static struct hook_chain *get_hook_chain( INT id )
{
    struct user_thread_info *thread_info = get_user_thread_info();
    struct hook_chain *chain, **cache = &thread_info->hook_chains[id - WH_MINHOOK];
    const struct hook_chain_entry *entry;
    UINT64 stack_buffer[512], *buffer = stack_buffer, serial;
    UINT count = 0, size, total = sizeof(stack_buffer), pos, len;
    WCHAR *module;
    NTSTATUS status;

    if (id == WH_KEYBOARD_LL || id == WH_MOUSE_LL) return NULL;
    if (!get_hooks_serial( &serial )) return NULL;

    if (!(chain = *cache) || chain->serial != serial)
    {
        for (;;)
        {
            SERVER_START_REQ( get_hook_chain )
            {
                req->id = id;
                wine_server_set_reply( req, buffer, total );
                status = wine_server_call( req );
                size = wine_server_reply_size( reply );
                total = reply->total;
            }
            SERVER_END_REQ;
            if (status != STATUS_BUFFER_TOO_SMALL) break;
            if (buffer != stack_buffer) free( buffer );
            if (!(buffer = malloc( total ))) return NULL;
        }
        if (status)
        {
            if (buffer != stack_buffer) free( buffer );
            return NULL;
        }

        for (pos = len = 0; pos < size; pos += sizeof(*entry) + ((entry->module_size + 7) & ~7))
        {
            entry = (const struct hook_chain_entry *)((char *)buffer + pos);
            len += entry->module_size + sizeof(WCHAR);
            count++;
        }
        if (!(chain = malloc( offsetof( struct hook_chain, hooks[count] ) + len )))
        {
            if (buffer != stack_buffer) free( buffer );
            return NULL;
        }
        chain->serial = serial;
        chain->refs = 1;
        chain->id = id;
        chain->count = count;
        module = (WCHAR *)&chain->hooks[count];
        for (pos = count = 0; pos < size; pos += sizeof(*entry) + ((entry->module_size + 7) & ~7), count++)
        {
            entry = (const struct hook_chain_entry *)((char *)buffer + pos);
            chain->hooks[count].handle  = wine_server_ptr_handle( entry->handle );
            chain->hooks[count].proc    = wine_server_get_ptr( entry->proc );
            chain->hooks[count].unicode = entry->unicode;
            chain->hooks[count].module  = module;
            memcpy( module, entry + 1, entry->module_size );
            module += entry->module_size / sizeof(WCHAR);
            *module++ = 0;
        }
        if (buffer != stack_buffer) free( buffer );
        if (*cache) release_hook_chain( *cache );
        *cache = chain;
    }

    chain->refs++;
    return chain;
}

/***********************************************************************
 *           NtUserSetWindowsHookEx   (win32u.@)
 */
HHOOK WINAPI NtUserSetWindowsHookEx( HINSTANCE inst, UNICODE_STRING *module, DWORD tid, INT id,
                                     HOOKPROC proc, BOOL ansi )
{
    HHOOK handle = 0;

    if (!proc)
    {
        RtlSetLastWin32Error( ERROR_INVALID_FILTER_PROC );
        return 0;
    }

    if (tid)  /* thread-local hook */
    {
        if (id == WH_JOURNALRECORD ||
            id == WH_JOURNALPLAYBACK ||
            id == WH_KEYBOARD_LL ||
            id == WH_MOUSE_LL ||
            id == WH_SYSMSGFILTER)
        {
            /* these can only be global */
            RtlSetLastWin32Error( ERROR_GLOBAL_ONLY_HOOK );
            return 0;
        }
    }
    else  /* system-global hook */
    {
        if (id == WH_JOURNALRECORD || id == WH_JOURNALPLAYBACK)
        {
            RtlSetLastWin32Error( ERROR_ACCESS_DENIED );
            return 0;
        }
        if (id == WH_KEYBOARD_LL || id == WH_MOUSE_LL) inst = 0;
        else if (!inst)
        {
            RtlSetLastWin32Error( ERROR_HOOK_NEEDS_HMOD );
            return 0;
        }
    }

    SERVER_START_REQ( set_hook )
    {
        req->id        = id;
        req->pid       = 0;
        req->tid       = tid;
        req->event_min = EVENT_MIN;
        req->event_max = EVENT_MAX;
        req->flags     = WINEVENT_INCONTEXT;
        req->unicode   = !ansi;
        if (inst) /* make proc relative to the module base */
        {
            req->proc = wine_server_client_ptr( (void *)((char *)proc - (char *)inst) );
            wine_server_add_data( req, module->Buffer, module->Length );
        }
        else req->proc = wine_server_client_ptr( proc );

        if (!wine_server_call_err( req ))
        {
            handle = wine_server_ptr_handle( reply->handle );
        }
    }
    SERVER_END_REQ;

    TRACE( "%s %p %x -> %p\n", debugstr_hook_id(id), proc, tid, handle );
    return handle;
}

/***********************************************************************
 *	     NtUserUnhookWindowsHookEx   (win32u.@)
 */
BOOL WINAPI NtUserUnhookWindowsHookEx( HHOOK handle )
{
    NTSTATUS status;

    SERVER_START_REQ( remove_hook )
    {
        req->handle = wine_server_user_handle( handle );
        req->id     = 0;
        status = wine_server_call_err( req );
    }
    SERVER_END_REQ;
    if (status == STATUS_INVALID_HANDLE) RtlSetLastWin32Error( ERROR_INVALID_HOOK_HANDLE );
    return !status;
}

/***********************************************************************
 *	     NtUserUnhookWindowsHook   (win32u.@)
 */
BOOL WINAPI NtUserUnhookWindowsHook( INT id, HOOKPROC proc )
{
    NTSTATUS status;

    TRACE( "%s %p\n", debugstr_hook_id(id), proc );

    SERVER_START_REQ( remove_hook )
    {
        req->handle = 0;
        req->id   = id;
        req->proc = wine_server_client_ptr( proc );
        status = wine_server_call_err( req );
    }
    SERVER_END_REQ;
    if (status == STATUS_INVALID_HANDLE) RtlSetLastWin32Error( ERROR_INVALID_HOOK_HANDLE );
    return !status;
}

/***********************************************************************
 *           NtUserCallMsgFilter (win32u.@)
 */
BOOL WINAPI NtUserCallMsgFilter( MSG *msg, INT code )
{
    /* FIXME: We should use NtCallbackReturn instead of passing (potentially kernel) pointer
     * like that, but we need to consequently use syscall thunks first for that to work. */
    if (call_hooks( WH_SYSMSGFILTER, code, 0, (LPARAM)msg, sizeof(*msg) )) return TRUE;
    return call_hooks( WH_MSGFILTER, code, 0, (LPARAM)msg, sizeof(*msg) );
}

static UINT get_ll_hook_timeout(void)
{
    /* FIXME: should retrieve LowLevelHooksTimeout in HKEY_CURRENT_USER\Control Panel\Desktop */
    return 2000;
}

/***********************************************************************
 *	     call_hook
 *
 * Call hook either in current thread or send message to the destination
 * thread.
 */
static LRESULT call_hook( struct win_hook_params *info, const WCHAR *module, size_t lparam_size,
                          size_t message_size, BOOL ansi, struct hook_chain *chain, UINT index )
{
    DWORD_PTR ret = 0;

    if (info->tid)
    {
        struct hook_extra_info h_extra;
        h_extra.handle = info->handle;
        h_extra.lparam = info->lparam;

        TRACE( "calling hook in thread %04x %s code %x wp %lx lp %lx\n",
               info->tid, hook_names[info->id-WH_MINHOOK],
               info->code, (long)info->wparam, info->lparam );

        switch(info->id)
        {
        case WH_KEYBOARD_LL:
            send_internal_message_timeout( info->pid, info->tid, WM_WINE_KEYBOARD_LL_HOOK,
                                           info->wparam, (LPARAM)&h_extra, SMTO_ABORTIFHUNG,
                                           get_ll_hook_timeout(), &ret );
            break;
        case WH_MOUSE_LL:
            send_internal_message_timeout( info->pid, info->tid, WM_WINE_MOUSE_LL_HOOK,
                                           info->wparam, (LPARAM)&h_extra, SMTO_ABORTIFHUNG,
                                           get_ll_hook_timeout(), &ret );
            break;
        default:
            ERR("Unknown hook id %d\n", info->id);
            assert(0);
            break;
        }
    }
    else if (info->proc)
    {
        struct user_thread_info *thread_info = get_user_thread_info();
        size_t size, lparam_offset = 0, message_offset = 0;
        size_t lparam_ret_size = lparam_size;
        HHOOK prev = thread_info->hook;
        BOOL prev_unicode = thread_info->hook_unicode;
        struct hook_chain *prev_chain = thread_info->hook_chain;
        UINT prev_index = thread_info->hook_index;
        struct win_hook_params *params = info;
        void *ret_ptr, *extra_buffer = NULL;
        SIZE_T extra_buffer_size = 0;
        size_t reply_size;
        ULONG ret_len;

        size = FIELD_OFFSET( struct win_hook_params, module[module ? lstrlenW( module ) + 1 : 1] );

        if (lparam_size)
        {
            if (params->id == WH_CBT && params->code == HCBT_CREATEWND)
            {
                CBT_CREATEWNDW *cbtc = (CBT_CREATEWNDW *)params->lparam;
                message_size = user_message_size( (HWND)params->wparam, WM_NCCREATE,
                                                  0, (LPARAM)cbtc->lpcs, TRUE, FALSE, &reply_size );
                lparam_size = lparam_ret_size = 0;
            }

            if (lparam_size)
            {
                lparam_offset = (size + 15) & ~15; /* align offset */
                size = lparam_offset + lparam_size;
            }

            if (message_size)
            {
                message_offset = (size + 15) & ~15; /* align offset */
                size = message_offset + message_size;
            }
        }

        if (size > sizeof(*info))
        {
            if (!(params = malloc( size ))) return 0;
            memcpy( params, info, FIELD_OFFSET( struct win_hook_params, module ));
        }
        if (module)
            wcscpy( params->module, module );
        else
            params->module[0] = 0;

        if (lparam_size)
            memcpy( (char *)params + lparam_offset, (const void *)params->lparam, lparam_size );

        if (message_size)
        {
            switch (params->id)
            {
            case WH_CBT:
                {
                    CBT_CREATEWNDW *cbtc = (CBT_CREATEWNDW *)params->lparam;
                    LPARAM lp = (LPARAM)cbtc->lpcs;
                    pack_user_message( (char *)params + message_offset, message_size,
                                       WM_CREATE, 0, lp, FALSE, &extra_buffer );
                }
                break;
            case WH_CALLWNDPROC:
                {
                    CWPSTRUCT *cwp = (CWPSTRUCT *)((char *)params + lparam_offset);
                    pack_user_message( (char *)params + message_offset, message_size,
                                       cwp->message, cwp->wParam, cwp->lParam, ansi, &extra_buffer );
                }
                break;
            case WH_CALLWNDPROCRET:
                {
                    CWPRETSTRUCT *cwpret = (CWPRETSTRUCT *)((char *)params + lparam_offset);
                    pack_user_message( (char *)params + message_offset, message_size,
                                       cwpret->message, cwpret->wParam, cwpret->lParam, ansi, &extra_buffer );
                }
                break;
            }
        }

        /*
         * Windows protects from stack overflow in recursive hook calls. Different Windows
         * allow different depths.
         */
        if (thread_info->hook_call_depth >= 25)
        {
            WARN("Too many hooks called recursively, skipping call.\n");
            if (params != info) free( params );
            if (extra_buffer)
                NtFreeVirtualMemory( GetCurrentProcess(), &extra_buffer, &extra_buffer_size, MEM_RELEASE );
            return 0;
        }

        TRACE( "calling hook %p %s code %x wp %lx lp %lx module %s\n",
               params->proc, hook_names[params->id-WH_MINHOOK], params->code, (long)params->wparam,
               params->lparam, debugstr_w(module) );

        thread_info->hook = params->handle;
        thread_info->hook_unicode = params->next_unicode;
        thread_info->hook_chain = chain;
        thread_info->hook_index = index;
        thread_info->hook_call_depth++;
        if (!KeUserModeCallback( NtUserCallWindowsHook, params, size, &ret_ptr, &ret_len ) &&
            ret_len >= sizeof(ret))
        {
            LRESULT *result_ptr = ret_ptr;
            ret = *result_ptr;
            if (ret_len == sizeof(ret) + lparam_ret_size)
                memcpy( (void *)params->lparam, result_ptr + 1, ret_len - sizeof(ret) );
        }
        thread_info->hook = prev;
        thread_info->hook_unicode = prev_unicode;
        thread_info->hook_chain = prev_chain;
        thread_info->hook_index = prev_index;
        thread_info->hook_call_depth--;

        if (params != info) free( params );
        if (extra_buffer)
            NtFreeVirtualMemory( GetCurrentProcess(), &extra_buffer, &extra_buffer_size, MEM_RELEASE );
    }

    return ret;
}

static NTSTATUS query_hook( HHOOK handle, BOOL next, struct win_hook_params *info, WCHAR *module )
{
    NTSTATUS status;

    SERVER_START_REQ( get_hook_info )
    {
        req->handle = wine_server_user_handle( handle );
        req->get_next = next;
        req->event = EVENT_MIN;
        wine_server_set_reply( req, module, (MAX_PATH - 1) * sizeof(WCHAR) );
        if (!(status = wine_server_call( req )))
        {
            module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info->handle       = wine_server_ptr_handle( reply->handle );
            info->id           = reply->id;
            info->pid          = reply->pid;
            info->tid          = reply->tid;
            info->proc         = wine_server_get_ptr( reply->proc );
            info->next_unicode = reply->unicode;
        }
    }
    SERVER_END_REQ;
    return status;
}

static LRESULT call_chain_hook( struct hook_chain *chain, UINT index, INT code, WPARAM wparam, LPARAM lparam,
                                BOOL prev_unicode, size_t lparam_size, size_t message_size, BOOL ansi )
{
    struct win_hook_params info;

    memset( &info, 0, sizeof(info) );
    info.handle       = chain->hooks[index].handle;
    info.id           = chain->id;
    info.proc         = chain->hooks[index].proc;
    info.next_unicode = chain->hooks[index].unicode;
    info.prev_unicode = prev_unicode;
    info.code         = code;
    info.wparam       = wparam;
    info.lparam       = lparam;
    return call_hook( &info, chain->hooks[index].module, lparam_size, message_size, ansi, chain, index );
}

/***********************************************************************
 *	     NtUserCallNextHookEx (win32u.@)
 */
LRESULT WINAPI NtUserCallNextHookEx( HHOOK hhook, INT code, WPARAM wparam, LPARAM lparam )
{
    struct user_thread_info *thread_info = get_user_thread_info();
    struct hook_chain *chain = thread_info->hook_chain;
    UINT index = thread_info->hook_index + 1;
    struct win_hook_params info;
    WCHAR module[MAX_PATH];
    NTSTATUS status;
    UINT64 serial;

    if (chain && get_hooks_serial( &serial ) && serial == chain->serial)
    {
        if (index >= chain->count) return 0;
        return call_chain_hook( chain, index, code, wparam, lparam, thread_info->hook_unicode, 0, 0, FALSE );
    }

    memset( &info, 0, sizeof(info) );

    /* The hooks changed since the snapshot: go on with the snapshot hooks that still exist.
     * Hooks added meanwhile aren't part of the running chain, like on Windows. */
    if (chain)
    {
        for (; index < chain->count; index++)
        {
            if (query_hook( chain->hooks[index].handle, FALSE, &info, module ) || !info.proc) continue;
            return call_chain_hook( chain, index, code, wparam, lparam, thread_info->hook_unicode, 0, 0, FALSE );
        }
        return 0;
    }

    if ((status = query_hook( thread_info->hook, TRUE, &info, module )))
        RtlSetLastWin32Error( RtlNtStatusToDosError( status ));

    info.code   = code;
    info.wparam = wparam;
    info.lparam = lparam;
    info.prev_unicode = thread_info->hook_unicode;
    return call_hook( &info, module, 0, 0, FALSE, NULL, 0 );
}

LRESULT call_current_hook( HHOOK hhook, INT code, WPARAM wparam, LPARAM lparam )
{
    struct win_hook_params info;
    WCHAR module[MAX_PATH];

    memset( &info, 0, sizeof(info) );

    SERVER_START_REQ( get_hook_info )
    {
        req->handle = wine_server_user_handle( hhook );
        req->get_next = 0;
        req->event = EVENT_MIN;
        wine_server_set_reply( req, module, sizeof(module) );
        if (!wine_server_call_err( req ))
        {
            module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info.handle       = wine_server_ptr_handle( reply->handle );
            info.id           = reply->id;
            info.pid          = reply->pid;
            info.tid          = reply->tid;
            info.proc         = wine_server_get_ptr( reply->proc );
            info.next_unicode = reply->unicode;
        }
    }
    SERVER_END_REQ;

    info.code   = code;
    info.wparam = wparam;
    info.lparam = lparam;
    info.prev_unicode = TRUE;  /* assume Unicode for this function */
    return call_hook( &info, module, 0, 0, FALSE, NULL, 0 );
}

LRESULT call_message_hooks( INT id, INT code, WPARAM wparam, LPARAM lparam, size_t lparam_size,
                            size_t message_size, BOOL ansi )
{
    struct win_hook_params info;
    struct hook_chain *chain;
    WCHAR module[MAX_PATH];
    DWORD_PTR ret;

    user_check_not_lock();

    if (!is_hooked( id ))
    {
        TRACE( "skipping hook %s\n", hook_names[id - WH_MINHOOK] );
        return 0;
    }

    /* no server round trips while the hooks don't change */
    if ((chain = get_hook_chain( id )))
    {
        ret = chain->count ? call_chain_hook( chain, 0, code, wparam, lparam, TRUE, lparam_size, message_size, ansi ) : 0;
        release_hook_chain( chain );
        return ret;
    }

    memset( &info, 0, sizeof(info) );
    info.prev_unicode = TRUE;
    info.id = id;

    SERVER_START_REQ( start_hook_chain )
    {
        req->id = info.id;
        req->event = EVENT_MIN;
        wine_server_set_reply( req, module, sizeof(module)-sizeof(WCHAR) );
        if (!wine_server_call( req ))
        {
            module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info.handle       = wine_server_ptr_handle( reply->handle );
            info.pid          = reply->pid;
            info.tid          = reply->tid;
            info.proc         = wine_server_get_ptr( reply->proc );
            info.next_unicode = reply->unicode;
        }
    }
    SERVER_END_REQ;
    if (!info.tid && !info.proc) return 0;

    info.code   = code;
    info.wparam = wparam;
    info.lparam = lparam;
    ret = call_hook( &info, module, lparam_size, message_size, ansi, NULL, 0 );

    SERVER_START_REQ( finish_hook_chain )
    {
        req->id = id;
        wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}

LRESULT call_hooks( INT id, INT code, WPARAM wparam, LPARAM lparam, size_t lparam_size )
{
    return call_message_hooks( id, code, wparam, lparam, lparam_size, 0, FALSE );
}

/***********************************************************************
 *           NtUserSetWinEventHook   (win32u.@)
 */
HWINEVENTHOOK WINAPI NtUserSetWinEventHook( DWORD event_min, DWORD event_max, HMODULE inst,
                                            UNICODE_STRING *module, WINEVENTPROC proc,
                                            DWORD pid, DWORD tid, DWORD flags )
{
    HWINEVENTHOOK handle = 0;

    if ((flags & WINEVENT_INCONTEXT) && !inst)
    {
        RtlSetLastWin32Error(ERROR_HOOK_NEEDS_HMOD);
        return 0;
    }

    if (event_min > event_max)
    {
        RtlSetLastWin32Error(ERROR_INVALID_HOOK_FILTER);
        return 0;
    }

    /* FIXME: what if the tid or pid belongs to another process? */
    if (tid) inst = 0; /* thread-local hook */

    SERVER_START_REQ( set_hook )
    {
        req->id        = WH_WINEVENT;
        req->pid       = pid;
        req->tid       = tid;
        req->event_min = event_min;
        req->event_max = event_max;
        req->flags     = flags;
        req->unicode   = 1;
        if (inst) /* make proc relative to the module base */
        {
            req->proc = wine_server_client_ptr( (void *)((char *)proc - (char *)inst) );
            wine_server_add_data( req, module->Buffer, module->Length );
        }
        else req->proc = wine_server_client_ptr( proc );

        if (!wine_server_call_err( req ))
        {
            handle = wine_server_ptr_handle( reply->handle );
        }
    }
    SERVER_END_REQ;

    TRACE("-> %p\n", handle);
    return handle;
}

/***********************************************************************
 *           NtUserUnhookWinEvent   (win32u.@)
 */
BOOL WINAPI NtUserUnhookWinEvent( HWINEVENTHOOK handle )
{
    BOOL ret;

    SERVER_START_REQ( remove_hook )
    {
        req->handle = wine_server_user_handle( handle );
        req->id     = WH_WINEVENT;
        ret = !wine_server_call_err( req );
    }
    SERVER_END_REQ;
    return ret;
}

/***********************************************************************
 *           NtUserNotifyWinEvent   (win32u.@)
 */
void WINAPI NtUserNotifyWinEvent( DWORD event, HWND hwnd, LONG object_id, LONG child_id )
{
    struct win_event_hook_params info;
    void *ret_ptr;
    ULONG ret_len;
    BOOL ret;

    TRACE( "%04x, %p, %d, %d\n", event, hwnd, object_id, child_id );

    user_check_not_lock();

    if (!hwnd)
    {
        RtlSetLastWin32Error( ERROR_INVALID_WINDOW_HANDLE );
        return;
    }

    if (!is_hooked( WH_WINEVENT ))
    {
        TRACE( "skipping hook\n" );
        return;
    }

    info.event     = event;
    info.hwnd      = hwnd;
    info.object_id = object_id;
    info.child_id  = child_id;
    info.tid       = GetCurrentThreadId();

    SERVER_START_REQ( start_hook_chain )
    {
        req->id        = WH_WINEVENT;
        req->event     = event;
        req->window    = wine_server_user_handle( hwnd );
        req->object_id = object_id;
        req->child_id  = child_id;
        wine_server_set_reply( req, info.module, sizeof(info.module) - sizeof(WCHAR) );
        ret = !wine_server_call( req ) && reply->proc;
        if (ret)
        {
            info.module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info.handle = wine_server_ptr_handle( reply->handle );
            info.proc   = wine_server_get_ptr( reply->proc );
        }
    }
    SERVER_END_REQ;
    if (!ret) return;

    do
    {
        TRACE( "calling WH_WINEVENT hook %p event %x hwnd %p %x %x module %s\n",
               info.proc, event, hwnd, object_id, child_id, debugstr_w(info.module) );

        info.time = NtGetTickCount();
        KeUserModeCallback( NtUserCallWinEventHook, &info,
                            FIELD_OFFSET( struct win_event_hook_params, module[lstrlenW(info.module) + 1] ),
                            &ret_ptr, &ret_len );

        SERVER_START_REQ( get_hook_info )
        {
            req->handle    = wine_server_user_handle( info.handle );
            req->get_next  = 1;
            req->event     = event;
            req->window    = wine_server_user_handle( hwnd );
            req->object_id = object_id;
            req->child_id  = child_id;
            wine_server_set_reply( req, info.module, sizeof(info.module) - sizeof(WCHAR) );
            ret = !wine_server_call( req ) && reply->proc;
            if (ret)
            {
                info.module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
                info.handle = wine_server_ptr_handle( reply->handle );
                info.proc   = wine_server_get_ptr( reply->proc );
            }
        }
        SERVER_END_REQ;
    }
    while (ret);

    SERVER_START_REQ( finish_hook_chain )
    {
        req->id = WH_WINEVENT;
        wine_server_call( req );
    }
    SERVER_END_REQ;
}
