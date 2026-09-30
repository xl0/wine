/*
 * Associations
 *
 * Copyright 2007 Robert Shearman (for CodeWeavers)
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
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>

#include "rpc.h"
#include "rpcndr.h"

#include "wine/debug.h"

#include "rpc_binding.h"
#include "rpc_assoc.h"
#include "rpc_message.h"

WINE_DEFAULT_DEBUG_CHANNEL(rpc);

static CRITICAL_SECTION assoc_list_cs;
static CRITICAL_SECTION_DEBUG assoc_list_cs_debug =
{
    0, 0, &assoc_list_cs,
    { &assoc_list_cs_debug.ProcessLocksList, &assoc_list_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": assoc_list_cs") }
};
static CRITICAL_SECTION assoc_list_cs = { &assoc_list_cs_debug, -1, 0, 0, 0, 0 };

static struct list client_assoc_list = LIST_INIT(client_assoc_list);
static struct list server_assoc_list = LIST_INIT(server_assoc_list);

static LONG last_assoc_group_id;

typedef struct _RpcContextHandle
{
    struct list entry;
    void *user_context;
    NDR_RUNDOWN rundown_routine;
    void *ctx_guard;
    UUID uuid;
    CRITICAL_SECTION lock;
    unsigned int refs;
} RpcContextHandle;

static void RpcContextHandle_Destroy(RpcContextHandle *context_handle);

static RPC_STATUS RpcAssoc_Alloc(LPCSTR Protseq, LPCSTR NetworkAddr,
                                 LPCSTR Endpoint, LPCWSTR NetworkOptions,
                                 RpcAssoc **assoc_out)
{
    RpcAssoc *assoc;
    assoc = malloc(sizeof(*assoc));
    if (!assoc)
        return RPC_S_OUT_OF_RESOURCES;
    assoc->refs = 1;
    list_init(&assoc->free_connection_pool);
    list_init(&assoc->context_handle_list);
    InitializeCriticalSectionEx(&assoc->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    assoc->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RpcAssoc.cs");
    assoc->Protseq = strdup(Protseq);
    assoc->NetworkAddr = strdup(NetworkAddr);
    assoc->Endpoint = strdup(Endpoint);
    assoc->NetworkOptions = wcsdup(NetworkOptions);
    assoc->assoc_group_id = 0;
    assoc->connection_cnt = 0;
    UuidCreate(&assoc->http_uuid);
    list_init(&assoc->entry);
    *assoc_out = assoc;
    return RPC_S_OK;
}

static BOOL compare_networkoptions(LPCWSTR opts1, LPCWSTR opts2)
{
    if ((opts1 == NULL) && (opts2 == NULL))
        return TRUE;
    if ((opts1 == NULL) || (opts2 == NULL))
        return FALSE;
    return !wcscmp(opts1, opts2);
}

RPC_STATUS RPCRT4_GetAssociation(LPCSTR Protseq, LPCSTR NetworkAddr,
                                 LPCSTR Endpoint, LPCWSTR NetworkOptions,
                                 RpcAssoc **assoc_out)
{
    RpcAssoc *assoc;
    RPC_STATUS status;

    EnterCriticalSection(&assoc_list_cs);
    LIST_FOR_EACH_ENTRY(assoc, &client_assoc_list, RpcAssoc, entry)
    {
        if (!strcmp(Protseq, assoc->Protseq) &&
            !strcmp(NetworkAddr, assoc->NetworkAddr) &&
            !strcmp(Endpoint, assoc->Endpoint) &&
            compare_networkoptions(NetworkOptions, assoc->NetworkOptions))
        {
            assoc->refs++;
            *assoc_out = assoc;
            LeaveCriticalSection(&assoc_list_cs);
            TRACE("using existing assoc %p\n", assoc);
            return RPC_S_OK;
        }
    }

    status = RpcAssoc_Alloc(Protseq, NetworkAddr, Endpoint, NetworkOptions, &assoc);
    if (status != RPC_S_OK)
    {
        LeaveCriticalSection(&assoc_list_cs);
        return status;
    }
    list_add_head(&client_assoc_list, &assoc->entry);
    *assoc_out = assoc;

    LeaveCriticalSection(&assoc_list_cs);

    TRACE("new assoc %p\n", assoc);

    return RPC_S_OK;
}

RPC_STATUS RpcServerAssoc_GetAssociation(LPCSTR Protseq, LPCSTR NetworkAddr,
                                         LPCSTR Endpoint, LPCWSTR NetworkOptions,
                                         ULONG assoc_gid,
                                         RpcAssoc **assoc_out)
{
    RpcAssoc *assoc;
    RPC_STATUS status;

    EnterCriticalSection(&assoc_list_cs);
    if (assoc_gid)
    {
        LIST_FOR_EACH_ENTRY(assoc, &server_assoc_list, RpcAssoc, entry)
        {
            /* FIXME: NetworkAddr shouldn't be NULL */
            if (assoc->assoc_group_id == assoc_gid &&
                !strcmp(Protseq, assoc->Protseq) &&
                (!NetworkAddr || !assoc->NetworkAddr || !strcmp(NetworkAddr, assoc->NetworkAddr)) &&
                !strcmp(Endpoint, assoc->Endpoint) &&
                ((!assoc->NetworkOptions == !NetworkOptions) &&
                 (!NetworkOptions || !wcscmp(NetworkOptions, assoc->NetworkOptions))))
            {
                assoc->refs++;
                *assoc_out = assoc;
                LeaveCriticalSection(&assoc_list_cs);
                TRACE("using existing assoc %p\n", assoc);
                return RPC_S_OK;
            }
        }
        *assoc_out = NULL;
        LeaveCriticalSection(&assoc_list_cs);
        return RPC_S_NO_CONTEXT_AVAILABLE;
    }

    status = RpcAssoc_Alloc(Protseq, NetworkAddr, Endpoint, NetworkOptions, &assoc);
    if (status != RPC_S_OK)
    {
        LeaveCriticalSection(&assoc_list_cs);
        return status;
    }
    assoc->assoc_group_id = InterlockedIncrement(&last_assoc_group_id);
    list_add_head(&server_assoc_list, &assoc->entry);
    *assoc_out = assoc;

    LeaveCriticalSection(&assoc_list_cs);

    TRACE("new assoc %p\n", assoc);

    return RPC_S_OK;
}

ULONG RpcAssoc_Release(RpcAssoc *assoc)
{
    ULONG refs;

    EnterCriticalSection(&assoc_list_cs);
    refs = --assoc->refs;
    if (!refs)
        list_remove(&assoc->entry);
    LeaveCriticalSection(&assoc_list_cs);

    if (!refs)
    {
        RpcConnection *Connection, *cursor2;
        RpcContextHandle *context_handle, *context_handle_cursor;

        TRACE("destroying assoc %p\n", assoc);

        LIST_FOR_EACH_ENTRY_SAFE(Connection, cursor2, &assoc->free_connection_pool, RpcConnection, conn_pool_entry)
        {
            list_remove(&Connection->conn_pool_entry);
            RPCRT4_ReleaseConnection(Connection);
        }

        LIST_FOR_EACH_ENTRY_SAFE(context_handle, context_handle_cursor, &assoc->context_handle_list, RpcContextHandle, entry)
            RpcContextHandle_Destroy(context_handle);

        free(assoc->NetworkOptions);
        free(assoc->Endpoint);
        free(assoc->NetworkAddr);
        free(assoc->Protseq);

        assoc->cs.DebugInfo->Spare[0] = 0;
        DeleteCriticalSection(&assoc->cs);

        free(assoc);
    }

    return refs;
}

#define ROUND_UP(value, alignment) (((value) + ((alignment) - 1)) & ~((alignment)-1))

static const struct rpc_context *find_context(const RpcConnection *conn, const RPC_SYNTAX_IDENTIFIER *InterfaceId)
{
    unsigned int i;

    for (i = 0; i < conn->context_count; i++)
        if (!memcmp(&conn->contexts[i].syntax, InterfaceId, sizeof(*InterfaceId)))
            return &conn->contexts[i];
    return NULL;
}

/* Binds the interface to a new connection, or adds it to a bound one with an
 * alter_context request. *rejected is set if the server rejected the interface. */
static RPC_STATUS RpcAssoc_BindConnection(const RpcAssoc *assoc, RpcConnection *conn,
                                          const RPC_SYNTAX_IDENTIFIER *InterfaceId,
                                          const RPC_SYNTAX_IDENTIFIER *TransferSyntax,
                                          BOOL *rejected)
{
    unsigned char ptype = conn->context_count ? PKT_ALTER_CONTEXT : PKT_BIND;
    unsigned short context_id = conn->context_count;
    struct rpc_context *contexts;
    RpcPktHdr *hdr;
    RpcPktHdr *response_hdr;
    RPC_MESSAGE msg;
    RPC_STATUS status;
    unsigned char *auth_data = NULL;
    ULONG auth_length;

    TRACE("sending %s request to server\n", ptype == PKT_BIND ? "bind" : "alter_context");

    hdr = RPCRT4_BuildBindHeader(NDR_LOCAL_DATA_REPRESENTATION, ptype,
                                 RPC_MAX_PACKET_SIZE, RPC_MAX_PACKET_SIZE,
                                 assoc->assoc_group_id, context_id,
                                 InterfaceId, TransferSyntax);

    status = RPCRT4_Send(conn, hdr, NULL, 0);
    free(hdr);
    if (status != RPC_S_OK)
        return status;

    status = RPCRT4_ReceiveWithAuth(conn, &response_hdr, &msg, &auth_data, &auth_length);
    if (status != RPC_S_OK)
    {
        ERR("receive failed with error %ld\n", status);
        return status;
    }

    switch (response_hdr->common.ptype)
    {
    case PKT_BIND_ACK:
    case PKT_ALTER_CONTEXT_RESP:
    {
        RpcAddressString *server_address = msg.Buffer;
        if (response_hdr->common.ptype != (ptype == PKT_BIND ? PKT_BIND_ACK : PKT_ALTER_CONTEXT_RESP))
        {
            ERR("wrong packet type received %d\n", response_hdr->common.ptype);
            status = RPC_S_PROTOCOL_ERROR;
        }
        else if ((msg.BufferLength >= FIELD_OFFSET(RpcAddressString, string[0])) ||
            (msg.BufferLength >= ROUND_UP(FIELD_OFFSET(RpcAddressString, string[server_address->length]), 4)))
        {
            unsigned short remaining = msg.BufferLength -
            ROUND_UP(FIELD_OFFSET(RpcAddressString, string[server_address->length]), 4);
            RpcResultList *results = (RpcResultList*)((ULONG_PTR)server_address +
                ROUND_UP(FIELD_OFFSET(RpcAddressString, string[server_address->length]), 4));
            if ((results->num_results == 1) &&
                (remaining >= FIELD_OFFSET(RpcResultList, results[results->num_results])))
            {
                *rejected = results->results[0].result != RESULT_ACCEPT;
                switch (results->results[0].result)
                {
                case RESULT_ACCEPT:
                    /* respond to authorization request */
                    if (auth_length > sizeof(RpcAuthVerifier))
                        status = RPCRT4_ClientConnectionAuth(conn,
                                                             auth_data + sizeof(RpcAuthVerifier),
                                                             auth_length);
                    if (status == RPC_S_OK &&
                        !(contexts = realloc(conn->contexts, (context_id + 1) * sizeof(*contexts))))
                        status = RPC_S_OUT_OF_RESOURCES;
                    if (status == RPC_S_OK)
                    {
                        if (ptype == PKT_BIND)
                        {
                            conn->assoc_group_id = response_hdr->bind_ack.assoc_gid;
                            conn->MaxTransmissionSize = response_hdr->bind_ack.max_tsize;
                        }
                        contexts[context_id].id = context_id;
                        contexts[context_id].syntax = *InterfaceId;
                        conn->contexts = contexts;
                        conn->context_count++;
                        conn->ActiveContextId = context_id;
                    }
                    break;
                case RESULT_PROVIDER_REJECTION:
                    switch (results->results[0].reason)
                    {
                    case REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED:
                        ERR("syntax %s, %d.%d not supported\n",
                            debugstr_guid(&InterfaceId->SyntaxGUID),
                            InterfaceId->SyntaxVersion.MajorVersion,
                            InterfaceId->SyntaxVersion.MinorVersion);
                        status = RPC_S_UNKNOWN_IF;
                        break;
                    case REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED:
                        ERR("transfer syntax not supported\n");
                        status = RPC_S_SERVER_UNAVAILABLE;
                        break;
                    case REASON_NONE:
                    default:
                        status = RPC_S_CALL_FAILED_DNE;
                    }
                    break;
                case RESULT_USER_REJECTION:
                default:
                    ERR("rejection result %d\n", results->results[0].result);
                    status = RPC_S_CALL_FAILED_DNE;
                }
            }
            else
            {
                ERR("incorrect results size\n");
                status = RPC_S_CALL_FAILED_DNE;
            }
        }
        else
        {
            ERR("bind ack packet too small (%d)\n", msg.BufferLength);
            status = RPC_S_PROTOCOL_ERROR;
        }
        break;
    }
    case PKT_BIND_NACK:
        switch (response_hdr->bind_nack.reject_reason)
        {
        case REJECT_LOCAL_LIMIT_EXCEEDED:
        case REJECT_TEMPORARY_CONGESTION:
            ERR("server too busy\n");
            status = RPC_S_SERVER_TOO_BUSY;
            break;
        case REJECT_PROTOCOL_VERSION_NOT_SUPPORTED:
            ERR("protocol version not supported\n");
            status = RPC_S_PROTOCOL_ERROR;
            break;
        case REJECT_UNKNOWN_AUTHN_SERVICE:
            ERR("unknown authentication service\n");
            status = RPC_S_UNKNOWN_AUTHN_SERVICE;
            break;
        case REJECT_INVALID_CHECKSUM:
            ERR("invalid checksum\n");
            status = RPC_S_ACCESS_DENIED;
            break;
        default:
            ERR("rejected bind for reason %d\n", response_hdr->bind_nack.reject_reason);
            status = RPC_S_CALL_FAILED_DNE;
        }
        break;
    default:
        ERR("wrong packet type received %d\n", response_hdr->common.ptype);
        status = RPC_S_PROTOCOL_ERROR;
        break;
    }

    I_RpcFree(msg.Buffer);
    free(response_hdr);
    free(auth_data);
    return status;
}

static RpcConnection *RpcAssoc_GetIdleConnection(RpcAssoc *assoc,
                                                 const RPC_SYNTAX_IDENTIFIER *InterfaceId,
                                                 const RPC_SYNTAX_IDENTIFIER *TransferSyntax, const RpcAuthInfo *AuthInfo,
                                                 const RpcQualityOfService *QOS)
{
    RpcConnection *Connection, *found = NULL;
    EnterCriticalSection(&assoc->cs);
    /* try to find a compatible connection from the connection pool, preferably
     * one with the interface already bound */
    LIST_FOR_EACH_ENTRY(Connection, &assoc->free_connection_pool, RpcConnection, conn_pool_entry)
    {
        if (!RpcAuthInfo_IsEqual(Connection->AuthInfo, AuthInfo) ||
            !RpcQualityOfService_IsEqual(Connection->QOS, QOS))
            continue;
        if (find_context(Connection, InterfaceId))
        {
            found = Connection;
            break;
        }
        /* FIXME: alter_context on authenticated connections is not supported */
        if (!found && !Connection->AuthInfo && Connection->context_count < RPC_MAX_CONTEXTS)
            found = Connection;
    }
    if (found)
    {
        list_remove(&found->conn_pool_entry);
        TRACE("got connection from pool %p\n", found);
    }

    LeaveCriticalSection(&assoc->cs);
    return found;
}

RPC_STATUS RpcAssoc_GetClientConnection(RpcAssoc *assoc,
                                        const RPC_SYNTAX_IDENTIFIER *InterfaceId,
                                        const RPC_SYNTAX_IDENTIFIER *TransferSyntax, RpcAuthInfo *AuthInfo,
                                        RpcQualityOfService *QOS, LPCWSTR CookieAuth,
                                        RpcConnection **Connection, BOOL *from_cache)
{
    const struct rpc_context *context;
    RpcConnection *NewConnection;
    BOOL rejected = FALSE;
    RPC_STATUS status;

    *Connection = RpcAssoc_GetIdleConnection(assoc, InterfaceId, TransferSyntax, AuthInfo, QOS);
    if (*Connection) {
        if ((context = find_context(*Connection, InterfaceId)))
            (*Connection)->ActiveContextId = context->id;
        else if ((status = RpcAssoc_BindConnection(assoc, *Connection, InterfaceId, TransferSyntax, &rejected)) != RPC_S_OK)
        {
            /* the connection is still usable if the server rejected the interface */
            if (rejected)
                RpcAssoc_ReleaseIdleConnection(assoc, *Connection);
            else
                RPCRT4_ReleaseConnection(*Connection);
            *Connection = NULL;
            if (rejected || status == RPC_S_CALL_CANCELLED)
                return status;
            WARN("alter_context failed with error %ld, opening a new connection\n", status);
        }
    }
    if (*Connection) {
        TRACE("return idle connection %p for association %p\n", *Connection, assoc);
        if (from_cache) *from_cache = TRUE;
        return RPC_S_OK;
    }

    /* create a new connection */
    status = RPCRT4_CreateConnection(&NewConnection, FALSE /* is this a server connection? */,
        assoc->Protseq, assoc->NetworkAddr,
        assoc->Endpoint, assoc->NetworkOptions,
        AuthInfo, QOS, CookieAuth);
    if (status != RPC_S_OK)
        return status;

    /* RPCRT4_ReleaseConnection() uncounts it, also on failure below */
    NewConnection->assoc = assoc;
    InterlockedIncrement(&assoc->connection_cnt);
    status = RPCRT4_OpenClientConnection(NewConnection);
    if (status != RPC_S_OK)
    {
        RPCRT4_ReleaseConnection(NewConnection);
        return status;
    }

    status = RpcAssoc_BindConnection(assoc, NewConnection, InterfaceId, TransferSyntax, &rejected);
    if (status != RPC_S_OK)
    {
        RPCRT4_ReleaseConnection(NewConnection);
        return status;
    }

    TRACE("return new connection %p for association %p\n", *Connection, assoc);
    *Connection = NewConnection;
    if (from_cache) *from_cache = FALSE;
    return RPC_S_OK;
}

void RpcAssoc_ReleaseIdleConnection(RpcAssoc *assoc, RpcConnection *Connection)
{
    assert(!Connection->server);
    Connection->async_state = NULL;
    EnterCriticalSection(&assoc->cs);
    if (!assoc->assoc_group_id) assoc->assoc_group_id = Connection->assoc_group_id;
    list_add_head(&assoc->free_connection_pool, &Connection->conn_pool_entry);
    LeaveCriticalSection(&assoc->cs);
}

void RpcAssoc_ConnectionReleased(RpcAssoc *assoc)
{
    if (InterlockedDecrement(&assoc->connection_cnt))
        return;

    TRACE("Last %p connection released\n", assoc);
    assoc->assoc_group_id = 0;
}

RPC_STATUS RpcServerAssoc_AllocateContextHandle(RpcAssoc *assoc, void *CtxGuard,
                                                NDR_SCONTEXT *SContext)
{
    RpcContextHandle *context_handle;

    context_handle = calloc(1, sizeof(*context_handle));
    if (!context_handle)
        return RPC_S_OUT_OF_MEMORY;

    context_handle->ctx_guard = CtxGuard;
    InitializeCriticalSectionEx(&context_handle->lock, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    context_handle->lock.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RpcContextHandle.lock");
    context_handle->refs = 1;

    /* lock here to mirror unmarshall, so we don't need to special-case the
     * freeing of a non-marshalled context handle */
    EnterCriticalSection(&context_handle->lock);

    EnterCriticalSection(&assoc->cs);
    list_add_tail(&assoc->context_handle_list, &context_handle->entry);
    LeaveCriticalSection(&assoc->cs);

    *SContext = (NDR_SCONTEXT)context_handle;
    return RPC_S_OK;
}

BOOL RpcContextHandle_IsGuardCorrect(NDR_SCONTEXT SContext, void *CtxGuard)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    return context_handle->ctx_guard == CtxGuard;
}

RPC_STATUS RpcServerAssoc_FindContextHandle(RpcAssoc *assoc, const UUID *uuid,
                                            void *CtxGuard, ULONG Flags, NDR_SCONTEXT *SContext)
{
    RpcContextHandle *context_handle;

    EnterCriticalSection(&assoc->cs);
    LIST_FOR_EACH_ENTRY(context_handle, &assoc->context_handle_list, RpcContextHandle, entry)
    {
        if (RpcContextHandle_IsGuardCorrect((NDR_SCONTEXT)context_handle, CtxGuard) &&
            !memcmp(&context_handle->uuid, uuid, sizeof(*uuid)))
        {
            *SContext = (NDR_SCONTEXT)context_handle;
            if (context_handle->refs++)
            {
                LeaveCriticalSection(&assoc->cs);
                TRACE("found %p\n", context_handle);
                EnterCriticalSection(&context_handle->lock);
                return RPC_S_OK;
            }
        }
    }
    LeaveCriticalSection(&assoc->cs);

    ERR("no context handle found for uuid %s, guard %p\n",
        debugstr_guid(uuid), CtxGuard);
    return ERROR_INVALID_HANDLE;
}

RPC_STATUS RpcServerAssoc_UpdateContextHandle(RpcAssoc *assoc,
                                              NDR_SCONTEXT SContext,
                                              void *CtxGuard,
                                              NDR_RUNDOWN rundown_routine)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    RPC_STATUS status;

    if (!RpcContextHandle_IsGuardCorrect((NDR_SCONTEXT)context_handle, CtxGuard))
        return ERROR_INVALID_HANDLE;

    EnterCriticalSection(&assoc->cs);
    if (UuidIsNil(&context_handle->uuid, &status))
    {
        /* add a ref for the data being valid */
        context_handle->refs++;
        UuidCreate(&context_handle->uuid);
        context_handle->rundown_routine = rundown_routine;
        TRACE("allocated uuid %s for context handle %p\n",
              debugstr_guid(&context_handle->uuid), context_handle);
    }
    LeaveCriticalSection(&assoc->cs);

    return RPC_S_OK;
}

void RpcContextHandle_GetUuid(NDR_SCONTEXT SContext, UUID *uuid)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    *uuid = context_handle->uuid;
}

static void RpcContextHandle_Destroy(RpcContextHandle *context_handle)
{
    TRACE("freeing %p\n", context_handle);

    if (context_handle->user_context && context_handle->rundown_routine)
    {
        TRACE("calling rundown routine %p with user context %p\n",
              context_handle->rundown_routine, context_handle->user_context);
        context_handle->rundown_routine(context_handle->user_context);
    }

    context_handle->lock.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&context_handle->lock);

    free(context_handle);
}

unsigned int RpcServerAssoc_ReleaseContextHandle(RpcAssoc *assoc, NDR_SCONTEXT SContext, BOOL release_lock)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    unsigned int refs;

    if (release_lock)
        LeaveCriticalSection(&context_handle->lock);

    EnterCriticalSection(&assoc->cs);
    refs = --context_handle->refs;
    if (!refs)
        list_remove(&context_handle->entry);
    LeaveCriticalSection(&assoc->cs);

    if (!refs)
        RpcContextHandle_Destroy(context_handle);

    return refs;
}
