/*
 * Wayland client surfaces shown by another process
 *
 * Copyright 2026 Alexey Zaytsev
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

/* A process may present to a child window of its own which has a window of
 * another process as parent (Chromium's GPU process does). The wl_surface of
 * the toplevel only exists in the Wayland connection of the process that owns
 * it, so the client surface cannot be made a subsurface of it.
 *
 * Instead the presenting process (the source) copies every frame to shared
 * memory, and the process of the toplevel (the sink) shows the frames in a
 * subsurface of its own. A source is only accepted for a window of its own
 * process: presenting to a window of another process is not supported, as
 * that would let any process draw over the windows of the others.
 *
 * - The source creates a control block (struct remote_shared), a section
 *   with the frame buffers, and a socket pair to wake the sink, and posts a
 *   driver message with its window and the handle of the control block to
 *   the toplevel window.
 * - The sink duplicates the handles it needs from the source process. The
 *   message is only needed for the first contact, afterwards the sink waits
 *   on the socket in the Wayland event thread, and doesn't depend on the
 *   message loop of the window.
 * - The source always has a buffer to draw to and never waits for the sink:
 *   of the three buffers one may be shown, one is the latest complete frame
 *   and one is being drawn.
 * - The sink places the subsurface itself, from the position and the visible
 *   region of the client window in the server: it is clipped by the parent
 *   windows and by the siblings above it like the window is, also when its
 *   own process changes them while the source doesn't present.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "waylanddrv.h"
#include "wine/debug.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(waylanddrv);

#define REMOTE_BUFFER_COUNT 3
#define REMOTE_BUFFER_MASK ((1u << REMOTE_BUFFER_COUNT) - 1)
#define REMOTE_MAX_SIZE 8192    /* of a buffer, in pixels */

/* The values of the mailboxes also have the generation of the buffers, so
 * that the values for a previous buffer section are ignored. */
#define REMOTE_GENERATION_SHIFT 8
#define REMOTE_GENERATION_MASK 0xffffff

static inline LONG mailbox_value(UINT generation, UINT value)
{
    return (generation << REMOTE_GENERATION_SHIFT) | value;
}

/* get the value of a mailbox, or 0 if it is of another generation */
static inline UINT mailbox_get(LONG value, UINT generation)
{
    if ((UINT)value >> REMOTE_GENERATION_SHIFT != generation) return 0;
    return value & ((1u << REMOTE_GENERATION_SHIFT) - 1);
}

/* get the mask of the buffer in a mailbox, which has its index + 1 */
static inline UINT mailbox_get_buffer(LONG value, UINT generation)
{
    UINT index = mailbox_get(value, generation);
    return index && index <= REMOTE_BUFFER_COUNT ? 1u << (index - 1) : 0;
}

/* Control block shared by a source and its sink. The sink doesn't trust the
 * fields written by the source, they are copied and validated before use. */
#define REMOTE_MAGIC 0x31727377  /* "wsr1" */

struct remote_shared
{
    /* written by the source */
    UINT magic;         /* REMOTE_MAGIC */
    LONG seq;           /* sequence lock of the configuration, odd while it changes;
                         * also incremented when the client window has changed */
    UINT hwnd;          /* client window */
    UINT wake;          /* source handle to the sink end of the wake socket */
    UINT section;       /* source handle to the section of the buffers */
    UINT generation;    /* changes with the section */
    UINT width;         /* size of the buffers */
    UINT height;
    /* written by both */
    LONG ready;         /* latest complete buffer + 1, taken by the sink */
    LONG released;      /* mask of the buffers that the sink has given back */
    /* written by the sink */
    LONG attached;      /* the sink has the wake socket */
};

/**********************************************************************
 *          Source, in the process which presents
 */

struct remote_source
{
    HWND toplevel;                  /* toplevel window, in the sink process */
    struct remote_shared *shared;
    HANDLE shared_handle;
    HANDLE wake_handle;             /* sink end of the wake socket, until the sink has it */
    int wake_fd;
    HANDLE section;                 /* section of the buffers */
    BYTE *data;
    SIZE_T buffer_size;
    UINT generation;
    UINT width, height;             /* size of the buffers */
    RECT rect;                      /* last position in the toplevel window */
    BOOL visible;
    UINT free;                      /* mask of the buffers that may be drawn to */
    int locked;                     /* buffer being drawn to */
};

static pthread_mutex_t source_mutex = PTHREAD_MUTEX_INITIALIZER;

static void remote_source_wake(struct remote_source *source)
{
    char c = 0;
    send(source->wake_fd, &c, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void remote_source_destroy(struct remote_source *source)
{
    TRACE("source=%p\n", source);

    /* closing the socket tells the sink */
    if (source->wake_fd != -1) close(source->wake_fd);
    if (source->wake_handle) NtClose(source->wake_handle);
    if (source->data) NtUnmapViewOfSection(GetCurrentProcess(), source->data);
    if (source->section) NtClose(source->section);
    if (source->shared) NtUnmapViewOfSection(GetCurrentProcess(), source->shared);
    if (source->shared_handle) NtClose(source->shared_handle);
    free(source);
}

static struct remote_source *remote_source_create(HWND hwnd, HWND toplevel)
{
    LARGE_INTEGER size = {.QuadPart = sizeof(struct remote_shared)};
    struct remote_source *source;
    SIZE_T view_size = 0;
    int fds[2];

    if (!(source = calloc(1, sizeof(*source)))) return NULL;
    source->toplevel = toplevel;
    source->wake_fd = -1;

    if (NtCreateSection(&source->shared_handle, GENERIC_READ | SECTION_MAP_READ | SECTION_MAP_WRITE,
                        NULL, &size, PAGE_READWRITE, SEC_COMMIT, 0))
        goto err;
    if (NtMapViewOfSection(source->shared_handle, GetCurrentProcess(), (void **)&source->shared, 0, 0,
                           NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE))
    {
        source->shared = NULL;
        goto err;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds)) goto err;
    source->wake_fd = fds[0];
    /* the server keeps the other end for the sink */
    if (wine_server_fd_to_handle(fds[1], GENERIC_READ | SYNCHRONIZE, 0, &source->wake_handle))
        source->wake_handle = 0;
    close(fds[1]);
    if (!source->wake_handle) goto err;

    source->shared->magic = REMOTE_MAGIC;
    source->shared->hwnd = HandleToULong(hwnd);
    source->shared->wake = HandleToULong(source->wake_handle);

    TRACE("hwnd=%p toplevel=%p source=%p\n", hwnd, toplevel, source);
    return source;

err:
    ERR("Failed to create a source for window %p\n", hwnd);
    remote_source_destroy(source);
    return NULL;
}

/* (re)create the buffers of a source */
static BOOL remote_source_set_size(struct remote_source *source, UINT width, UINT height)
{
    UINT64 buffer_size = (UINT64)width * height * WINEWAYLAND_BYTES_PER_PIXEL;
    LARGE_INTEGER size = {.QuadPart = buffer_size * REMOTE_BUFFER_COUNT};
    struct remote_shared *shared = source->shared;
    SIZE_T view_size = 0;
    HANDLE section;
    BYTE *data = NULL;

    if (!width || width > REMOTE_MAX_SIZE || !height || height > REMOTE_MAX_SIZE) return FALSE;

    if (NtCreateSection(&section, GENERIC_READ | SECTION_MAP_READ | SECTION_MAP_WRITE,
                        NULL, &size, PAGE_READWRITE, SEC_COMMIT, 0))
        return FALSE;
    if (NtMapViewOfSection(section, GetCurrentProcess(), (void **)&data, 0, 0, NULL, &view_size,
                           ViewUnmap, 0, PAGE_READWRITE))
    {
        NtClose(section);
        return FALSE;
    }

    TRACE("source=%p %ux%u\n", source, width, height);

    if (!(source->generation = (source->generation + 1) & REMOTE_GENERATION_MASK)) source->generation = 1;

    InterlockedIncrement(&shared->seq);
    shared->section = HandleToULong(section);
    shared->generation = source->generation;
    shared->width = width;
    shared->height = height;
    InterlockedIncrement(&shared->seq);

    /* the sink closes its side when it sees the new generation */
    if (source->data) NtUnmapViewOfSection(GetCurrentProcess(), source->data);
    if (source->section) NtClose(source->section);
    source->section = section;
    source->data = data;
    source->buffer_size = buffer_size;
    source->width = width;
    source->height = height;
    source->free = REMOTE_BUFFER_MASK;
    return TRUE;
}

/**********************************************************************
 *          wayland_client_surface_set_remote
 *
 * Present a client surface through the process of a toplevel window, or stop
 * doing it if toplevel is NULL.
 */
void wayland_client_surface_set_remote(struct wayland_client_surface *client, HWND toplevel,
                                       const RECT *rect, BOOL visible)
{
    struct remote_source *source;
    struct remote_shared *shared;
    HANDLE handle = 0;

    pthread_mutex_lock(&source_mutex);

    if ((source = client->remote) && source->toplevel != toplevel)
    {
        remote_source_destroy(source);
        client->remote = source = NULL;
    }
    if (!source && toplevel && (source = client->remote = remote_source_create(client->client.hwnd, toplevel)))
        handle = source->shared_handle;

    if (source)
    {
        shared = source->shared;

        if (source->wake_handle && ReadNoFence(&shared->attached))
        {
            NtClose(source->wake_handle);
            source->wake_handle = 0;
        }

        if (!EqualRect(&source->rect, rect) || source->visible != visible)
        {
            /* the sink gets the new state of the window from the server */
            source->rect = *rect;
            source->visible = visible;
            InterlockedExchangeAdd(&shared->seq, 2);
            remote_source_wake(source);
        }
    }

    pthread_mutex_unlock(&source_mutex);

    /* Only this first message depends on the message loop of the window. */
    if (handle) NtUserPostMessage(toplevel, WM_WAYLAND_REMOTE_SURFACE, (WPARAM)client->client.hwnd, HandleToULong(handle));
}

/**********************************************************************
 *          wayland_client_surface_lock_remote_buffer
 *
 * Get the buffer for the next frame of a client surface that is shown by
 * another process. Returns FALSE if the client surface is not. If there is
 * a buffer it must be unlocked.
 */
BOOL wayland_client_surface_lock_remote_buffer(struct wayland_client_surface *client, UINT width,
                                               UINT height, void **pixels)
{
    struct remote_source *source;
    struct remote_shared *shared;
    LONG value;

    *pixels = NULL;

    pthread_mutex_lock(&source_mutex);

    if (!(source = client->remote))
    {
        pthread_mutex_unlock(&source_mutex);
        return FALSE;
    }
    shared = source->shared;

    if ((source->width != width || source->height != height) && !remote_source_set_size(source, width, height))
    {
        WARN("Failed to create %ux%u buffers\n", width, height);
        pthread_mutex_unlock(&source_mutex);
        return TRUE;
    }

    value = InterlockedExchange(&shared->released, mailbox_value(source->generation, 0));
    source->free |= mailbox_get(value, source->generation) & REMOTE_BUFFER_MASK;
    /* take back the frame that the sink has not used */
    if (!source->free)
        source->free |= mailbox_get_buffer(InterlockedExchange(&shared->ready, 0), source->generation);
    if (!source->free)
    {
        WARN("No free buffer\n");
        pthread_mutex_unlock(&source_mutex);
        return TRUE;
    }

    for (source->locked = 0; !(source->free & (1u << source->locked)); source->locked++) {}
    *pixels = source->data + source->locked * source->buffer_size;
    return TRUE;
}

/**********************************************************************
 *          wayland_client_surface_unlock_remote_buffer
 *
 * Give the locked buffer to the sink if it has a frame.
 */
void wayland_client_surface_unlock_remote_buffer(struct wayland_client_surface *client, BOOL present)
{
    struct remote_source *source = client->remote;
    LONG value;

    if (present)
    {
        value = InterlockedExchange(&source->shared->ready, mailbox_value(source->generation, source->locked + 1));
        source->free &= ~(1u << source->locked);
        /* the previous frame, if the sink has not taken it */
        source->free |= mailbox_get_buffer(value, source->generation);
        remote_source_wake(source);
    }

    pthread_mutex_unlock(&source_mutex);
}

/**********************************************************************
 *          Sink, in the process of the toplevel window
 *
 * The sinks are protected by the window data lock. Their buffers have
 * listeners, they are only created and destroyed in the event thread.
 */

/* Limits for the sources of a single process, so that a process can only
 * take its own share. There is no limit for all of them. */
#define REMOTE_MAX_PROCESS_SINKS 16
#define REMOTE_MAX_PROCESS_SIZE 0x40000000  /* of the buffers, in bytes */

/* Position of a client window, in screen coordinates as the server has them. */
struct remote_geometry
{
    HWND toplevel;                  /* toplevel window that the client window is in */
    RECT toplevel_rect;             /* its client rect */
    RECT window_rect;               /* client rect of the client window */
    RECT visible_rect;              /* bounding box of its visible region */
};

struct remote_sink
{
    struct list entry;
    HWND toplevel;                  /* toplevel window showing the surface */
    HWND hwnd;                      /* client window, a window of the source process */
    DWORD pid;                      /* source process */
    HANDLE process;
    struct remote_shared *shared;
    int wake_fd;
    BOOL dirty;                     /* a window has changed, the geometry is to be queried */
    BOOL update;                    /* a buffer has been released while a frame was waiting */
    BOOL dead;                      /* to be destroyed by the event thread */
    LONG seq;                       /* sequence of the source for the geometry */
    struct remote_geometry geometry;
    struct wl_surface *wl_surface;
    struct wp_viewport *wp_viewport;
    struct wl_subsurface *wl_subsurface;
    UINT generation;
    UINT width, height;             /* size of the buffers */
    UINT size;                      /* of the pool of the buffers, in bytes */
    struct wl_buffer *buffers[REMOTE_BUFFER_COUNT];
    UINT busy;                      /* mask of the buffers that the compositor has not released */
    BOOL waiting;                   /* a frame is left in the mailbox until a buffer is released */
    int current;                    /* buffer with the last frame, or -1 */
    UINT attached_width;            /* size of the buffer that the surface has */
    UINT attached_height;
    RECT rect;                      /* position that was set */
};

static struct list sinks = LIST_INIT(sinks);
static LONG sink_count;
static pthread_once_t sinks_once = PTHREAD_ONCE_INIT;
static int sinks_fd = -1;           /* wakes the event thread */
static struct pollfd sinks_initial_pollfds[8];
static struct pollfd *sinks_pollfds = sinks_initial_pollfds;    /* of the event thread */
static int sinks_pollfds_size = ARRAY_SIZE(sinks_initial_pollfds);

static void remote_sinks_init(void)
{
    sinks_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}

static void remote_sinks_wake(void)
{
    UINT64 value = 1;

    pthread_once(&sinks_once, remote_sinks_init);
    if (write(sinks_fd, &value, sizeof(value)) == -1) WARN("Failed to wake the event thread\n");
}

static void buffer_release(void *data, struct wl_buffer *wl_buffer)
{
    struct remote_sink *sink = data;
    LONG old, new;
    UINT i, tries;

    wayland_win_data_lock();
    for (i = 0; i < REMOTE_BUFFER_COUNT; i++)
    {
        if (sink->buffers[i] != wl_buffer) continue;
        sink->busy &= ~(1u << i);
        if (sink->waiting) sink->update = TRUE;
        /* The source only takes the mask between two frames. Don't insist
         * if it keeps changing, it is not trusted to end the loop. */
        for (tries = 0; tries < 4; tries++)
        {
            old = ReadNoFence(&sink->shared->released);
            new = mailbox_value(sink->generation, mailbox_get(old, sink->generation) | (1u << i));
            if (InterlockedCompareExchange(&sink->shared->released, new, old) == old) break;
        }
    }
    wayland_win_data_unlock();
}

static const struct wl_buffer_listener buffer_listener = { buffer_release };

static void remote_sink_destroy_buffers(struct remote_sink *sink)
{
    UINT i;

    for (i = 0; i < REMOTE_BUFFER_COUNT; i++)
    {
        if (sink->buffers[i]) wl_buffer_destroy(sink->buffers[i]);
        sink->buffers[i] = NULL;
    }
    sink->busy = 0;
    sink->current = -1;
    sink->size = 0;
}

static void remote_sink_destroy(struct remote_sink *sink)
{
    TRACE("sink=%p\n", sink);

    list_remove(&sink->entry);
    InterlockedDecrement(&sink_count);

    if (sink->wl_subsurface) wl_subsurface_destroy(sink->wl_subsurface);
    if (sink->wp_viewport) wp_viewport_destroy(sink->wp_viewport);
    if (sink->wl_surface) wl_surface_destroy(sink->wl_surface);
    remote_sink_destroy_buffers(sink);
    NtUnmapViewOfSection(GetCurrentProcess(), sink->shared);
    NtClose(sink->process);
    close(sink->wake_fd);
    free(sink);
}

/* get an object of the source process */
static HANDLE remote_sink_get_handle(HANDLE process, UINT handle)
{
    HANDLE ret;

    if (NtDuplicateObject(process, UlongToHandle(handle), GetCurrentProcess(), &ret, 0, 0, DUPLICATE_SAME_ACCESS))
        return 0;
    return ret;
}

/* get a consistent copy of the configuration, unless the source is changing it */
static BOOL remote_sink_get_config(struct remote_sink *sink, struct remote_shared *config)
{
    UINT i;

    for (i = 0; i < 4; i++)
    {
        LONG seq = ReadNoFence(&sink->shared->seq);

        if (seq & 1) continue;
        *config = *sink->shared;
        if (ReadNoFence(&sink->shared->seq) != seq) continue;

        config->generation &= REMOTE_GENERATION_MASK;
        return TRUE;
    }

    /* the source wakes us again after the change */
    return FALSE;
}

/* create the buffers of a sink from the section of the source */
static void remote_sink_set_buffers(struct remote_sink *sink, const struct remote_shared *config)
{
    UINT buffer_size, size, used = 0;
    SECTION_BASIC_INFORMATION info;
    struct remote_sink *other;
    struct wl_shm_pool *pool;
    HANDLE section;
    struct stat st;
    int fd = -1;
    UINT i;

    TRACE("sink=%p generation=%u %ux%u\n", sink, config->generation, config->width, config->height);

    remote_sink_destroy_buffers(sink);
    sink->generation = config->generation;
    sink->width = config->width;
    sink->height = config->height;

    if (!config->width || config->width > REMOTE_MAX_SIZE || !config->height || config->height > REMOTE_MAX_SIZE)
        goto err;
    buffer_size = config->width * config->height * WINEWAYLAND_BYTES_PER_PIXEL;
    size = buffer_size * REMOTE_BUFFER_COUNT;

    LIST_FOR_EACH_ENTRY(other, &sinks, struct remote_sink, entry) if (other->pid == sink->pid) used += other->size;
    if (size > REMOTE_MAX_PROCESS_SIZE - used) goto err;

    /* The compositor maps and reads the buffers, not this process. The
     * section has to be large enough for a valid pool now; the source could
     * still truncate its file later, which compositors have to survive from
     * any client, and which ends our connection with an error. */
    if (!(section = remote_sink_get_handle(sink->process, config->section))) goto err;
    if (NtQuerySection(section, SectionBasicInformation, &info, sizeof(info), NULL) ||
        info.Size.QuadPart < size ||
        wine_server_handle_to_fd(section, FILE_READ_DATA, &fd, NULL))
        fd = -1;
    NtClose(section);
    if (fd == -1) goto err;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < size)
    {
        close(fd);
        goto err;
    }

    pool = wl_shm_create_pool(process_wayland.wl_shm, fd, size);
    close(fd);
    if (!pool) goto err;
    for (i = 0; i < REMOTE_BUFFER_COUNT; i++)
    {
        sink->buffers[i] = wl_shm_pool_create_buffer(pool, i * buffer_size, config->width, config->height,
                                                     config->width * WINEWAYLAND_BYTES_PER_PIXEL,
                                                     WL_SHM_FORMAT_XRGB8888);
        if (sink->buffers[i]) wl_buffer_add_listener(sink->buffers[i], &buffer_listener, sink);
    }
    wl_shm_pool_destroy(pool);
    sink->size = size;
    return;

err:
    WARN("Invalid buffers from the source of window %p\n", sink->hwnd);
}

/* get the client rect and the bounding box of the visible region of a window */
static BOOL get_window_visible_rect(HWND hwnd, HWND *toplevel, RECT *window_rect, RECT *visible_rect)
{
    struct rectangle buffer[64], *rects = buffer;
    data_size_t size = visible_rect ? sizeof(buffer) : 0, total = 0;
    NTSTATUS status;
    UINT i;

    for (;;)
    {
        SERVER_START_REQ(get_visible_region)
        {
            req->window = wine_server_user_handle(hwnd);
            req->flags = 0;
            if (size) wine_server_set_reply(req, rects, size);
            status = wine_server_call(req);
            if (!status || status == STATUS_BUFFER_OVERFLOW)
            {
                *toplevel = wine_server_ptr_handle(reply->top_win);
                *window_rect = wine_server_get_rect(reply->win_rect);
                total = reply->total_size;
            }
        }
        SERVER_END_REQ;

        /* the region is not wanted, or it is complete */
        if (status != STATUS_BUFFER_OVERFLOW || !visible_rect) break;
        if (rects != buffer) free(rects);
        if (!(rects = malloc(total))) return FALSE;
        size = total;
    }

    if (!status && visible_rect)
    {
        SetRectEmpty(visible_rect);
        for (i = 0; i < total / sizeof(*rects); i++)
        {
            RECT rect = wine_server_get_rect(rects[i]);
            if (!i) *visible_rect = rect;
            visible_rect->left = min(visible_rect->left, rect.left);
            visible_rect->top = min(visible_rect->top, rect.top);
            visible_rect->right = max(visible_rect->right, rect.right);
            visible_rect->bottom = max(visible_rect->bottom, rect.bottom);
        }
        TRACE("hwnd=%p toplevel=%p window=%s visible=%s (%u rects)\n", hwnd, *toplevel, wine_dbgstr_rect(window_rect),
              wine_dbgstr_rect(visible_rect), (UINT)(total / sizeof(*rects)));
    }
    if (rects != buffer) free(rects);
    return !status || (status == STATUS_BUFFER_OVERFLOW && !visible_rect);
}

/* Get the position of a client window and what is visible of it: the server
 * clips it by its parents and, as far as the window styles ask for it, by the
 * siblings above it and its parents. Must be called without the window data
 * lock. The window must still be one of the source process, a window handle
 * may get reused for a window of another process. */
static void remote_sink_get_geometry(HWND hwnd, DWORD pid, struct remote_geometry *geometry)
{
    DWORD window_pid;
    HWND toplevel;

    memset(geometry, 0, sizeof(*geometry));
    if (!NtUserGetWindowThread(hwnd, &window_pid) || window_pid != pid) return;
    if (!get_window_visible_rect(hwnd, &toplevel, &geometry->window_rect, &geometry->visible_rect)) return;
    if (!get_window_visible_rect(toplevel, &toplevel, &geometry->toplevel_rect, NULL)) return;
    geometry->toplevel = toplevel;
}

/* get the part of a buffer which is visible, for a viewport */
static void get_visible_source(UINT size, int start, int end, int visible_start, int visible_end,
                               wl_fixed_t *pos, wl_fixed_t *len)
{
    double scale = (double)size / (end - start);
    wl_fixed_t max = wl_fixed_from_int(size);

    *pos = wl_fixed_from_double((visible_start - start) * scale);
    *pos = max(0, min(*pos, max - 1));
    *len = wl_fixed_from_double((visible_end - start) * scale);
    *len = max(1, min(*len, max) - *pos);
}

static void remote_sink_attach(struct remote_sink *sink, int buffer)
{
    if (buffer == -1)
    {
        wl_surface_attach(sink->wl_surface, NULL, 0, 0);
        sink->attached_width = sink->attached_height = 0;
        return;
    }
    wl_surface_attach(sink->wl_surface, sink->buffers[buffer], 0, 0);
    wl_surface_damage_buffer(sink->wl_surface, 0, 0, sink->width, sink->height);
    sink->busy |= 1u << buffer;
    sink->attached_width = sink->width;
    sink->attached_height = sink->height;
}

/* Update a sink to the state of its source, and to the geometry of the
 * client window if it has been queried. */
static void remote_sink_update(struct remote_sink *sink, const struct remote_geometry *new_geometry)
{
    const struct remote_geometry *geometry = &sink->geometry;
    BOOL commit = FALSE, place = !!new_geometry;
    struct wayland_surface *surface = NULL;
    struct wayland_win_data *data;
    struct remote_shared config;
    RECT rect = {0};
    UINT index;

    if (!remote_sink_get_config(sink, &config)) return;
    if (config.generation != sink->generation) remote_sink_set_buffers(sink, &config);

    if (new_geometry)
    {
        sink->geometry = *new_geometry;
        /* the client window may have been moved to another toplevel of the process */
        if (geometry->toplevel && geometry->toplevel != sink->toplevel)
        {
            TRACE("sink=%p toplevel=%p=>%p\n", sink, sink->toplevel, geometry->toplevel);
            if (sink->wl_subsurface) wl_subsurface_destroy(sink->wl_subsurface);
            sink->wl_subsurface = NULL;
            sink->toplevel = geometry->toplevel;
        }
    }

    if ((data = wayland_win_data_get(sink->toplevel))) surface = data->wayland_surface;

    if (surface && geometry->toplevel == sink->toplevel && !IsRectEmpty(&geometry->visible_rect) &&
        !IsRectEmpty(&geometry->window_rect) && !IsRectEmpty(&geometry->toplevel_rect))
    {
        /* The surface is relative to the visible rect of the toplevel, in
         * the coordinates of the driver, which may be scaled. */
        const RECT *client = &data->rects.client, *top = &geometry->toplevel_rect;
        double scale_x = (double)(client->right - client->left) / (top->right - top->left);
        double scale_y = (double)(client->bottom - client->top) / (top->bottom - top->top);

        rect.left = round((geometry->visible_rect.left - top->left) * scale_x);
        rect.top = round((geometry->visible_rect.top - top->top) * scale_y);
        rect.right = round((geometry->visible_rect.right - top->left) * scale_x);
        rect.bottom = round((geometry->visible_rect.bottom - top->top) * scale_y);
        OffsetRect(&rect, client->left - data->rects.visible.left, client->top - data->rects.visible.top);
        rect = map_rect_to_surface(surface, rect);
        /* limit the position to what the protocol can express */
        if (rect.left < -SHRT_MAX || rect.top < -SHRT_MAX || rect.right > SHRT_MAX || rect.bottom > SHRT_MAX)
            SetRectEmpty(&rect);
    }

    if (IsRectEmpty(&rect))
    {
        if (sink->wl_subsurface)
        {
            TRACE("sink=%p hidden\n", sink);
            /* the surface is unmapped with its role */
            wl_subsurface_destroy(sink->wl_subsurface);
            sink->wl_subsurface = NULL;
            remote_sink_attach(sink, -1);
            wl_surface_commit(sink->wl_surface);
        }
        goto done;
    }

    if (!sink->wl_subsurface)
    {
        if (!(sink->wl_subsurface = wl_subcompositor_get_subsurface(process_wayland.wl_subcompositor,
                                                                    sink->wl_surface, surface->wl_surface)))
            goto done;
        wl_subsurface_set_desync(sink->wl_subsurface);
        SetRectEmpty(&sink->rect);
        /* show the last frame again */
        remote_sink_attach(sink, sink->current);
        commit = place = TRUE;
    }

    /* The source needs a buffer to draw to, besides the frame in the
     * mailbox: don't take a third one while the compositor has not released
     * two of them, the latest frame is taken when it does. */
    if ((sink->waiting = __builtin_popcount(sink->busy) >= 2)) index = 0;
    else index = mailbox_get(InterlockedExchange(&sink->shared->ready, 0), sink->generation);
    if (index && index <= REMOTE_BUFFER_COUNT && sink->buffers[index - 1])
    {
        /* the visible part depends on the size of the buffer */
        if (sink->attached_width != sink->width || sink->attached_height != sink->height) place = TRUE;
        sink->current = index - 1;
        remote_sink_attach(sink, sink->current);
        commit = TRUE;
    }

    if (place)
    {
        if (!EqualRect(&rect, &sink->rect))
        {
            TRACE("sink=%p rect=%s\n", sink, wine_dbgstr_rect(&rect));

            wl_subsurface_set_position(sink->wl_subsurface, rect.left, rect.top);
            /* like the client surfaces of the process, below its popup windows */
            wl_subsurface_place_above(sink->wl_subsurface, surface->wl_surface);
            sink->rect = rect;
            /* the position is applied with the state of the parent */
            wl_surface_commit(surface->wl_surface);
        }
        wp_viewport_set_destination(sink->wp_viewport, rect.right - rect.left, rect.bottom - rect.top);
        /* The source must be inside of the buffer that the surface has
         * when it is committed, or the compositor ends the connection. */
        if (sink->attached_width)
        {
            wl_fixed_t x, y, width, height;

            get_visible_source(sink->attached_width, geometry->window_rect.left, geometry->window_rect.right,
                               geometry->visible_rect.left, geometry->visible_rect.right, &x, &width);
            get_visible_source(sink->attached_height, geometry->window_rect.top, geometry->window_rect.bottom,
                               geometry->visible_rect.top, geometry->visible_rect.bottom, &y, &height);
            wp_viewport_set_source(sink->wp_viewport, x, y, width, height);
        }
        commit = TRUE;
    }

    if (commit) wl_surface_commit(sink->wl_surface);

done:
    if (data) wayland_win_data_release(data);
}

/**********************************************************************
 *          wayland_remote_sink_create
 *
 * Show the client surface of a window of another process in the toplevel
 * window that it is in. Any process can post the message for it.
 */
void wayland_remote_sink_create(HWND toplevel, HWND hwnd, UINT handle)
{
    OBJECT_ATTRIBUTES attr = {.Length = sizeof(attr)};
    SIZE_T view_size = sizeof(struct remote_shared);
    SECTION_BASIC_INFORMATION info;
    struct remote_sink *sink, *other;
    struct wl_region *region;
    HANDLE section, wake;
    UINT count = 0;
    struct stat st;
    CLIENT_ID cid;
    DWORD pid;

    TRACE("toplevel=%p hwnd=%p handle=%#x\n", toplevel, hwnd, handle);

    /* A process only gets to show the client surface of a window of its
     * own, where that window is: the source is the process of the window,
     * whoever posted the message. */
    if (!NtUserGetWindowThread(hwnd, &pid) || pid == GetCurrentProcessId() ||
        NtUserGetAncestor(hwnd, GA_ROOT) != toplevel)
    {
        WARN("Window %p is not a window of another process in toplevel %p\n", hwnd, toplevel);
        return;
    }

    if (!(sink = calloc(1, sizeof(*sink)))) return;
    sink->toplevel = toplevel;
    sink->hwnd = hwnd;
    sink->pid = pid;
    sink->wake_fd = -1;
    sink->current = -1;
    sink->dirty = TRUE;

    cid.UniqueProcess = UlongToHandle(pid);
    cid.UniqueThread = 0;
    if (NtOpenProcess(&sink->process, PROCESS_DUP_HANDLE, &attr, &cid))
    {
        sink->process = 0;
        goto err;
    }

    if (!(section = remote_sink_get_handle(sink->process, handle))) goto err;
    if (NtQuerySection(section, SectionBasicInformation, &info, sizeof(info), NULL) ||
        info.Size.QuadPart < sizeof(struct remote_shared) ||
        NtMapViewOfSection(section, GetCurrentProcess(), (void **)&sink->shared, 0, 0, NULL, &view_size,
                           ViewUnmap, 0, PAGE_READWRITE))
        sink->shared = NULL;
    NtClose(section);
    if (!sink->shared) goto err;
    /* it must be the control block of a source for this window, before it is written to */
    if (ReadNoFence((LONG *)&sink->shared->magic) != REMOTE_MAGIC ||
        ReadNoFence((LONG *)&sink->shared->hwnd) != HandleToULong(hwnd))
        goto err;

    if (!(wake = remote_sink_get_handle(sink->process, ReadNoFence((LONG *)&sink->shared->wake)))) goto err;
    if (wine_server_handle_to_fd(wake, FILE_READ_DATA, &sink->wake_fd, NULL)) sink->wake_fd = -1;
    NtClose(wake);
    /* the event thread polls it and must never block reading from it */
    if (sink->wake_fd == -1 || fstat(sink->wake_fd, &st) || !S_ISSOCK(st.st_mode)) goto err;
    fcntl(sink->wake_fd, F_SETFD, FD_CLOEXEC);

    if (!(sink->wl_surface = wl_compositor_create_surface(process_wayland.wl_compositor))) goto err;
    wl_surface_set_user_data(sink->wl_surface, toplevel);
    /* the frames are read back from OpenGL, with the bottom row first */
    wl_surface_set_buffer_transform(sink->wl_surface, WL_OUTPUT_TRANSFORM_FLIPPED_180);
    /* let the toplevel handle all pointer events */
    if (!(region = wl_compositor_create_region(process_wayland.wl_compositor))) goto err;
    wl_surface_set_input_region(sink->wl_surface, region);
    wl_region_destroy(region);
    if (!(sink->wp_viewport = wp_viewporter_get_viewport(process_wayland.wp_viewporter, sink->wl_surface)))
        goto err;

    wayland_win_data_lock();
    LIST_FOR_EACH_ENTRY(other, &sinks, struct remote_sink, entry) if (other->pid == pid) count++;
    if (count >= REMOTE_MAX_PROCESS_SINKS)
    {
        wayland_win_data_unlock();
        goto err;
    }
    list_add_tail(&sinks, &sink->entry);
    InterlockedIncrement(&sink_count);
    /* the source can close its handle to the socket */
    WriteNoFence(&sink->shared->attached, 1);
    wayland_win_data_unlock();

    /* the event thread does the first update */
    remote_sinks_wake();
    return;

err:
    WARN("Failed to create a sink for window %p of process %04x in toplevel %p\n", hwnd, (UINT)pid, toplevel);
    if (sink->wp_viewport) wp_viewport_destroy(sink->wp_viewport);
    if (sink->wl_surface) wl_surface_destroy(sink->wl_surface);
    if (sink->wake_fd != -1) close(sink->wake_fd);
    if (sink->shared) NtUnmapViewOfSection(GetCurrentProcess(), sink->shared);
    if (sink->process) NtClose(sink->process);
    free(sink);
}

/**********************************************************************
 *          wayland_remote_sinks_detach
 *
 * Detach the sinks from the surface of a toplevel window which is destroyed.
 */
void wayland_remote_sinks_detach(HWND hwnd)
{
    struct remote_sink *sink;
    BOOL wake = FALSE;

    if (!sink_count) return;

    wayland_win_data_lock();
    LIST_FOR_EACH_ENTRY(sink, &sinks, struct remote_sink, entry)
    {
        if (sink->toplevel != hwnd) continue;
        if (sink->wl_subsurface) wl_subsurface_destroy(sink->wl_subsurface);
        sink->wl_subsurface = NULL;
        wake = sink->dirty = TRUE;
    }
    wayland_win_data_unlock();

    if (wake) remote_sinks_wake();
}

/**********************************************************************
 *          wayland_remote_sinks_update
 *
 * Update the sinks of a toplevel window after its surface, or the position,
 * visibility or order of one of the windows in it, has changed.
 */
void wayland_remote_sinks_update(HWND hwnd)
{
    struct remote_sink *sink;
    BOOL wake = FALSE;

    if (!sink_count) return;

    wayland_win_data_lock();
    LIST_FOR_EACH_ENTRY(sink, &sinks, struct remote_sink, entry)
    {
        if (sink->toplevel != hwnd) continue;
        wake = sink->dirty = TRUE;
    }
    wayland_win_data_unlock();

    if (wake) remote_sinks_wake();
}

/**********************************************************************
 *          wayland_remote_window_changed
 *
 * Update the sinks for a window that has changed in a way which isn't a
 * change of its position. Must not be called with the window data locked.
 */
void wayland_remote_window_changed(HWND hwnd)
{
    if (!sink_count) return;
    wayland_remote_sinks_update(NtUserGetAncestor(hwnd, GA_ROOT));
}

/**********************************************************************
 *          wayland_remote_sinks_destroy
 *
 * Destroy the sinks of a window, either the toplevel or the client window.
 */
void wayland_remote_sinks_destroy(HWND hwnd)
{
    struct remote_sink *sink;
    BOOL wake = FALSE;

    if (!sink_count) return;

    wayland_win_data_lock();
    LIST_FOR_EACH_ENTRY(sink, &sinks, struct remote_sink, entry)
    {
        if (sink->toplevel != hwnd && sink->hwnd != hwnd) continue;
        /* hide it now, the event thread does the rest */
        if (sink->wl_subsurface) wl_subsurface_destroy(sink->wl_subsurface);
        sink->wl_subsurface = NULL;
        wake = sink->dead = TRUE;
    }
    wayland_win_data_unlock();

    if (wake) remote_sinks_wake();
}

/**********************************************************************
 *          wayland_remote_get_poll_fds
 *
 * Get the file descriptors that the event thread waits on, with the ones of
 * the sinks after the first which is left for the caller.
 */
struct pollfd *wayland_remote_get_poll_fds(int *count)
{
    struct pollfd *fds = sinks_pollfds;
    struct remote_sink *sink;
    int size;

    pthread_once(&sinks_once, remote_sinks_init);

    fds[1].fd = sinks_fd;
    fds[1].events = POLLIN;
    *count = 2;
    if (!sink_count) return fds;

    wayland_win_data_lock();
    if ((size = 2 + sink_count) > sinks_pollfds_size && (fds = malloc(size * 2 * sizeof(*fds))))
    {
        fds[1] = sinks_pollfds[1];
        if (sinks_pollfds != sinks_initial_pollfds) free(sinks_pollfds);
        sinks_pollfds = fds;
        sinks_pollfds_size = size * 2;
    }
    fds = sinks_pollfds;

    LIST_FOR_EACH_ENTRY(sink, &sinks, struct remote_sink, entry)
    {
        if (*count == sinks_pollfds_size) break;
        fds[*count].fd = sink->wake_fd;
        fds[(*count)++].events = POLLIN;
    }
    wayland_win_data_unlock();

    return fds;
}

/* Read all the wakes of a source, they stand for a single update. Returns
 * FALSE when the source is gone. */
static BOOL remote_sink_read_wakes(struct remote_sink *sink, BOOL *update)
{
    char buffer[4096];
    ssize_t ret;
    UINT i;

    /* a source which keeps sending is left for the next round */
    for (i = 0; i < 64; i++)
    {
        if ((ret = recv(sink->wake_fd, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0) *update = TRUE;
        else if (!ret || (errno != EAGAIN && errno != EINTR)) return FALSE;
        if (ret < (ssize_t)sizeof(buffer)) break;
    }
    return TRUE;
}

/**********************************************************************
 *          wayland_remote_process_events
 *
 * Process the events of the sinks, in the event thread: each sink is
 * updated once at most, the events of the display come before the next ones.
 */
void wayland_remote_process_events(const struct pollfd *fds, int count)
{
    struct remote_sink *sink, *next;
    struct remote_geometry geometry;
    UINT64 value;
    HWND hwnd;
    DWORD pid;
    LONG seq;
    int i;

    if (fds[1].revents && read(sinks_fd, &value, sizeof(value)) == -1) WARN("Failed to read the event\n");

    if (!sink_count) return;

    wayland_win_data_lock();
    /* Only this thread removes sinks from the list, so the next one is
     * still there after the lock has been released for a sink. */
    LIST_FOR_EACH_ENTRY_SAFE(sink, next, &sinks, struct remote_sink, entry)
    {
        BOOL update = sink->dirty || sink->update;

        sink->update = FALSE;
        for (i = 2; i < count; i++)
        {
            if (fds[i].fd != sink->wake_fd || !fds[i].revents) continue;
            if (!remote_sink_read_wakes(sink, &update)) sink->dead = TRUE;
            break;
        }

        if (sink->dead)
        {
            remote_sink_destroy(sink);
            continue;
        }
        if (!update) continue;

        seq = ReadNoFence(&sink->shared->seq);
        if (!sink->dirty && seq == sink->seq)
        {
            remote_sink_update(sink, NULL);
            continue;
        }

        /* A window has changed, here or in the process of the source. Ask
         * the server without the lock, like everything outside the driver. */
        hwnd = sink->hwnd;
        pid = sink->pid;
        sink->seq = seq;
        sink->dirty = FALSE;
        wayland_win_data_unlock();
        remote_sink_get_geometry(hwnd, pid, &geometry);
        wayland_win_data_lock();

        next = LIST_ENTRY(sink->entry.next, struct remote_sink, entry);
        if (sink->dead) remote_sink_destroy(sink);
        else remote_sink_update(sink, &geometry);
    }
    wayland_win_data_unlock();

    wl_display_flush(process_wayland.wl_display);
}
