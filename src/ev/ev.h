/*
 * libev native API header
 *
 * Copyright (c) 2007-2018 Marc Alexander Lehmann <libev@schmorp.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifica-
 * tion, are permitted provided that the following conditions are met:
 *
 *   1.  Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *   2.  Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MER-
 * CHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPE-
 * CIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTH-
 * ERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * the GNU General Public License ("GPL") version 2 or any later version,
 * in which case the provisions of the GPL are applicable instead of
 * the above. If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use your
 * version of this file under the BSD license, indicate your decision
 * by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL. If you do not delete the
 * provisions above, a recipient may use your version of this file under
 * either the BSD or the GPL.
 */

#ifndef QTNG_EV_H
#define QTNG_EV_H

#include <signal.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef double ev_tstamp;
#define EV_ATOMIC_T sig_atomic_t volatile
struct ev_loop;
/* these priorities are inclusive, higher priorities will be invoked earlier */
#define EV_MINPRI -2
#define EV_MAXPRI +2

/* eventmask, revents, events... */
enum {
#ifdef __cplusplus
    EV_UNDEF    = static_cast<int>(0xFFFFFFFF), /* guaranteed to be invalid */
#else
    EV_UNDEF    = (int)0xFFFFFFFF, /* guaranteed to be invalid */
#endif
    EV_NONE     =            0x00, /* no events */
    EV_READ     =            0x01, /* ev_io detected read will not block */
    EV_WRITE    =            0x02, /* ev_io detected write will not block */
    EV__IOFDSET =            0x80, /* internal use only */
    EV_IO       =         EV_READ, /* alias for type-detection */
    EV_TIMER    =      0x00000100, /* timer timed out */
    EV_ASYNC    =      0x00080000, /* async intra-loop signal */
    EV_CUSTOM   =      0x01000000, /* for use by user code */
#ifdef __cplusplus
    EV_ERROR    = static_cast<int>(0x80000000)  /* sent when an error occurs */
#else
    EV_ERROR    = (int)0x80000000  /* sent when an error occurs */
#endif
};


#define EV_CB_DECLARE(type) void (*cb)(struct ev_loop* loop, struct type *w, int revents);
#define EV_CB_INVOKE(watcher,revents) (watcher)->cb(loop, (watcher), (revents))
/* shared by all watchers */
#define EV_WATCHER(type)                 \
    int active;                  /* private */        \
    int pending;                 /* private */        \
    int priority;                /* private */        \
    int dummy;                                        \
    void *data;                  /* rw */             \
    EV_CB_DECLARE (type)         /* private */

#define EV_WATCHER_LIST(type)                         \
    EV_WATCHER(type)                                  \
    struct ev_watcher_list *next; /* private */

#define EV_WATCHER_TIME(type)                         \
    EV_WATCHER(type)                                  \
    ev_tstamp at;     /* private */


/* base class, nothing to see here unless you subclass */
typedef struct ev_watcher
{
    EV_WATCHER(ev_watcher)
} ev_watcher;


/* base class, nothing to see here unless you subclass */
typedef struct ev_watcher_list
{
    EV_WATCHER_LIST(ev_watcher_list)
} ev_watcher_list;


/* base class, nothing to see here unless you subclass */
typedef struct ev_watcher_time
{
  EV_WATCHER_TIME(ev_watcher_time)
} ev_watcher_time;


typedef struct ev_io
{
    EV_WATCHER_LIST(ev_io)
    int fd;     /* ro */
    int events; /* ro */
} ev_io;


typedef struct ev_timer
{
    EV_WATCHER_TIME(ev_timer)
    ev_tstamp repeat; /* rw */
} ev_timer;


typedef struct ev_async
{
    EV_WATCHER (ev_async)
    EV_ATOMIC_T sent; /* private */
} ev_async;

# define ev_async_pending(w) (+(w)->sent)


/* the presence of this union forces similar struct layout */
union ev_any_watcher
{
    struct ev_watcher w;
    struct ev_watcher_list wl;
    struct ev_io io;
    struct ev_timer timer;
    struct ev_async async;
};


/* flag bits for ev_default_loop and ev_loop_new */
enum {
    EVFLAG_AUTO      = 0x00000000U, /* not quite a mask */
    EVFLAG_NOENV     = 0x01000000U, /* do NOT consult environment */
};

enum {
    EVBACKEND_POLL    = 0x00000002U, /* !win, !aix, broken on osx */
    EVBACKEND_EPOLL   = 0x00000004U, /* linux */
    EVBACKEND_KQUEUE  = 0x00000008U, /* bsd, broken on osx */
    EVBACKEND_ALL     = 0x0000003FU, /* all known backends */
    EVBACKEND_MASK    = 0x0000FFFFU  /* all future backends */
};


enum {
    EVBREAK_CANCEL = 0, /* undo unloop */
    EVBREAK_ONE    = 1, /* unloop once */
    EVBREAK_ALL    = 2  /* unloop all loops */
};


ev_tstamp ev_time();
struct ev_loop *ev_loop_new (unsigned int flags);
ev_tstamp ev_now(struct ev_loop* loop);
void ev_loop_destroy(struct ev_loop* loop);
int  ev_run (struct ev_loop* loop, int flags);
void ev_break (struct ev_loop* loop, int how);

#define ev_init(ev,cb_) do {                      \
    ((ev_watcher *)(void *)(ev))->active  = 0;    \
    ((ev_watcher *)(void *)(ev))->pending = 0;    \
    ev_set_priority((ev), 0);                     \
    ev_set_cb((ev), cb_);                         \
} while (0)

#define ev_io_set(ev,fd_,events_)                 \
    do { (ev)->fd = (fd_); (ev)->events = (events_) | EV__IOFDSET; } while (0)
#define ev_timer_set(ev,after_,repeat_)           \
    do { ((ev_watcher_time *)(ev))->at = (after_); (ev)->repeat = (repeat_); } while (0)
#define ev_async_set(ev)

#define ev_io_init(ev,cb,fd,events)               \
    do { ev_init((ev), (cb)); ev_io_set((ev),(fd),(events)); } while (0)
#define ev_timer_init(ev,cb,after,repeat)         \
    do { ev_init ((ev), (cb)); ev_timer_set((ev),(after),(repeat)); } while (0)
#define ev_async_init(ev,cb)                      \
    do { ev_init((ev), (cb)); ev_async_set((ev)); } while (0)

#define ev_is_pending(ev)                    (0 + ((ev_watcher *)(void *)(ev))->pending) /* ro, true when watcher is waiting for callback invocation */
#define ev_is_active(ev)                     (0 + ((ev_watcher *)(void *)(ev))->active) /* ro, true when the watcher has been started */

#define ev_priority(ev)                     (+(((ev_watcher *)(void *)(ev))->priority))
#define ev_set_priority(ev,pri)             (   (ev_watcher *)(void *)(ev))->priority = (pri)

#define ev_cb_(ev)                          (ev)->cb /* rw */
#define ev_set_cb(ev,cb_)                   (ev_cb_ (ev) = (cb_), memmove (&((ev_watcher *)(ev))->cb, &ev_cb_ (ev), sizeof (ev_cb_ (ev))))

void ev_io_start(struct ev_loop *loop, ev_io *w);
void ev_io_stop(struct ev_loop *loop, ev_io *w);
void ev_timer_start(struct ev_loop *loop, ev_timer *w);
void ev_timer_stop(struct ev_loop *loop, ev_timer *w);
void ev_timer_again(struct ev_loop *loop, ev_timer *w);
ev_tstamp ev_timer_remaining (struct ev_loop *loop, ev_timer *w);
void ev_async_start(struct ev_loop *loop, ev_async *w);
void ev_async_stop(struct ev_loop *loop, ev_async *w);
void ev_async_send(struct ev_loop *loop, ev_async *w);

#ifdef __cplusplus
} // extern "C"
#endif  // #ifdef __cplusplus
#endif
