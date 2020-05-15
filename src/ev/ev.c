/*
 * libev event processing core, watcher management
 *
 * Copyright (c) 2007,2008,2009,2010,2011,2012,2013 Marc Alexander Lehmann <libev@schmorp.de>
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


#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <math.h>
#include <unistd.h>
#include "ev.h"
#include "ecb.h"

#if EV_USE_EVENTFD
#include <sys/eventfd.h>
#endif

#define expect_false(cond) ecb_expect_false (cond)
#define expect_true(cond)  ecb_expect_true  (cond)

/*
 * This is used to work around floating point rounding problems.
 * This value is good at least till the year 4000.
 */
#define MIN_INTERVAL  0.0001220703125 // 1/2**13, good till 4000
#define MIN_TIMEJUMP  1. /* minimum timejump that gets detected (if monotonic clock available) */
#define MAX_BLOCKTIME 59.743 /* never wait longer than this time (to detect time jumps) */
#define ev_floor(v) floor (v)
#define NUMPRI (EV_MAXPRI - EV_MINPRI + 1)
#define ABSPRI(w) (((ev_watcher *) w)->priority - EV_MINPRI)
#define EMPTY       /* required for microsofts broken pseudo-c compiler */
#define EMPTY2(a,b) do {(void)(a);(void)(b);} while (0);    /* used to suppress some warnings */
#define EVBREAK_RECURSE 0x80


ev_tstamp ev_time()
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}


static ev_tstamp get_clock()
{
    struct timespec ts;
#ifdef CLOCK_BOOTTIME
    clock_gettime(CLOCK_BOOTTIME, &ts);
#elif defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
#elif defined(CLOCK_REALTIME)
    clock_gettime(CLOCK_REALTIME, &ts);
#else
    return ev_time();  // TODO support macos?
#endif
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}


static void ev_sleep(ev_tstamp delay)
{
    if (delay > 0.) {
        struct timespec ts;
        ts.tv_sec = (long) delay;
        ts.tv_nsec = (long) ((delay - ts.tv_sec) * 1e9);
        nanosleep(&ts, 0);
    }
}


static void ev_printerr (const char *msg)
{
    write(STDERR_FILENO, msg, strlen(msg));
}


static void ev_syserr(const char *msg)
{
    if (!msg)
        msg = "(libev) system error";
    ev_printerr(msg);
    ev_printerr(": ");
    ev_printerr(strerror(errno));
    ev_printerr("\n");
    abort ();
}

static void *ev_realloc_emul(void *ptr, size_t size)
{
    /* some systems, notably openbsd and darwin, fail to properly
    * implement realloc (x, 0) (as required by both ansi c-89 and
    * the single unix specification, so work around them here.
    * recently, also (at least) fedora and debian started breaking it,
    * despite documenting it otherwise.
    */
    if (size) {
        return realloc(ptr, size);
    } else {
        free(ptr);
        return 0;
    }
}


static void *ev_realloc(void *ptr, int size)
{
    ptr = ev_realloc_emul(ptr, (size_t)size);
    if (!ptr && size) {
        ev_printerr("(libev) memory allocation failed, aborting.\n");
        abort ();
    }
    return ptr;
}


#define MALLOC_ROUND   4096
#define PTR_SIZE       ((int)(sizeof(void *)))

static int array_nextsize(int elem, int cur, int cnt)
{
    int ncur = cur + 1;
    do {
        ncur <<= 1;
    } while (cnt > ncur);
    /* if size is large, round to MALLOC_ROUND - 4 * longs to accommodate malloc overhead */
    if (elem * ncur > MALLOC_ROUND - PTR_SIZE * 4) {
        ncur *= elem;
        ncur = (ncur + elem + (MALLOC_ROUND - 1) + PTR_SIZE * 4) & ~(MALLOC_ROUND - 1);
        ncur = ncur - PTR_SIZE * 4;
        ncur /= elem;
    }
    return ncur;
}


static void *array_realloc(int elem, void *base, int *cur, int cnt)
{
    *cur = array_nextsize(elem, *cur, cnt);
    return ev_realloc(base, elem * (*cur));
}


#define ev_malloc(size) ev_realloc(0, (size))
#define ev_free(ptr)    ev_realloc((ptr), 0)
#define array_init_zero(base,count)                        \
    memset((void *)(base), 0, sizeof(*(base)) * ((size_t)count))
#define array_needsize(type,base,cur,cnt,init)             \
    if (expect_false((cnt) > (cur))) {                     \
        int ocur_ = (cur);                                 \
        (base) = (type *)array_realloc                     \
           (((int)sizeof(type)), (base), &(cur), (cnt));          \
        init((base) + (ocur_), (cur) - ocur_);             \
    }
#define array_free(stem, idx) \
    ev_free (stem ## s idx); stem ## cnt idx = stem ## max idx = 0; stem ## s idx = 0


#define ev_active(w) ((ev_watcher *)(w))->active
#define ev_at(w) ((ev_watcher_time *)(w))->at

#define EV_ANFD_REIFY 1
/* file descriptor info structure */
typedef struct
{
  ev_watcher_list *head;
  unsigned char events; /* the events watched for */
  unsigned char reify;  /* flag set when this ANFD needs reification (EV_ANFD_REIFY, EV__IOFDSET) */
  unsigned char emask;  /* the epoll backend stores the actual kernel mask in here */
  unsigned char unused;
#if EV_USE_EPOLL
  unsigned int egen;    /* generation counter to counter epoll bugs */
#else
  unsigned int dummy;
#endif
} ANFD;

/* stores the pending event set for a given watcher */
typedef struct
{
  ev_watcher *w;
  int events; /* the pending event set for the given watcher */
  int dummy;
} ANPENDING;

/* a heap element */
typedef struct {
    ev_tstamp at;
    ev_watcher_time *w;
} ANHE;

#define ANHE_w(he)        (he).w     /* access watcher, read-write */
#define ANHE_at(he)       (he).at    /* access cached at, read-only */
#define ANHE_at_cache(he) (he).at = (he).w->at /* update at from watcher */


struct ev_loop
{
    ev_tstamp ev_rt_now;

    ev_tstamp now_floor;            /* last time we refreshed rt_time */
    ev_tstamp mn_now;               /* monotonic clock "now" */
    ev_tstamp rtmn_diff;            /* difference realtime - monotonic time */

    /* for reverse feeding of events */
    ev_watcher **rfeeds;
    int rfeedmax;
    int rfeedcnt;

    ANPENDING *pendings[NUMPRI];
    int pendingmax[NUMPRI];
    int pendingcnt[NUMPRI];
    int pendingpri;                  /* highest priority currently pending */
    int dummy;
    ev_watcher pending_w;            /* dummy pending watcher */

    ev_tstamp io_blocktime;
    ev_tstamp timeout_blocktime;

    int backend;
    int activecnt;                   /* total number of active events ("refcount") */
    EV_ATOMIC_T loop_done;           /* signal by ev_break */

    int backend_fd;
    ev_tstamp backend_mintime;       /* assumed typical timer resolution */
    void (*backend_modify)(struct ev_loop* loop, int fd, int oev, int nev);
    void (*backend_poll)(struct ev_loop* loop, ev_tstamp timeout);

    ANFD *anfds;
    int anfdmax;

    int evpipe[2];
    int postfork;                    /* true if we need to recreate kernel state after fork */
    ev_io pipe_w;
    EV_ATOMIC_T pipe_write_wanted;
    EV_ATOMIC_T pipe_write_skipped;



    #if EV_USE_POLL
    struct pollfd * polls;
    int pollmax;
    int pollcnt;
    int *pollidxs;                /* maps fds into structure indices */
    int pollidxmax;
    int dummy3;
    #endif

    #if EV_USE_EPOLL
    struct epoll_event *epoll_events;
    int epoll_eventmax;
    int dummy4;
    int *epoll_eperms;
    int epoll_epermcnt;
    int epoll_epermmax;
    #endif

    #if EV_USE_KQUEUE
    pid_t kqueue_fd_pid;
    struct kevent *kqueue_changes;
    int kqueue_changemax;
    int kqueue_changecnt;
    struct kevent *kqueue_events;
    int kqueue_eventmax;
    int dummy5;
    #endif

    int *fdchanges;
    int fdchangemax;
    int fdchangecnt;

    ANHE *timers;
    int timermax;
    int timercnt;

    EV_ATOMIC_T async_pending;
    int dummy6;
    ev_async **asyncs;
    int asyncmax;
    int asynccnt;

    unsigned int loop_count;      /* total number of loop iterations/blocks */
    unsigned int loop_depth;      /* #ev_run enters - #ev_run leaves */
};


void ev_ref(struct ev_loop *loop)
{
    ++loop->activecnt;
}


void ev_unref(struct ev_loop *loop)
{
    --loop->activecnt;
}

ev_tstamp ev_now(struct ev_loop *loop)
{
    return loop->ev_rt_now;
}


static void pendingcb(struct ev_loop *loop, ev_watcher *w, int revents)
{
    (void) loop;
    (void) w;
    (void) revents;
}


static void ev_feed_event(struct ev_loop* loop, void *w, int revents)
{
    ev_watcher *w_ = (ev_watcher *)w;
#if QTNG_EV_ASSERT
    assert (("libev: ev_feed_event called with invalid callback.", w_->cb != 0));
#endif
    int pri = ABSPRI(w_);

    if (expect_false(w_->pending)) {
        loop->pendings[pri][w_->pending - 1].events |= revents;
    } else {
        w_->pending = ++loop->pendingcnt[pri];
        array_needsize(ANPENDING, loop->pendings[pri], loop->pendingmax[pri], w_->pending, EMPTY2);
        loop->pendings[pri][w_->pending - 1].w      = w_;
        loop->pendings[pri][w_->pending - 1].events = revents;
    }
    loop->pendingpri = NUMPRI - 1;
}


static void feed_reverse(struct ev_loop *loop, ev_watcher *w)
{
    array_needsize(ev_watcher *, loop->rfeeds, loop->rfeedmax, loop->rfeedcnt + 1, EMPTY2);
#if QTNG_EV_ASSERT
    assert (("libev: feed_reverse called with invalid callback.", w->cb != 0));
#endif
    loop->rfeeds[loop->rfeedcnt++] = w;
}


static void feed_reverse_done(struct ev_loop *loop, int revents)
{
    do {
        ev_feed_event(loop, loop->rfeeds[--loop->rfeedcnt], revents);
    } while (loop->rfeedcnt);
}


static void queue_events(struct ev_loop* loop, ev_watcher **events, int eventcnt, int type)
{
    int i;

    for (i = 0; i < eventcnt; ++i) {
        ev_feed_event(loop, events[i], type);
    }
}


static void fd_event_nocheck(struct ev_loop* loop, int fd, int revents)
{
    ANFD *anfd = loop->anfds + fd;
    ev_io *w;

    for (w = (ev_io *)anfd->head; w; w = (ev_io *)((ev_watcher_list *)w)->next) {
        int ev = w->events & revents;

        if (ev) {
            ev_feed_event(loop, (ev_watcher*)w, ev);
        }
    }
}


void fd_event(struct ev_loop* loop, int fd, int revents)
{
    ANFD *anfd = loop->anfds + fd;

    if (expect_true(!anfd->reify)) {
        fd_event_nocheck(loop, fd, revents);
    }
}


void ev_feed_fd_event(struct ev_loop* loop, int fd, int revents)
{
    if (fd >= 0 && fd < loop->anfdmax) {
        fd_event_nocheck(loop, fd, revents);
    }
}


/* make sure the external fd watch events are in-sync */
/* with the kernel/libev internal state */
static void fd_reify(struct ev_loop *loop)
{
    int i;
    ev_io *w;

    for (i = 0; i < loop->fdchangecnt; ++i) {
        int fd = loop->fdchanges[i];
        ANFD *anfd = loop->anfds + fd;

        unsigned char o_events = anfd->events;
        unsigned char o_reify  = anfd->reify;

        anfd->reify  = 0;

        /*if (expect_true (o_reify & EV_ANFD_REIFY)) probably a deoptimisation */
        {
            anfd->events = 0;

            for (w = (ev_io *) anfd->head; w; w = (ev_io *)w->next) {
                anfd->events |= (unsigned char)w->events;
            }

            if (o_events != anfd->events) {
                o_reify = EV__IOFDSET; /* actually |= */
            }
        }

        if (o_reify & EV__IOFDSET) {
            loop->backend_modify(loop, fd, o_events, anfd->events);
        }
    }
    loop->fdchangecnt = 0;
}


/* something about the given fd changed */
static void fd_change(struct ev_loop *loop, int fd, int flags)
{
    unsigned char reify = loop->anfds[fd].reify;
    loop->anfds[fd].reify |= flags;

    if (expect_true(!reify)) {
        ++loop->fdchangecnt;
        array_needsize(int, loop->fdchanges, loop->fdchangemax, loop->fdchangecnt, EMPTY2);
        loop->fdchanges[loop->fdchangecnt - 1] = fd;
    }
}


/* the given fd is invalid/unusable, so make sure it doesn't hurt us anymore */
static void fd_kill(struct ev_loop *loop, int fd)
{
    ev_io *w;

    while ((w = (ev_io *) loop->anfds[fd].head)) {
        ev_io_stop(loop, w);
        ev_feed_event(loop, (ev_watcher *) w, EV_ERROR | EV_READ | EV_WRITE);
    }
}


/* check whether the given fd is actually valid, for error recovery */
static int fd_valid (int fd)
{
    return fcntl(fd, F_GETFD) != -1;
}


/* called on EBADF to verify fds */
static void fd_ebadf(struct ev_loop *loop)
{
    int fd;

    for (fd = 0; fd < loop->anfdmax; ++fd) {
        if (loop->anfds[fd].events) {
            if (!fd_valid(fd) && errno == EBADF) {
                fd_kill(loop, fd);
            }
        }
    }
}


/* called on ENOMEM in select/poll to kill some fds and retry */
static void fd_enomem(struct ev_loop *loop)
{
    int fd;

    for (fd = loop->anfdmax; fd--; ) {
        if (loop->anfds[fd].events) {
            fd_kill(loop, fd);
            break;
        }
    }
}


/* usually called after fork if backend needs to re-arm all fds from scratch */
static void fd_rearm_all(struct ev_loop *loop)
{
    int fd;

    for (fd = 0; fd < loop->anfdmax; ++fd) {
        if (loop->anfds[fd].events) {
            loop->anfds[fd].events = 0;
            loop->anfds[fd].emask  = 0;
            fd_change(loop, fd, EV__IOFDSET | EV_ANFD_REIFY);
        }
    }
}


/* used to prepare libev internal fd's */
/* this is not fork-safe */
static void fd_intern(int fd)
{
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  fcntl(fd, F_SETFL, O_NONBLOCK);
}

/*
 * the heap functions want a real array index. array index 0 is guaranteed to not
 * be in-use at any time. the first heap entry is at array [HEAP0]. DHEAP gives
 * the branching factor of the d-tree.
 */

/*
 * at the moment we allow libev the luxury of two heaps,
 * a small-code-size 2-heap one and a ~1.5kb larger 4-heap
 * which is more cache-efficient.
 * the difference is about 5% with 50000+ watchers.
 */

#if EV_USE_4HEAP

#define DHEAP 4
#define HEAP0 (DHEAP - 1) /* index of first element in heap */
#define HPARENT(k) ((((k) - HEAP0 - 1) / DHEAP) + HEAP0)
#define UPHEAP_DONE(p,k) ((p) == (k))

/* away from the root */
static void downheap(ANHE *heap, int N, int k)
{
    ANHE he = heap[k];
    ANHE *E = heap + N + HEAP0;

    for (;;) {
        ev_tstamp minat;
        ANHE *minpos;
        ANHE *pos = heap + DHEAP * (k - HEAP0) + HEAP0 + 1;

        /* find minimum child */
        if (expect_true(pos + DHEAP - 1 < E)) {
            /* fast path */                             { (minpos = pos + 0); (minat = ANHE_at(*minpos)); }
            if (               ANHE_at(pos[1]) < minat) { (minpos = pos + 1); (minat = ANHE_at(*minpos)); }
            if (               ANHE_at(pos[2]) < minat) { (minpos = pos + 2); (minat = ANHE_at(*minpos)); }
            if (               ANHE_at(pos[3]) < minat) { (minpos = pos + 3); (minat = ANHE_at(*minpos)); }
        } else if (pos < E) {
            /* slow path */                             { (minpos = pos + 0); (minat = ANHE_at(*minpos)); }
            if (pos + 1 < E && ANHE_at(pos[1]) < minat) { (minpos = pos + 1); (minat = ANHE_at(*minpos)); }
            if (pos + 2 < E && ANHE_at(pos[2]) < minat) { (minpos = pos + 2); (minat = ANHE_at(*minpos)); }
            if (pos + 3 < E && ANHE_at(pos[3]) < minat) { (minpos = pos + 3); (minat = ANHE_at(*minpos)); }
        } else {
            break;
        }

        if (ANHE_at(he) <= minat) {
            break;
        }

        heap[k] = *minpos;
        ev_active(ANHE_w(*minpos)) = k;

        k = (int) (minpos - heap);
    }

    heap[k] = he;
    ev_active(ANHE_w(he)) = k;
}

#else /* 4HEAP */

#define HEAP0 1
#define HPARENT(k) ((k) >> 1)
#define UPHEAP_DONE(p,k) (!(p))

/* away from the root */
static void downheap(ANHE *heap, int N, int k)
{
    ANHE he = heap[k];

    for (;;) {
        int c = k << 1;

        if (c >= N + HEAP0) {
            break;
        }

        c += c + 1 < N + HEAP0 && ANHE_at(heap[c]) > ANHE_at(heap[c + 1]) ? 1 : 0;

        if (ANHE_at(he) <= ANHE_at(heap[c])) {
            break;
        }

        heap[k] = heap[c];
        ev_active(ANHE_w(heap[k])) = k;

        k = c;
    }

    heap[k] = he;
    ev_active(ANHE_w(he)) = k;
}

#endif

/* towards the root */
static void upheap(ANHE *heap, int k)
{
    ANHE he = heap[k];

    for (;;) {
        int p = HPARENT(k);

        if (UPHEAP_DONE(p, k) || ANHE_at(heap[p]) <= ANHE_at(he)) {
            break;
        }

        heap[k] = heap[p];
        ev_active(ANHE_w(heap[k])) = k;
        k = p;
    }

    heap[k] = he;
    ev_active(ANHE_w(he)) = k;
}


/* move an element suitably so it is in a correct place */
static void adjustheap(ANHE *heap, int N, int k)
{
    if (k > HEAP0 && ANHE_at(heap[k]) <= ANHE_at(heap[HPARENT(k)])) {
        upheap(heap, k);
    } else {
        downheap(heap, N, k);
    }
}


/* rebuild the heap: this function is used only once and executed rarely */
static void reheap(ANHE *heap, int N)
{
    int i;

    /* we don't use floyds algorithm, upheap is simpler and is more cache-efficient */
    /* also, this is easy to implement and correct for both 2-heaps and 4-heaps */
    for (i = 0; i < N; ++i) {
        upheap(heap, i + HEAP0);
    }
}


static void evpipe_init(struct ev_loop *loop)
{
    if (!ev_is_active(&loop->pipe_w)) {
        int fds [2];

# if EV_USE_EVENTFD
        fds[0] = -1;
        fds[1] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (fds[1] < 0 && errno == EINVAL) {
            fds[1] = eventfd(0, 0);
        }
        if (fds[1] < 0)
# endif
        {
            while(pipe(fds)) {
                ev_syserr("(libev) error creating signal/async pipe");
            }
            fd_intern(fds[0]);
        }
        loop->evpipe[0] = fds[0];
        if (loop->evpipe[1] < 0) {
            loop->evpipe[1] = fds[1]; /* first call, set write fd */
        } else {
            /* on subsequent calls, do not change evpipe[1] */
            /* so that evpipe_write can always rely on its value. */
            /* this branch does not do anything sensible on windows, */
            /* so must not be executed on windows */
            dup2(fds[1], loop->evpipe[1]);
            close(fds[1]);
        }
        fd_intern(loop->evpipe[1]);

        ev_io_set(&loop->pipe_w, loop->evpipe[0] < 0 ? loop->evpipe[1] : loop->evpipe[0], EV_READ);
        ev_io_start(loop, &loop->pipe_w);
        ev_unref(loop); /* watcher should not keep loop alive */
    }
}


static void evpipe_write(struct ev_loop* loop, EV_ATOMIC_T *flag)
{
    ECB_MEMORY_FENCE; /* push out the write before this function was called, acquire flag */

    if (expect_true(*flag)) {
        return;
    }

    *flag = 1;
    ECB_MEMORY_FENCE_RELEASE; /* make sure flag is visible before the wakeup */

    loop->pipe_write_skipped = 1;

    ECB_MEMORY_FENCE; /* make sure pipe_write_skipped is visible before we check pipe_write_wanted */

    if (loop->pipe_write_wanted) {
        int old_errno;

        loop->pipe_write_skipped = 0;
        ECB_MEMORY_FENCE_RELEASE;

        old_errno = errno; /* save errno because write will clobber it */

#if EV_USE_EVENTFD
        if (loop->evpipe[0] < 0) {
            uint64_t counter = 1;
            write(loop->evpipe[1], &counter, sizeof(uint64_t));
        } else
#endif
        {
            write(loop->evpipe[1], &(loop->evpipe[1]), 1);
        }

        errno = old_errno;
    }
}


/* called whenever the libev signal pipe */
/* got some events (signal, async) */
static void pipecb(struct ev_loop *loop, ev_io *iow, int revents)
{
    int i;
    (void)iow;
    if (revents & EV_READ) {
#if EV_USE_EVENTFD
        if (loop->evpipe[0] < 0) {
            uint64_t counter;
            read (loop->evpipe[1], &counter, sizeof(uint64_t));
        } else
#endif
        {
          char dummy[4];
          read (loop->evpipe[0], &dummy, sizeof(dummy));
        }
    }

    loop->pipe_write_skipped = 0;

    ECB_MEMORY_FENCE; /* push out skipped, acquire flags */

    if (loop->async_pending) {
        loop->async_pending = 0;

        ECB_MEMORY_FENCE;

        for (i = loop->asynccnt; i--; ) {
            if (loop->asyncs[i]->sent) {
                loop->asyncs[i]->sent = 0;
                ECB_MEMORY_FENCE_RELEASE;
                ev_feed_event(loop, loop->asyncs[i], EV_ASYNC);
            }
        }
    }
}

/*****************************************************************************/


#if EV_USE_KQUEUE
# include "ev_kqueue.c"
#endif
#if EV_USE_EPOLL
# include "ev_epoll.c"
#endif
#if EV_USE_POLL
# include "ev_poll.c"
#endif


unsigned int ev_depth(struct ev_loop *loop)
{
    return loop->loop_depth;
}


static unsigned int ev_backend(struct ev_loop *loop)
{
    return (unsigned int ) loop->backend;
}


static void loop_init (struct ev_loop *loop, unsigned int flags)
{
    (void) flags;
    if (!loop->backend) {
        loop->ev_rt_now          = ev_time();
        loop->mn_now             = get_clock();
        loop->now_floor          = loop->mn_now;
        loop->rtmn_diff          = loop->ev_rt_now - loop->mn_now;

        loop->io_blocktime       = 0.;
        loop->timeout_blocktime  = 0.;
        loop->backend            = 0;
        loop->backend_fd         = -1;
        loop->async_pending      = 0;
        loop->pipe_write_skipped = 0;
        loop->pipe_write_wanted  = 0;
        loop->evpipe[0]          = -1;
        loop->evpipe[1]          = -1;
#if EV_USE_KQUEUE
        loop->backend = kqueue_init(loop);
#endif
#if EV_USE_EPOLL
        loop->backend = epoll_init(loop);
#endif
#if EV_USE_POLL
        loop->backend = poll_init(loop);
#endif
    }
    ev_init(&loop->pending_w, pendingcb);
    ev_init(&loop->pipe_w, pipecb);
    ev_set_priority (&loop->pipe_w, EV_MAXPRI);
}


void ev_loop_destroy(struct ev_loop *loop)
{
    int i;
    if (!loop) {
        return;
    }

    if (ev_is_active(&loop->pipe_w)) {
        if (loop->evpipe[0] >= 0) close(loop->evpipe[0]);
        if (loop->evpipe[1] >= 0) close(loop->evpipe[1]);
    }

    if (loop->backend_fd >= 0) {
        close(loop->backend_fd);
    }
#if EV_USE_KQUEUE
    if (loop->backend == EVBACKEND_KQUEUE) kqueue_destroy(loop);
#endif
#if EV_USE_EPOLL
    if (loop->backend == EVBACKEND_EPOLL ) epoll_destroy(loop);
#endif
#if EV_USE_POLL
    if (loop->backend == EVBACKEND_POLL  ) poll_destroy(loop);
#endif

    for (i = NUMPRI; i--; ) {
        ev_free(loop->pendings[i]);
        loop->pendingcnt[i] = loop->pendingmax[i] = 0;
        loop->pendings[i] = 0;
    }

    ev_free(loop->anfds);
    loop->anfds = 0;
    loop->anfdmax = 0;

    ev_free(loop->rfeeds);
    loop->rfeedcnt = loop->rfeedmax = 0;
    loop->rfeeds = 0;

    ev_free(loop->fdchanges);
    loop->fdchangecnt = loop->rfeedmax = 0;
    loop->fdchanges = 0;

    ev_free(loop->timers);
    loop->timercnt = loop->timermax = 0;
    loop->timers = 0;

    ev_free(loop->asyncs);
    loop->asynccnt = loop->asyncmax = 0;
    loop->asyncs = 0;

    loop->backend = 0;
    ev_free(loop);
}


void loop_fork(struct ev_loop *loop)
{
#if EV_USE_KQUEUE
    if (backend == EVBACKEND_KQUEUE) kqueue_fork(loop);
#endif
#if EV_USE_EPOLL
    if (loop->backend == EVBACKEND_EPOLL ) epoll_fork(loop);
#endif

    if (ev_is_active (&loop->pipe_w) && loop->postfork != 2) {
        /* pipe_write_wanted must be false now, so modifying fd vars should be safe */

        ev_ref(loop);
        ev_io_stop(loop, &loop->pipe_w);

        if (loop->evpipe [0] >= 0) {
            close(loop->evpipe [0]);
        }

        evpipe_init(loop);
        /* iterate over everything, in case we missed something before */
        ev_feed_event(loop, &loop->pipe_w, EV_CUSTOM);
    }

    loop->postfork = 0;
}


struct ev_loop *ev_loop_new(unsigned int flags)
{
    struct ev_loop *loop = (struct ev_loop *) ev_malloc(sizeof(struct ev_loop));

    memset(loop, 0, sizeof(struct ev_loop));
    loop_init(loop, flags);

    if (ev_backend(loop)) {
        return loop;
    }

    ev_free(loop);
    return 0;
}

#if EV_VERIFY

static void verify_watcher(struct ev_loop* loop, ev_watcher *w)
{
    assert (("libev: watcher has invalid priority", ABSPRI(w) >= 0 && ABSPRI(w) < NUMPRI));

    if (w->pending) {
        assert (("libev: pending watcher not on pending queue", loop->pendings[ABSPRI(w)][w->pending - 1].w == w));
    }
}


static void verify_heap(struct ev_loop* loop, ANHE *heap, int N)
{
    int i;

    for (i = HEAP0; i < N + HEAP0; ++i) {
        assert (("libev: active index mismatch in heap", ev_active(ANHE_w(heap[i])) == i));
        assert (("libev: heap condition violated", i == HEAP0 || ANHE_at(heap[HPARENT(i)]) <= ANHE_at(heap[i])));
        assert (("libev: heap at cache mismatch", ANHE_at(heap[i]) == ev_at(ANHE_w(heap[i]))));
        verify_watcher(loop, (ev_watcher*) ANHE_w(heap[i]));
    }
}


static void array_verify(struct ev_loop* loop, ev_watcher **ws, int cnt)
{
    while (cnt--) {
        assert (("libev: active index mismatch", ev_active(ws[cnt]) == cnt + 1));
        verify_watcher(loop, ws[cnt]);
    }
}


static void ev_verify(struct ev_loop* loop)
{
    int i;
    int j;
    ev_watcher_list *w, *w2;

    assert (loop->activecnt >= -1);

    assert (loop->fdchangemax >= loop->fdchangecnt);
    for (i = 0; i < loop->fdchangecnt; ++i) {
        assert (("libev: negative fd in fdchanges", loop->fdchanges[i] >= 0));
    }

    assert (loop->anfdmax >= 0);
    for (i = 0; i < loop->anfdmax; ++i) {
        j = 0;

        for (w = w2 = loop->anfds[i].head; w; w = w->next) {
            verify_watcher(loop, (ev_watcher *) w);

            if (j++ & 1) {
                assert (("libev: io watcher list contains a loop", w != w2));
                w2 = w2->next;
            }

            assert (("libev: inactive fd watcher on anfd list", ev_active(w) == 1));
            assert (("libev: fd mismatch between watcher and anfd", ((ev_io *)w)->fd == i));
        }
    }

    assert(loop->timermax >= loop->timercnt);
    verify_heap(loop, loop->timers, loop->timercnt);

    for (i = NUMPRI; i--; ) {
        assert (loop->pendingmax[i] >= loop->pendingcnt [i]);
    }

    assert(loop->asyncmax >= loop->asynccnt);
    array_verify(loop, (ev_watcher **)loop->asyncs, loop->asynccnt);
}


#endif

static void ev_invoke(struct ev_loop* loop, void *w, int revents)
{
    ((ev_watcher *) w)->cb(loop, ((ev_watcher *)w), revents);
}


static unsigned int ev_pending_count(struct ev_loop *loop)
{
    int pri;
    unsigned int count = 0;

    for (pri = NUMPRI; pri--; ) {
        count += (unsigned int)loop->pendingcnt[pri];
    }

    return count;
}


static void ev_invoke_pending(struct ev_loop *loop)
{
    loop->pendingpri = NUMPRI;

    while (loop->pendingpri) { /* pendingpri possibly gets modified in the inner loop */
        --loop->pendingpri;
        while (loop->pendingcnt[loop->pendingpri]) {
            ANPENDING *p = loop->pendings[loop->pendingpri] + --loop->pendingcnt[loop->pendingpri];
            p->w->pending = 0;
            p->w->cb(loop, p->w, p->events);
        }
    }
}


static void timers_reify(struct ev_loop *loop)
{
    if (loop->timercnt && ANHE_at(loop->timers[HEAP0]) < loop->mn_now) {
        do {
            ev_timer *w = (ev_timer *) ANHE_w(loop->timers[HEAP0]);

            /*assert (("libev: inactive timer on timer heap detected", ev_is_active (w)));*/

            /* first reschedule or stop timer */
            if (w->repeat != 0.0) {
                ev_at(w) += w->repeat;
                if (ev_at(w) < loop->mn_now) {
                    ev_at(w) = loop->mn_now;
                }
#if QTNG_EV_ASSERT
                assert (("libev: negative ev_timer repeat value found while processing timers", w->repeat > 0.));
#endif

                ANHE_at_cache(loop->timers[HEAP0]);
                downheap(loop->timers, loop->timercnt, HEAP0);
            } else {
                ev_timer_stop(loop, w); /* nonrepeating: stop timer */
            }
            feed_reverse(loop, (ev_watcher*) w);
        } while (loop->timercnt && (ANHE_at(loop->timers[HEAP0]) < loop->mn_now));

        feed_reverse_done(loop, EV_TIMER);
    }
}


/* fetch new monotonic and realtime times from the kernel */
/* also detect if there was a timejump, and act accordingly */
static void time_update(struct ev_loop* loop, ev_tstamp max_block)
{
    (void) max_block;
    int i;
    ev_tstamp odiff = loop->rtmn_diff;

    loop->mn_now = get_clock();

    /* only fetch the realtime clock every 0.5*MIN_TIMEJUMP seconds */
    /* interpolate in the meantime */
    if (expect_true(loop->mn_now - loop->now_floor < MIN_TIMEJUMP * .5)) {
        loop->ev_rt_now = loop->rtmn_diff + loop->mn_now;
        return;
    }

    loop->now_floor = loop->mn_now;
    loop->ev_rt_now = ev_time();

    /* loop a few times, before making important decisions.
    * on the choice of "4": one iteration isn't enough,
    * in case we get preempted during the calls to
    * ev_time and get_clock. a second call is almost guaranteed
    * to succeed in that case, though. and looping a few more times
    * doesn't hurt either as we only do this on time-jumps or
    * in the unlikely event of having been preempted here.
    */
    for (i = 4; --i; ) {
        ev_tstamp diff;
        loop->rtmn_diff = loop->ev_rt_now - loop->mn_now;

        diff = odiff - loop->rtmn_diff;

        if (expect_true ((diff < 0. ? -diff : diff) < MIN_TIMEJUMP))
            return; /* all is well */

        loop->ev_rt_now = ev_time ();
        loop->mn_now    = get_clock ();
        loop->now_floor = loop->mn_now;
    }
}

int ev_run(struct ev_loop* loop, int flags)
{
    (void) flags;
    ++loop->loop_depth;

#if QTNG_EV_ASSERT
    assert (("libev: ev_loop recursion during release detected", loop->loop_done != EVBREAK_RECURSE));
#endif

    loop->loop_done = EVBREAK_CANCEL;

    ev_invoke_pending(loop); /* in case we recurse, ensure ordering stays nice and clean */

    do {
#if EV_VERIFY
        ev_verify(loop);
#endif
        /* we might have forked, so queue fork handlers */
        if (expect_false(loop->loop_done)) {
            break;
        }
        /* we might have forked, so reify kernel state if necessary */
        if (expect_false(loop->postfork)) {
            loop_fork(loop);
        }
        fd_reify(loop);

        /* calculate blocking time */
        {
            ev_tstamp waittime  = 0.;
            ev_tstamp sleeptime = 0.;

            /* remember old timestamp for io_blocktime calculation */
            ev_tstamp prev_mn_now = loop->mn_now;

            /* update time to cancel out callback processing overhead */
            time_update(loop, 1e100);

            /* from now on, we want a pipe-wake-up */
            loop->pipe_write_wanted = 1;

            ECB_MEMORY_FENCE; /* make sure pipe_write_wanted is visible before we check for potential skips */

            if (expect_true(loop->activecnt && !loop->pipe_write_skipped)) {
                waittime = MAX_BLOCKTIME;

                if (loop->timercnt) {
                    ev_tstamp to = ANHE_at(loop->timers[HEAP0]) - loop->mn_now;
                    if (waittime > to) {
                        waittime = to;
                    }
                }

                /* don't let timeouts decrease the waittime below timeout_blocktime */
                if (expect_false(waittime < loop->timeout_blocktime)) {
                    waittime = loop->timeout_blocktime;
                }

                /* at this point, we NEED to wait, so we have to ensure */
                /* to pass a minimum nonzero value to the backend */
                if (expect_false(waittime < loop->backend_mintime)) {
                    waittime = loop->backend_mintime;
                }

                /* extra check because io_blocktime is commonly 0 */
                if (expect_false(loop->io_blocktime != 0.0)) {
                    sleeptime = loop->io_blocktime - (loop->mn_now - prev_mn_now);

                    if (sleeptime > waittime - loop->backend_mintime) {
                        sleeptime = waittime - loop->backend_mintime;
                    }

                    if (expect_true(sleeptime > 0.)) {
                        ev_sleep(sleeptime);
                        waittime -= sleeptime;
                    }
                }
            }

            ++loop->loop_count;
            assert ((loop->loop_done = EVBREAK_RECURSE, 1)); /* assert for side effect */
            loop->backend_poll(loop, waittime);
            assert ((loop->loop_done = EVBREAK_CANCEL, 1)); /* assert for side effect */

            loop->pipe_write_wanted = 0; /* just an optimisation, no fence needed */

            ECB_MEMORY_FENCE_ACQUIRE;
            if (loop->pipe_write_skipped) {
#if QTNG_EV_ASSERT
                assert (("libev: pipe_w not active, but pipe not written", ev_is_active(&loop->pipe_w)));
#endif
                ev_feed_event(loop, &loop->pipe_w, EV_CUSTOM);
            }

            /* update ev_rt_now, do magic */
            time_update(loop, waittime + sleeptime);
        }

        /* queue pending timers and reschedule them */
        timers_reify(loop); /* relative timers called last */

        ev_invoke_pending(loop);
    } while (expect_true(loop->activecnt  && !loop->loop_done));

    if (loop->loop_done == EVBREAK_ONE) {
        loop->loop_done = EVBREAK_CANCEL;
    }

    --loop->loop_depth;
    return loop->activecnt;
}


void ev_break(struct ev_loop* loop, int how)
{
    loop->loop_done = how;
}


void ev_now_update(struct ev_loop *loop)
{
    time_update(loop, 1e100);
}


/*****************************************************************************/
/* singly-linked list management, used when the expected list length is short */
void wlist_add(ev_watcher_list **head, ev_watcher_list *elem)
{
    elem->next = *head;
    *head = elem;
}


void wlist_del(ev_watcher_list **head, ev_watcher_list *elem)
{
    while (*head) {
        if (expect_true(*head == elem)) {
            *head = elem->next;
            break;
        }
        head = &(*head)->next;
    }
}


/* internal, faster, version of ev_clear_pending */
void clear_pending(struct ev_loop *loop, ev_watcher *w)
{
    if (w->pending) {
        loop->pendings[ABSPRI(w)][w->pending - 1].w = &loop->pending_w;
        w->pending = 0;
    }
}


int ev_clear_pending(struct ev_loop* loop, void *w)
{
    ev_watcher *w_ = (ev_watcher*)w;
    int pending = w_->pending;

    if (expect_true(pending)) {
        ANPENDING *p = loop->pendings[ABSPRI(w_)] + pending - 1;
        p->w = (ev_watcher*)&loop->pending_w;
        w_->pending = 0;
        return p->events;
    } else {
        return 0;
    }
}


static void pri_adjust(struct ev_loop* loop, ev_watcher *w)
{
    int pri = ev_priority(w);
    (void)loop;
    pri = pri < EV_MINPRI ? EV_MINPRI : pri;
    pri = pri > EV_MAXPRI ? EV_MAXPRI : pri;
    ev_set_priority(w, pri);
}


static void ev_start(struct ev_loop *loop, ev_watcher *w, int active)
{
    pri_adjust(loop, w);
    w->active = active;
#if QTNG_EV_ASSERT
    assert (("callback is empty.", w->cb != 0));
#endif
    ev_ref(loop);
}


static void ev_stop(struct ev_loop *loop, ev_watcher *w)
{
    ev_unref(loop);
    w->active = 0;
}


/*****************************************************************************/

void ev_io_start(struct ev_loop* loop, ev_io *w)
{
    int fd = w->fd;

    if (expect_false(ev_is_active(w))) {
        return;
    }

#if QTNG_EV_ASSERT
    assert (("libev: ev_io_start called with negative fd", fd >= 0));
    assert (("libev: ev_io_start called with invalid callback.", w->cb != 0));
    assert (("libev: ev_io_start called with illegal event mask", !(w->events & ~(EV__IOFDSET | EV_READ | EV_WRITE))));
#endif

    ev_start(loop, (ev_watcher*)w, 1);
    array_needsize(ANFD, loop->anfds, loop->anfdmax, fd + 1, array_init_zero);
    wlist_add(&loop->anfds[fd].head, (ev_watcher_list *) w);

    /* common bug, apparently */
#if QTNG_EV_ASSERT
    assert (("libev: ev_io_start called with corrupted watcher", ((ev_watcher_list *) w)->next != (ev_watcher_list *) w));
#endif

    fd_change(loop, fd, (w->events & EV__IOFDSET) | EV_ANFD_REIFY);
    w->events &= ~EV__IOFDSET;
}


void ev_io_stop(struct ev_loop* loop, ev_io *w)
{
    clear_pending(loop, (ev_watcher*) w);
    if (expect_false(!ev_is_active(w))) {
        return;
    }

#if QTNG_EV_ASSERT
    assert (("libev: ev_io_stop called with illegal fd (must stay constant after start!)", w->fd >= 0 && w->fd < loop->anfdmax));
#endif
    wlist_del(&loop->anfds[w->fd].head, (ev_watcher_list *) w);
    ev_stop(loop, (ev_watcher *) w);
    fd_change(loop, w->fd, EV_ANFD_REIFY);
}


void ev_timer_start(struct ev_loop* loop, ev_timer *w)
{
    if (expect_false(ev_is_active(w))) {
        return;
    }
    ev_at(w) += loop->mn_now;
#if QTNG_EV_ASSERT
    assert (("libev: ev_timer_start called with negative timer repeat value", w->repeat >= 0.));
    assert (("libev: ev_timer_start called with invalid callback.", w->cb != 0));
#endif
    ++loop->timercnt;
    ev_start(loop, (ev_watcher *) w, loop->timercnt + HEAP0 - 1);
    array_needsize(ANHE, loop->timers, loop->timermax, ev_active(w) + 1, EMPTY2);
    ANHE_w(loop->timers[ev_active(w)]) = (ev_watcher_time *) w;
    ANHE_at_cache(loop->timers[ev_active(w)]);
    upheap(loop->timers, ev_active(w));
    /*assert (("libev: internal timer heap corruption", timers [ev_active (w)] == (WT)w));*/
}


void ev_timer_stop(struct ev_loop* loop, ev_timer *w)
{
    clear_pending(loop, (ev_watcher*)w);
    if (expect_false(!ev_is_active(w))) {
        return;
    }

    {
        int active = ev_active(w);
#if QTNG_EV_ASSERT
        assert (("libev: internal timer heap corruption", ANHE_w(loop->timers[active]) == (ev_watcher_time *) w));
#endif
        --loop->timercnt;

        if (expect_true(active < loop->timercnt + HEAP0)) {
            loop->timers[active] = loop->timers[loop->timercnt + HEAP0];
            adjustheap(loop->timers, loop->timercnt, active);
        }
    }
    ev_at(w) -= loop->mn_now;
    ev_stop(loop, (ev_watcher *) w);
}


void ev_timer_again(struct ev_loop* loop, ev_timer *w)
{
    clear_pending(loop, (ev_watcher *) w);

    if (ev_is_active(w)) {
        if (w->repeat != 0.0) {
            ev_at(w) = loop->mn_now + w->repeat;
            ANHE_at_cache(loop->timers[ev_active(w)]);
            adjustheap(loop->timers, loop->timercnt, ev_active(w));
        } else {
            ev_timer_stop(loop, w);
        }
    } else if (w->repeat != 0.0) {
        ev_at(w) = w->repeat;
        ev_timer_start(loop, w);
    }
}


ev_tstamp ev_timer_remaining (struct ev_loop* loop, ev_timer *w)
{
    return ev_at(w) - (ev_is_active(w) ? loop->mn_now : 0.);
}


void ev_async_start(struct ev_loop* loop, ev_async *w)
{
    if (expect_false(ev_is_active(w))) {
        return;
    }

    w->sent = 0;
    evpipe_init(loop);
    ev_start(loop, (ev_watcher *)w, ++loop->asynccnt);
    array_needsize(ev_async *, loop->asyncs, loop->asyncmax, loop->asynccnt, EMPTY2);
    loop->asyncs[loop->asynccnt - 1] = w;
}


void ev_async_stop(struct ev_loop* loop, ev_async *w)
{
    clear_pending(loop, (ev_watcher*)w);
    if (expect_false(!ev_is_active (w))) {
        return;
    }

    int active = ev_active(w);
    loop->asyncs[active - 1] = loop->asyncs[--loop->asynccnt];
    ev_active(loop->asyncs[active - 1]) = active;
    ev_stop(loop, (ev_watcher*)w);
}


void ev_async_send(struct ev_loop* loop, ev_async *w)
{
    w->sent = 1;
    evpipe_write(loop, &loop->async_pending);
}
