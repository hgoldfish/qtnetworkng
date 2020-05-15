/*
 * libev epoll fd activity backend
 *
 * Copyright (c) 2007,2008,2009,2010,2011 Marc Alexander Lehmann <libev@schmorp.de>
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

/*
 * general notes about epoll:
 *
 * a) epoll silently removes fds from the fd set. as nothing tells us
 *    that an fd has been removed otherwise, we have to continually
 *    "rearm" fds that we suspect *might* have changed (same
 *    problem with kqueue, but much less costly there).
 * b) the fact that ADD != MOD creates a lot of extra syscalls due to a)
 *    and seems not to have any advantage.
 * c) the inability to handle fork or file descriptors (think dup)
 *    limits the applicability over poll, so this is not a generic
 *    poll replacement.
 * d) epoll doesn't work the same as select with many file descriptors
 *    (such as files). while not critical, no other advanced interface
 *    seems to share this (rather non-unixy) limitation.
 * e) epoll claims to be embeddable, but in practise you never get
 *    a ready event for the epoll fd (broken: <=2.6.26, working: >=2.6.32).
 * f) epoll_ctl returning EPERM means the fd is always ready.
 *
 * lots of "weird code" and complication handling in this file is due
 * to these design problems with epoll, as we try very hard to avoid
 * epoll_ctl syscalls for common usage patterns and handle the breakage
 * ensuing from receiving events for closed and otherwise long gone
 * file descriptors.
 */

#include <sys/epoll.h>

#define EV_EMASK_EPERM 0x80

static void epoll_modify(struct ev_loop *loop, int fd, int oev, int nev)
{
    struct epoll_event ev;
    unsigned char oldmask;

    /*
    * we handle EPOLL_CTL_DEL by ignoring it here
    * on the assumption that the fd is gone anyways
    * if that is wrong, we have to handle the spurious
    * event in epoll_poll.
    * if the fd is added again, we try to ADD it, and, if that
    * fails, we assume it still has the same eventmask.
    */
    if (!nev) {
        return;
    }

    oldmask = loop->anfds[fd].emask;
    loop->anfds[fd].emask = nev;

    /* store the generation counter in the upper 32 bits, the fd in the lower 32 bits */
    ev.data.u64 = (uint64_t)(uint32_t)fd | ((uint64_t)(uint32_t)++loop->anfds[fd].egen << 32);
    ev.events   = (nev & EV_READ  ? EPOLLIN  : 0)
                | (nev & EV_WRITE ? EPOLLOUT : 0);

    if (expect_true(!epoll_ctl(loop->backend_fd, oev && oldmask != nev ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &ev))) {
        return;
    }

    if (expect_true(errno == ENOENT)) {
        /* if ENOENT then the fd went away, so try to do the right thing */
        if (!nev) {
            goto dec_egen;
        }

        if (!epoll_ctl(loop->backend_fd, EPOLL_CTL_ADD, fd, &ev)) {
            return;
        }
    } else if (expect_true(errno == EEXIST)) {
      /* EEXIST means we ignored a previous DEL, but the fd is still active */
      /* if the kernel mask is the same as the new mask, we assume it hasn't changed */
        if (oldmask == nev) {
            goto dec_egen;
        }

        if (!epoll_ctl(loop->backend_fd, EPOLL_CTL_MOD, fd, &ev)) {
            return;
        }
    } else if (expect_true (errno == EPERM)) {
        /* EPERM means the fd is always ready, but epoll is too snobbish */
        /* to handle it, unlike select or poll. */
        loop->anfds[fd].emask = EV_EMASK_EPERM;

        /* add fd to epoll_eperms, if not already inside */
        if (!(oldmask & EV_EMASK_EPERM)) {
            array_needsize(int, loop->epoll_eperms, loop->epoll_epermmax, loop->epoll_epermcnt + 1, EMPTY2);
            loop->epoll_eperms[loop->epoll_epermcnt++] = fd;
        }
        return;
    }
    fd_kill(loop, fd);

dec_egen:
    /* we didn't successfully call epoll_ctl, so decrement the generation counter again */
    --loop->anfds[fd].egen;
}

static void epoll_poll(struct ev_loop *loop, ev_tstamp timeout)
{
    int i;
    int eventcnt;

    if (expect_false(loop->epoll_epermcnt)) {
        timeout = 0.;
    }

    /* epoll wait times cannot be larger than (LONG_MAX - 999UL) / HZ msecs, which is below */
    /* the default libev max wait time, however. */
    eventcnt = epoll_wait(loop->backend_fd, loop->epoll_events, loop->epoll_eventmax, timeout * 1e3);

    if (expect_false(eventcnt < 0)) {
        if (errno != EINTR) {
            ev_syserr("(libev) epoll_wait");
        }
        return;
    }

    for (i = 0; i < eventcnt; ++i) {
        struct epoll_event *ev = loop->epoll_events + i;

        int fd = (uint32_t)ev->data.u64; /* mask out the lower 32 bits */
        int want = loop->anfds[fd].events;
        int got  = (ev->events & (EPOLLOUT | EPOLLERR | EPOLLHUP) ? EV_WRITE : 0)
                 | (ev->events & (EPOLLIN  | EPOLLERR | EPOLLHUP) ? EV_READ  : 0);

        /*
        * check for spurious notification.
        * this only finds spurious notifications on egen updates
        * other spurious notifications will be found by epoll_ctl, below
        * we assume that fd is always in range, as we never shrink the anfds array
        */
        if (expect_false((uint32_t)loop->anfds[fd].egen != (uint32_t)(ev->data.u64 >> 32))) {
            /* recreate kernel state */
            loop->postfork |= 2;
            continue;
        }

        if (expect_false (got & ~want)) {
            loop->anfds[fd].emask = want;

            /*
            * we received an event but are not interested in it, try mod or del
            * this often happens because we optimistically do not unregister fds
            * when we are no longer interested in them, but also when we get spurious
            * notifications for fds from another process. this is partially handled
            * above with the gencounter check (== our fd is not the event fd), and
            * partially here, when epoll_ctl returns an error (== a child has the fd
            * but we closed it).
            */
            ev->events = (want & EV_READ  ? EPOLLIN  : 0)
                       | (want & EV_WRITE ? EPOLLOUT : 0);

            /* pre-2.6.9 kernels require a non-null pointer with EPOLL_CTL_DEL, */
            /* which is fortunately easy to do for us. */
            if (epoll_ctl(loop->backend_fd, want ? EPOLL_CTL_MOD : EPOLL_CTL_DEL, fd, ev)) {
                loop->postfork |= 2; /* an error occurred, recreate kernel state */
                continue;
            }
        }

        fd_event(loop, fd, got);
    }

    /* if the receive array was full, increase its size */
    if (expect_false(eventcnt == loop->epoll_eventmax)) {
        ev_free(loop->epoll_events);
        loop->epoll_eventmax = array_nextsize(sizeof(struct epoll_event), loop->epoll_eventmax, loop->epoll_eventmax + 1);
        loop->epoll_events = (struct epoll_event *) ev_malloc(sizeof(struct epoll_event) * loop->epoll_eventmax);
    }

    /* now synthesize events for all fds where epoll fails, while select works... */
    for (i = loop->epoll_epermcnt; i--; ) {
        int fd = loop->epoll_eperms[i];
        unsigned char events = loop->anfds[fd].events & (EV_READ | EV_WRITE);

        if (loop->anfds[fd].emask & EV_EMASK_EPERM && events) {
            fd_event(loop, fd, events);
        } else {
            loop->epoll_eperms[i] = loop->epoll_eperms[--loop->epoll_epermcnt];
            loop->anfds[fd].emask = 0;
        }
    }
}


static int epoll_init(struct ev_loop *loop)
{
#if defined EPOLL_CLOEXEC && !defined __ANDROID__
    loop->backend_fd = epoll_create1(EPOLL_CLOEXEC);

    if (loop->backend_fd < 0 && (errno == EINVAL || errno == ENOSYS))
#endif
        loop->backend_fd = epoll_create(256);

    if (loop->backend_fd < 0) {
        return 0;
    }

    fcntl(loop->backend_fd, F_SETFD, FD_CLOEXEC);

    loop->backend_mintime = 1e-3; /* epoll does sometimes return early, this is just to avoid the worst */
    loop->backend_modify  = epoll_modify;
    loop->backend_poll    = epoll_poll;

    loop->epoll_eventmax = 64; /* initial number of events receivable per poll */
    loop->epoll_events = (struct epoll_event *)ev_malloc(sizeof(struct epoll_event) * loop->epoll_eventmax);

    return EVBACKEND_EPOLL;
}


static void epoll_destroy(struct ev_loop *loop)
{
    ev_free(loop->epoll_events);
    array_free(loop->epoll_eperm, EMPTY);
}


static void epoll_fork(struct ev_loop *loop)
{
    close(loop->backend_fd);

    while ((loop->backend_fd = epoll_create(256)) < 0) {
        ev_syserr ("(libev) epoll_create");
    }

    fcntl(loop->backend_fd, F_SETFD, FD_CLOEXEC);

    fd_rearm_all(loop);
}
