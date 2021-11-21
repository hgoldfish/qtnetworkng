/****************************************************************************
**
** Copyright (C) 2017 The Qt Company Ltd.
** Copyright (C) 2017 Intel Corporation.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#ifndef QNETWORKINTERFACE_UNIX_P_H
#define QNETWORKINTERFACE_UNIX_P_H

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API. It exists purely as an
// implementation detail. This header file may change from version to
// version without notice, or even be removed.
//
// We mean it.
//

#include "../../include/private/network_interface_p.h"

#define IP_MULTICAST    // make AIX happy and define IFF_MULTICAST

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#ifdef Q_OS_SOLARIS
#  include <sys/sockio.h>
#endif
#ifdef Q_OS_HAIKU
#  include <sys/sockio.h>
#  define IFF_RUNNING 0x0001
#endif


// VxWorks' headers specify 'int' instead of '...' for the 3rd ioctl() parameter.
template <typename T>
static inline int qt_safe_ioctl(int sockfd, unsigned long request, T arg)
{
#ifdef Q_OS_VXWORKS
    return ::ioctl(sockfd, request, (int) arg);
#else
    return ::ioctl(sockfd, request, arg);
#endif
}

static inline int qt_safe_socket(int domain, int type, int protocol, int flags = 0)
{
    Q_ASSERT((flags & ~O_NONBLOCK) == 0);
    int fd;
#ifdef QT_THREADSAFE_CLOEXEC
    int newtype = type | SOCK_CLOEXEC;
    if (flags & O_NONBLOCK)
        newtype |= SOCK_NONBLOCK;
    fd = ::socket(domain, newtype, protocol);
    return fd;
#else
    fd = ::socket(domain, type, protocol);
    if (fd == -1)
        return -1;
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    // set non-block too?
    if (flags & O_NONBLOCK)
        ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
#endif
}

#define EINTR_LOOP(var, cmd)                    \
    do {                                        \
        var = cmd;                              \
    } while (var == -1 && errno == EINTR)

static inline int qt_safe_close(int fd)
{
    int ret;
    EINTR_LOOP(ret, ::close(fd));
    return ret;
}


QTNETWORKNG_NAMESPACE_BEGIN

static NetworkInterface::InterfaceFlags convertFlags(uint rawFlags)
{
    NetworkInterface::InterfaceFlags flags;
    flags |= (rawFlags & IFF_UP) ? NetworkInterface::IsUp : NetworkInterface::InterfaceFlag(0);
    flags |= (rawFlags & IFF_RUNNING) ? NetworkInterface::IsRunning : NetworkInterface::InterfaceFlag(0);
    flags |= (rawFlags & IFF_BROADCAST) ? NetworkInterface::CanBroadcast : NetworkInterface::InterfaceFlag(0);
    flags |= (rawFlags & IFF_LOOPBACK) ? NetworkInterface::IsLoopBack : NetworkInterface::InterfaceFlag(0);
#ifdef IFF_POINTOPOINT //cygwin doesn't define IFF_POINTOPOINT
    flags |= (rawFlags & IFF_POINTOPOINT) ? NetworkInterface::IsPointToPoint : NetworkInterface::InterfaceFlag(0);
#endif

#ifdef IFF_MULTICAST
    flags |= (rawFlags & IFF_MULTICAST) ? NetworkInterface::CanMulticast : NetworkInterface::InterfaceFlag(0);
#endif
    return flags;
}

QTNETWORKNG_NAMESPACE_END

#endif // QNETWORKINTERFACE_UNIX_P_H
