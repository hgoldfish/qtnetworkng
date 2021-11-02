/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
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

#include <QtCore/qatomic.h>
#if QT_VERSION >= QT_VERSION_CHECK(5, 8, 0)
#include <QtCore/qdeadlinetimer.h>
#endif
#include <QtCore/qlist.h>
#include <QtCore/qreadwritelock.h>
#include <QtCore/qstring.h>
#include <QtCore/qdebug.h>
#include "../../include/private/network_interface_p.h"

QTNETWORKNG_NAMESPACE_BEGIN


static QList<NetworkInterfacePrivate *> postProcess(QList<NetworkInterfacePrivate *> list)
{
    // Some platforms report a netmask but don't report a broadcast address
    // Go through all available addresses and calculate the broadcast address
    // from the IP and the netmask
    //
    // This is an IPv4-only thing -- IPv6 has no concept of broadcasts
    // The math is:
    //    broadcast = IP | ~netmask

    for (NetworkInterfacePrivate *interface : list) {
        for (NetworkAddressEntry &address : interface->addressEntries) {
            if (address.ip().protocol() != HostAddress::IPv4Protocol) {
                continue;
            }
            if (!address.netmask().isNull() && address.broadcast().isNull()) {
                HostAddress bcast = address.ip();
                bcast = HostAddress(bcast.toIPv4Address() | ~address.netmask().toIPv4Address());
                address.setBroadcast(bcast);
            }
        }
    }

    return list;
}


Q_GLOBAL_STATIC(NetworkInterfaceManager, manager)
NetworkInterfaceManager::NetworkInterfaceManager() {}
NetworkInterfaceManager::~NetworkInterfaceManager() {}


QSharedDataPointer<NetworkInterfacePrivate> NetworkInterfaceManager::interfaceFromName(const QString &name)
{
    const QList<QSharedDataPointer<NetworkInterfacePrivate> > &interfaceList = allInterfaces();

    bool ok;
    uint index = name.toUInt(&ok);

    for (const QSharedDataPointer<NetworkInterfacePrivate> &interface : interfaceList) {
        if (ok && interface->index == int(index)) {
            return interface;
        } else if (interface->name == name) {
            return interface;
        }
    }

    return empty;
}


QSharedDataPointer<NetworkInterfacePrivate> NetworkInterfaceManager::interfaceFromIndex(int index)
{
    const QList<QSharedDataPointer<NetworkInterfacePrivate> > &interfaceList = allInterfaces();
    for (const QSharedDataPointer<NetworkInterfacePrivate> &interface : interfaceList) {
        if (interface->index == index) {
            return interface;
        }
    }

    return empty;
}


QList<QSharedDataPointer<NetworkInterfacePrivate> > NetworkInterfaceManager::allInterfaces()
{
    const QList<NetworkInterfacePrivate *> list = postProcess(scan());
    QList<QSharedDataPointer<NetworkInterfacePrivate> > result;
    result.reserve(list.size());

    for (NetworkInterfacePrivate *ptr : list) {
        if ((ptr->flags & NetworkInterface::IsUp) == 0) {
            // if the network interface isn't UP, the addresses are ineligible for DNS
            for (NetworkAddressEntry &addr : ptr->addressEntries) {
                addr.setDnsEligibility(NetworkAddressEntry::DnsIneligible);
            }
        }
        result << QSharedDataPointer<NetworkInterfacePrivate>(ptr);
    }

    return result;
}


static inline char toHexUpper(uchar i)
{
    Q_ASSERT(i < 16);
    return "0123456789ABCDEF"[i];
}


QString NetworkInterfacePrivate::makeHwAddress(int len, uchar *data)
{
    const int outLen = qMax(len * 2 + (len - 1) * 1, 0);
    QString result(outLen, Qt::Uninitialized);
    QChar *out = result.data();
    for (int i = 0; i < len; ++i) {
        if (i) {
            *out++ = QLatin1Char(':');
        }
        *out++ = QLatin1Char(toHexUpper(data[i] / 16));
        *out++ = QLatin1Char(toHexUpper(data[i] % 16));
    }
    return result;
}


NetworkAddressEntry::NetworkAddressEntry()
    : d(new NetworkAddressEntryPrivate)
{
}


NetworkAddressEntry::NetworkAddressEntry(const NetworkAddressEntry &other)
    : d(new NetworkAddressEntryPrivate(*other.d.data()))
{
}


NetworkAddressEntry &NetworkAddressEntry::operator=(const NetworkAddressEntry &other)
{
    *d.data() = *other.d.data();
    return *this;
}


NetworkAddressEntry::~NetworkAddressEntry()
{
}


bool NetworkAddressEntry::operator==(const NetworkAddressEntry &other) const
{
    if (d == other.d) return true;
    if (!d || !other.d) return false;
    return d->address == other.d->address &&
        d->netmask == other.d->netmask &&
        d->broadcast == other.d->broadcast;
}


NetworkAddressEntry::DnsEligibilityStatus NetworkAddressEntry::dnsEligibility() const
{
    return d->dnsEligibility;
}


void NetworkAddressEntry::setDnsEligibility(DnsEligibilityStatus status)
{
    d->dnsEligibility = status;
}


HostAddress NetworkAddressEntry::ip() const
{
    return d->address;
}


void NetworkAddressEntry::setIp(const HostAddress &newIp)
{
    d->address = newIp;
}


HostAddress NetworkAddressEntry::netmask() const
{
    return d->netmask.address(d->address.protocol());
}


void NetworkAddressEntry::setNetmask(const HostAddress &newNetmask)
{
    if (newNetmask.protocol() != ip().protocol()) {
        d->netmask = Netmask();
        return;
    }
    d->netmask.setAddress(newNetmask);
}


int NetworkAddressEntry::prefixLength() const
{
    return d->netmask.prefixLength();
}


void NetworkAddressEntry::setPrefixLength(int length)
{
    d->netmask.setPrefixLength(d->address.protocol(), length);
}


HostAddress NetworkAddressEntry::broadcast() const
{
    return d->broadcast;
}


void NetworkAddressEntry::setBroadcast(const HostAddress &newBroadcast)
{
    d->broadcast = newBroadcast;
}


#if QT_VERSION >= QT_VERSION_CHECK(5, 8, 0)

bool NetworkAddressEntry::isLifetimeKnown() const
{
    return d->lifetimeKnown;
}


QDeadlineTimer NetworkAddressEntry::preferredLifetime() const
{
    return d->preferredLifetime;
}


QDeadlineTimer NetworkAddressEntry::validityLifetime() const
{
    return d->validityLifetime;
}


void NetworkAddressEntry::setAddressLifetime(QDeadlineTimer preferred, QDeadlineTimer validity)
{
    d->preferredLifetime = preferred;
    d->validityLifetime = validity;
    d->lifetimeKnown = true;
}


void NetworkAddressEntry::clearAddressLifetime()
{
    d->preferredLifetime = QDeadlineTimer::Forever;
    d->validityLifetime = QDeadlineTimer::Forever;
    d->lifetimeKnown = false;
}


bool NetworkAddressEntry::isPermanent() const
{
    return d->validityLifetime.isForever();
}

#endif // QT_VERSION_CHECK


NetworkInterface::NetworkInterface()
    : d(nullptr)
{
}


NetworkInterface::~NetworkInterface()
{
}


NetworkInterface::NetworkInterface(const NetworkInterface &other)
    : d(other.d)
{
}


NetworkInterface &NetworkInterface::operator=(const NetworkInterface &other)
{
    d = other.d;
    return *this;
}


bool NetworkInterface::isValid() const
{
    return !name().isEmpty();
}


int NetworkInterface::index() const
{
    return d ? d->index : 0;
}


int NetworkInterface::maximumTransmissionUnit() const
{
    return d ? d->mtu : 0;
}


QString NetworkInterface::name() const
{
    return d ? d->name : QString();
}


QString NetworkInterface::humanReadableName() const
{
    return d ? !d->friendlyName.isEmpty() ? d->friendlyName : name() : QString();
}


NetworkInterface::InterfaceFlags NetworkInterface::flags() const
{
    return d ? d->flags : InterfaceFlags();
}


NetworkInterface::InterfaceType NetworkInterface::type() const
{
    return d ? d->type : Unknown;
}


QString NetworkInterface::hardwareAddress() const
{
    return d ? d->hardwareAddress : QString();
}


QList<NetworkAddressEntry> NetworkInterface::addressEntries() const
{
    return d ? d->addressEntries : QList<NetworkAddressEntry>();
}


int NetworkInterface::interfaceIndexFromName(const QString &name)
{
    if (name.isEmpty())
        return 0;

    bool ok;
    uint id = name.toUInt(&ok);
    if (!ok)
        id = NetworkInterfaceManager::interfaceIndexFromName(name);
    return int(id);
}


NetworkInterface NetworkInterface::interfaceFromName(const QString &name)
{
    NetworkInterface result;
    result.d = manager()->interfaceFromName(name);
    return result;
}


NetworkInterface NetworkInterface::interfaceFromIndex(int index)
{
    NetworkInterface result;
    result.d = manager()->interfaceFromIndex(index);
    return result;
}


QString NetworkInterface::interfaceNameFromIndex(int index)
{
    if (!index)
        return QString();
    return NetworkInterfaceManager::interfaceNameFromIndex(index);
}


QList<NetworkInterface> NetworkInterface::allInterfaces()
{
    const QList<QSharedDataPointer<NetworkInterfacePrivate> > privs = manager()->allInterfaces();
    QList<NetworkInterface> result;
    result.reserve(privs.size());
    for (const QSharedDataPointer<NetworkInterfacePrivate> &p : privs) {
        NetworkInterface item;
        item.d = p;
        result << item;
    }

    return result;
}


QList<HostAddress> NetworkInterface::allAddresses()
{
    const QList<QSharedDataPointer<NetworkInterfacePrivate> > privs = manager()->allInterfaces();
    QList<HostAddress> result;
    for (const QSharedDataPointer<NetworkInterfacePrivate> &p : privs) {
        // skip addresses if the interface isn't up
        if ((p->flags & NetworkInterface::IsUp) == 0) {
            continue;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        for (const NetworkAddressEntry &entry : qAsConst(p->addressEntries)) {
#else
		for (const NetworkAddressEntry &entry : p->addressEntries) {
#endif
            result += entry.ip();
        }
    }

    return result;
}


QTNETWORKNG_NAMESPACE_END


#ifndef QT_NO_DEBUG_STREAM
static inline QDebug flagsDebug(QDebug debug, QTNETWORKNG_NAMESPACE::NetworkInterface::InterfaceFlags flags)
{
    if (flags & QTNETWORKNG_NAMESPACE::NetworkInterface::IsUp)
        debug << "IsUp ";
    if (flags & QTNETWORKNG_NAMESPACE::NetworkInterface::IsRunning)
        debug << "IsRunning ";
    if (flags & QTNETWORKNG_NAMESPACE::NetworkInterface::CanBroadcast)
        debug << "CanBroadcast ";
    if (flags & QTNETWORKNG_NAMESPACE::NetworkInterface::IsLoopBack)
        debug << "IsLoopBack ";
    if (flags & QTNETWORKNG_NAMESPACE::NetworkInterface::IsPointToPoint)
        debug << "IsPointToPoint ";
    if (flags & QTNETWORKNG_NAMESPACE::NetworkInterface::CanMulticast)
        debug << "CanMulticast ";
    return debug;
}


static inline QDebug operator<<(QDebug debug, const QTNETWORKNG_NAMESPACE::NetworkAddressEntry &entry)
{
    debug << "(address = " << entry.ip();
    if (!entry.netmask().isNull())
        debug << ", netmask = " << entry.netmask();
    if (!entry.broadcast().isNull())
        debug << ", broadcast = " << entry.broadcast();
    debug << ')';
    return debug;
}


QDebug operator<<(QDebug debug, const QTNETWORKNG_NAMESPACE::NetworkInterface &networkInterface)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace();
    debug << "NetworkInterface(name = " << networkInterface.name()
          << ", hardware address = " << networkInterface.hardwareAddress()
          << ", flags = ";
    flagsDebug(debug, networkInterface.flags());
    debug << ", entries = " << networkInterface.addressEntries()
          << ")\n";
    return debug;
}

#endif  // QT_NO_DEBUG_STREAM

