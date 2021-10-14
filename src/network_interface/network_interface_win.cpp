/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Copyright (C) 2016 Intel Corporation.
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

#define WIN32_LEAN_AND_MEAN 1
#define _WIN32_WINNT 0x0600

#include <QtCore/qt_windows.h>
#include <QtCore/qlibrary.h>

// Since we need to include winsock2.h, we need to define WIN32_LEAN_AND_MEAN
// (above) so windows.h won't include winsock.h.
// In addition, we need to include winsock2.h before iphlpapi.h and we need
// to include ws2ipdef.h to work around an MinGW-w64 bug
// (http://sourceforge.net/p/mingw-w64/mailman/message/32935366/)
#include <winsock2.h>
#include <ws2ipdef.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include "../../include/private/hostaddress_p.h"
#include "../../include/private/network_interface_p.h"

// In case these aren't defined
#define IF_TYPE_IEEE80216_WMAN  237
#define IF_TYPE_IEEE802154      259

QTNETWORKNG_NAMESPACE_BEGIN


typedef DWORD (WINAPI *PtrGetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
static PtrGetAdaptersInfo ptrGetAdaptersInfo = 0;
typedef ULONG (WINAPI *PtrGetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
static PtrGetAdaptersAddresses ptrGetAdaptersAddresses = 0;
typedef DWORD (WINAPI *PtrGetNetworkParams)(PFIXED_INFO, PULONG);
static PtrGetNetworkParams ptrGetNetworkParams = 0;

typedef NETIO_STATUS (WINAPI *PtrConvertInterfaceLuidToName)(const NET_LUID *, PWSTR, SIZE_T);
static PtrConvertInterfaceLuidToName ptrConvertInterfaceLuidToName = 0;
typedef NETIO_STATUS (WINAPI *PtrConvertInterfaceLuidToIndex)(const NET_LUID *, PNET_IFINDEX);
static PtrConvertInterfaceLuidToIndex ptrConvertInterfaceLuidToIndex = 0;
typedef NETIO_STATUS (WINAPI *PtrConvertInterfaceNameToLuid)(const wchar_t*, NET_LUID *);
static PtrConvertInterfaceNameToLuid ptrConvertInterfaceNameToLuid = 0;
typedef NETIO_STATUS (WINAPI *PtrConvertInterfaceIndexToLuid)(NET_IFINDEX, PNET_LUID);
static PtrConvertInterfaceIndexToLuid ptrConvertInterfaceIndexToLuid = 0;

static void resolveLibs()
{
    // try to find the functions we need from Iphlpapi.dll
    static bool done = false;

    if (!done) {
        done = true;

        QLibrary lib("iphlpapi");
        if (!lib.load()) {
            return;
        }
        ptrGetAdaptersInfo = (PtrGetAdaptersInfo) lib.resolve("GetAdaptersInfo");
        ptrGetAdaptersAddresses = (PtrGetAdaptersAddresses) lib.resolve("GetAdaptersAddresses");
        ptrGetNetworkParams = (PtrGetNetworkParams) lib.resolve("GetNetworkParams");
        ptrConvertInterfaceLuidToName = (PtrConvertInterfaceLuidToName) lib.resolve("ConvertInterfaceLuidToNameW");
        ptrConvertInterfaceLuidToIndex = (PtrConvertInterfaceLuidToIndex) lib.resolve("ConvertInterfaceLuidToIndex");
        ptrConvertInterfaceNameToLuid = (PtrConvertInterfaceNameToLuid) lib.resolve("ConvertInterfaceNameToLuidW");
        ptrConvertInterfaceIndexToLuid = (PtrConvertInterfaceIndexToLuid) lib.resolve("ConvertInterfaceIndexToLuid");
    }
}


static QHash<HostAddress, HostAddress> ipv4Netmasks()
{
    //Retrieve all the IPV4 addresses & netmasks
    IP_ADAPTER_INFO staticBuf[2]; // 2 is arbitrary
    PIP_ADAPTER_INFO pAdapter = staticBuf;
    ULONG bufSize = sizeof staticBuf;
    QHash<HostAddress, HostAddress> ipv4netmasks;

    DWORD retval = ptrGetAdaptersInfo(pAdapter, &bufSize);
    if (retval == ERROR_BUFFER_OVERFLOW) {
        // need more memory
        pAdapter = (IP_ADAPTER_INFO *)malloc(bufSize);
        if (!pAdapter)
            return ipv4netmasks;
        // try again
        if (ptrGetAdaptersInfo(pAdapter, &bufSize) != ERROR_SUCCESS) {
            free(pAdapter);
            return ipv4netmasks;
        }
    } else if (retval != ERROR_SUCCESS) {
        // error
        return ipv4netmasks;
    }

    // iterate over the list and add the entries to our listing
    for (PIP_ADAPTER_INFO ptr = pAdapter; ptr; ptr = ptr->Next) {
        for (PIP_ADDR_STRING addr = &ptr->IpAddressList; addr; addr = addr->Next) {
            HostAddress address(QLatin1String(addr->IpAddress.String));
            HostAddress mask(QLatin1String(addr->IpMask.String));
            ipv4netmasks[address] = mask;
        }
    }
    if (pAdapter != staticBuf)
        free(pAdapter);

    return ipv4netmasks;
}


static QList<NetworkInterfacePrivate *> interfaceListingWinXP()
{
    QList<NetworkInterfacePrivate *> interfaces;
    IP_ADAPTER_ADDRESSES staticBuf[2]; // 2 is arbitrary
    PIP_ADAPTER_ADDRESSES pAdapter = staticBuf;
    ULONG bufSize = sizeof staticBuf;

    const QHash<HostAddress, HostAddress> &ipv4netmasks = ipv4Netmasks();
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX |
                  GAA_FLAG_SKIP_DNS_SERVER |
                  GAA_FLAG_SKIP_MULTICAST;
    ULONG retval = ptrGetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAdapter, &bufSize);
    if (retval == ERROR_BUFFER_OVERFLOW) {
        // need more memory
        pAdapter = (IP_ADAPTER_ADDRESSES *)malloc(bufSize);
        if (!pAdapter)
            return interfaces;
        // try again
        if (ptrGetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAdapter, &bufSize) != ERROR_SUCCESS) {
            free(pAdapter);
            return interfaces;
        }
    } else if (retval != ERROR_SUCCESS) {
        // error
        return interfaces;
    }

    // iterate over the list and add the entries to our listing
    for (PIP_ADAPTER_ADDRESSES ptr = pAdapter; ptr; ptr = ptr->Next) {
        NetworkInterfacePrivate *iface = new NetworkInterfacePrivate;
        interfaces << iface;

        iface->index = 0;
        if (ptr->Length >= offsetof(IP_ADAPTER_ADDRESSES, Ipv6IfIndex) && ptr->Ipv6IfIndex != 0)
            iface->index = ptr->Ipv6IfIndex;
        else if (ptr->IfIndex != 0)
            iface->index = ptr->IfIndex;

        iface->flags = NetworkInterface::CanBroadcast;
        if (ptr->OperStatus == IfOperStatusUp)
            iface->flags |= NetworkInterface::IsUp | NetworkInterface::IsRunning;
        if ((ptr->Flags & IP_ADAPTER_NO_MULTICAST) == 0)
            iface->flags |= NetworkInterface::CanMulticast;
        if (ptr->IfType == IF_TYPE_PPP)
            iface->flags |= NetworkInterface::IsPointToPoint;

        iface->name = QString::fromLocal8Bit(ptr->AdapterName);
        iface->friendlyName = QString::fromWCharArray(ptr->FriendlyName);
        if (ptr->PhysicalAddressLength)
            iface->hardwareAddress = iface->makeHwAddress(ptr->PhysicalAddressLength,
                                                          ptr->PhysicalAddress);
        else
            // loopback if it has no address
            iface->flags |= NetworkInterface::IsLoopBack;

        // The GetAdaptersAddresses call has an interesting semantic:
        // It can return a number N of addresses and a number M of prefixes.
        // But if you have IPv6 addresses, generally N > M.
        // I cannot find a way to relate the Address to the Prefix, aside from stopping
        // the iteration at the last Prefix entry and assume that it applies to all addresses
        // from that point on.
        PIP_ADAPTER_PREFIX pprefix = 0;
        if (ptr->Length >= offsetof(IP_ADAPTER_ADDRESSES, FirstPrefix))
            pprefix = ptr->FirstPrefix;
        for (PIP_ADAPTER_UNICAST_ADDRESS addr = ptr->FirstUnicastAddress; addr; addr = addr->Next) {
            NetworkAddressEntry entry;
            entry.setIp(HostAddress(addr->Address.lpSockaddr));
            if (pprefix) {
                if (entry.ip().protocol() == HostAddress::IPv4Protocol) {
                    entry.setNetmask(ipv4netmasks[entry.ip()]);

                    // broadcast address is set on postProcess()
                } else { //IPV6
                    entry.setPrefixLength(pprefix->PrefixLength);
                }
                pprefix = pprefix->Next ? pprefix->Next : pprefix;
            }
            iface->addressEntries << entry;
        }
    }

    if (pAdapter != staticBuf)
        free(pAdapter);

    return interfaces;
}


static QList<NetworkInterfacePrivate *> interfaceListingWin2k()
{
    QList<NetworkInterfacePrivate *> interfaces;
    IP_ADAPTER_INFO staticBuf[2]; // 2 is arbitrary
    PIP_ADAPTER_INFO pAdapter = staticBuf;
    ULONG bufSize = sizeof staticBuf;

    DWORD retval = ptrGetAdaptersInfo(pAdapter, &bufSize);
    if (retval == ERROR_BUFFER_OVERFLOW) {
        // need more memory
        pAdapter = (IP_ADAPTER_INFO *)malloc(bufSize);
        if (!pAdapter)
            return interfaces;
        // try again
        if (ptrGetAdaptersInfo(pAdapter, &bufSize) != ERROR_SUCCESS) {
            free(pAdapter);
            return interfaces;
        }
    } else if (retval != ERROR_SUCCESS) {
        // error
        return interfaces;
    }

    // iterate over the list and add the entries to our listing
    for (PIP_ADAPTER_INFO ptr = pAdapter; ptr; ptr = ptr->Next) {
        NetworkInterfacePrivate *iface = new NetworkInterfacePrivate;
        interfaces << iface;

        iface->index = ptr->Index;
        iface->flags = NetworkInterface::IsUp | NetworkInterface::IsRunning;
        if (ptr->Type == MIB_IF_TYPE_PPP)
            iface->flags |= NetworkInterface::IsPointToPoint;
        else
            iface->flags |= NetworkInterface::CanBroadcast;
        iface->name = QString::fromLocal8Bit(ptr->AdapterName);
        iface->hardwareAddress = NetworkInterfacePrivate::makeHwAddress(ptr->AddressLength,
                                                                         ptr->Address);

        for (PIP_ADDR_STRING addr = &ptr->IpAddressList; addr; addr = addr->Next) {
            NetworkAddressEntry entry;
            entry.setIp(HostAddress(QLatin1String(addr->IpAddress.String)));
            entry.setNetmask(HostAddress(QLatin1String(addr->IpMask.String)));
            // broadcast address is set on postProcess()

            iface->addressEntries << entry;
        }
    }

    if (pAdapter != staticBuf)
        free(pAdapter);

    return interfaces;
}

static QList<NetworkInterfacePrivate *> interfaceListingVista()
{
    QList<NetworkInterfacePrivate *> interfaces;
    IP_ADAPTER_ADDRESSES staticBuf[2]; // 2 is arbitrary
    PIP_ADAPTER_ADDRESSES pAdapter = staticBuf;
    ULONG bufSize = sizeof staticBuf;

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX |
                  GAA_FLAG_SKIP_DNS_SERVER |
                  GAA_FLAG_SKIP_MULTICAST;
    ULONG retval = ptrGetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAdapter, &bufSize);
    if (retval == ERROR_BUFFER_OVERFLOW) {
        // need more memory
        pAdapter = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(malloc(bufSize));
        if (!pAdapter)
            return interfaces;
        // try again
        if (ptrGetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAdapter, &bufSize) != ERROR_SUCCESS) {
            free(pAdapter);
            return interfaces;
        }
    } else if (retval != ERROR_SUCCESS) {
        // error
        return interfaces;
    }

    // iterate over the list and add the entries to our listing
    for (PIP_ADAPTER_ADDRESSES ptr = pAdapter; ptr; ptr = ptr->Next) {
        // the structure grows over time, so let's make sure the fields
        // introduced in Windows Vista are present (Luid is the furthest
        // field we access from IP_ADAPTER_ADDRESSES_LH)
        Q_ASSERT(ptr->Length >= offsetof(IP_ADAPTER_ADDRESSES, Luid));
        Q_ASSERT(ptr->Length >= offsetof(IP_ADAPTER_ADDRESSES, Ipv6IfIndex));

        NetworkInterfacePrivate *iface = new NetworkInterfacePrivate;
        interfaces << iface;

        iface->index = 0;
        if (ptr->Ipv6IfIndex != 0)
            iface->index = ptr->Ipv6IfIndex;
        else if (ptr->IfIndex != 0)
            iface->index = ptr->IfIndex;

        iface->mtu = qMin<qint64>(ptr->Mtu, INT_MAX);
        iface->flags = NetworkInterface::CanBroadcast;
        if (ptr->OperStatus == IfOperStatusUp)
            iface->flags |= NetworkInterface::IsUp | NetworkInterface::IsRunning;
        if ((ptr->Flags & IP_ADAPTER_NO_MULTICAST) == 0)
            iface->flags |= NetworkInterface::CanMulticast;
        if (ptr->IfType == IF_TYPE_PPP)
            iface->flags |= NetworkInterface::IsPointToPoint;

        switch (ptr->IfType) {
        case IF_TYPE_ETHERNET_CSMACD:
            iface->type = NetworkInterface::Ethernet;
            break;

        case IF_TYPE_FDDI:
            iface->type = NetworkInterface::Fddi;
            break;

        case IF_TYPE_PPP:
            iface->type = NetworkInterface::Ppp;
            break;

        case IF_TYPE_SLIP:
            iface->type = NetworkInterface::Slip;
            break;

        case IF_TYPE_SOFTWARE_LOOPBACK:
            iface->type = NetworkInterface::Loopback;
            iface->flags |= NetworkInterface::IsLoopBack;
            break;

        case IF_TYPE_IEEE80211:
            iface->type = NetworkInterface::Ieee80211;
            break;

        case IF_TYPE_IEEE1394:
            iface->type = NetworkInterface::Ieee1394;
            break;

        case IF_TYPE_IEEE80216_WMAN:
            iface->type = NetworkInterface::Ieee80216;
            break;

        case IF_TYPE_IEEE802154:
            iface->type = NetworkInterface::Ieee802154;
            break;
        }

        // use ConvertInterfaceLuidToNameW because that returns a friendlier name, though not
        // as "friendly" as FriendlyName below
        WCHAR buf[IF_MAX_STRING_SIZE + 1];
        if (ptrConvertInterfaceLuidToName(&ptr->Luid, buf, sizeof(buf)/sizeof(buf[0])) == NO_ERROR)
            iface->name = QString::fromWCharArray(buf);
        if (iface->name.isEmpty())
            iface->name = QString::fromLocal8Bit(ptr->AdapterName);

        iface->friendlyName = QString::fromWCharArray(ptr->FriendlyName);
        if (ptr->PhysicalAddressLength)
            iface->hardwareAddress = iface->makeHwAddress(ptr->PhysicalAddressLength,
                                                          ptr->PhysicalAddress);

        // parse the IP (unicast) addresses
        for (PIP_ADAPTER_UNICAST_ADDRESS addr = ptr->FirstUnicastAddress; addr; addr = addr->Next) {
            Q_ASSERT(addr->Length >= offsetof(IP_ADAPTER_UNICAST_ADDRESS, OnLinkPrefixLength));

            // skip addresses in invalid state
            if (addr->DadState == IpDadStateInvalid)
                continue;

            NetworkAddressEntry entry;
            entry.setIp(HostAddress(addr->Address.lpSockaddr));
            entry.setPrefixLength(addr->OnLinkPrefixLength);

            auto toDeadline = [](ULONG lifetime) -> QDeadlineTimer {
                if (lifetime == 0xffffffffUL)
                    return QDeadlineTimer::Forever;
                return QDeadlineTimer(lifetime * 1000);
            };
            entry.setAddressLifetime(toDeadline(addr->ValidLifetime), toDeadline(addr->PreferredLifetime));
            entry.setDnsEligibility(addr->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE ?
                                        NetworkAddressEntry::DnsEligible :
                                        NetworkAddressEntry::DnsIneligible);

            iface->addressEntries << entry;
        }
    }

    if (pAdapter != staticBuf)
        free(pAdapter);

    return interfaces;
}


static QList<NetworkInterfacePrivate *> interfaceListing()
{
    resolveLibs();
    if (ptrConvertInterfaceLuidToName && ptrGetAdaptersAddresses) {
        return interfaceListingVista();
    } else if (ptrGetAdaptersAddresses) {
        return interfaceListingWinXP();
    } else if (ptrGetAdaptersInfo) {
        return interfaceListingWin2k();
    }
    // failed
    return QList<NetworkInterfacePrivate *>();
}


uint NetworkInterfaceManager::interfaceIndexFromName(const QString &name)
{
    resolveLibs();
    if (ptrConvertInterfaceNameToLuid && ptrConvertInterfaceLuidToIndex) {
        NET_IFINDEX id;
        NET_LUID luid;
        if (ptrConvertInterfaceNameToLuid(reinterpret_cast<const wchar_t *>(name.constData()), &luid) == NO_ERROR
                && ptrConvertInterfaceLuidToIndex(&luid, &id) == NO_ERROR)
            return uint(id);
    }
    return 0;
}


QString NetworkInterfaceManager::interfaceNameFromIndex(uint index)
{
    resolveLibs();
    if (ptrConvertInterfaceLuidToName && ptrConvertInterfaceIndexToLuid) {
        NET_LUID luid;
        if (ptrConvertInterfaceIndexToLuid(index, &luid) == NO_ERROR) {
            WCHAR buf[IF_MAX_STRING_SIZE + 1];
            if (ptrConvertInterfaceLuidToName(&luid, buf, sizeof(buf)/sizeof(buf[0])) == NO_ERROR)
                return QString::fromWCharArray(buf);
        }
    }
    return QString::number(index);
}


QList<NetworkInterfacePrivate *> NetworkInterfaceManager::scan()
{
    return interfaceListing();
}


QTNETWORKNG_NAMESPACE_END
