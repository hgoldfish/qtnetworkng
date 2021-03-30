#ifndef QTNG_HOSTADDRESS_H
#define QTNG_HOSTADDRESS_H

#include <QtCore/qobject.h>
#include <QtCore/qshareddata.h>
#include <QtCore/qlist.h>
#include "config.h"

#ifdef QT_NETWORK_LIB
#include <QtNetwork/qhostaddress.h>
#endif

struct sockaddr;

QTNETWORKNG_NAMESPACE_BEGIN

struct  IPv6Address
{
    inline quint8 &operator [](int index) { return c[index]; }
    inline quint8 operator [](int index) const { return c[index]; }
    quint8 c[16];
};

typedef quint32 IPv4Address;

#ifdef Q_OS_WIN
void initWinSock();
void freeWinSock();
#endif

class HostAddressPrivate;
class HostAddress
{
public:
    enum SpecialAddress {
        Null,
        Broadcast,
        LocalHost,
        LocalHostIPv6,
        Any,
        AnyIPv6,
        AnyIPv4
    };
    enum NetworkLayerProtocol {
        IPv4Protocol = 1,
        IPv6Protocol = 2,
        AnyIPProtocol = 3,
        UnknownNetworkLayerProtocol = -1
    };
    Q_ENUMS(NetworkLayerProtocol)

    enum ConversionModeFlag {
        ConvertV4MappedToIPv4 = 1,
        ConvertV4CompatToIPv4 = 2,
        ConvertUnspecifiedAddress = 4,
        ConvertLocalHost = 8,
        TolerantConversion = 0xff,
        StrictConversion = 0
    };
    Q_DECLARE_FLAGS(ConversionMode, ConversionModeFlag)

public:
    HostAddress();
    HostAddress(const HostAddress& copy);
    HostAddress(SpecialAddress address);
    HostAddress(const QString &address);
    HostAddress(quint32 ip4Addr);
    HostAddress(quint8 *ip6Addr);
    HostAddress(const quint8 *ip6Addr);
    HostAddress(const IPv6Address &ip6Addr);
    HostAddress(const sockaddr *sockaddr);
#ifdef QT_NETWORK_LIB
    HostAddress(const QHostAddress& address);
    HostAddress(QHostAddress::SpecialAddress address);
    HostAddress(const QIPv6Address &ip6Addr);
#endif
    ~HostAddress();

    HostAddress &operator=(HostAddress &&other) noexcept
    { swap(other); return *this; }
    HostAddress &operator=(const HostAddress &other);
    HostAddress &operator=(SpecialAddress address);

    bool isEqual(const HostAddress &address, ConversionMode mode = TolerantConversion) const;
    bool operator ==(const HostAddress &address) const;
    bool operator ==(SpecialAddress address) const;
    inline bool operator !=(const HostAddress &address) const
    { return !operator==(address); }
    inline bool operator !=(SpecialAddress address) const
    { return !operator==(address); }

    void swap(HostAddress &other) noexcept;
    void clear();
public:
    void setAddress(const IPv4Address ipv4);
    void setAddress(const IPv6Address &ipv6);
    void setAddress(const quint8* ipv6);
    bool setAddress(const QString &ipString);

    bool isNull() const;
    NetworkLayerProtocol protocol() const;
    IPv4Address toIPv4Address(bool *ok) const;
    IPv6Address toIPv6Address() const;

    bool isInSubnet(const HostAddress &subnet, int netmask) const;
    bool isInSubnet(const QPair<HostAddress, int> &subnet) const;
    static QPair<HostAddress, int> parseSubnet(const QString &subnet);

    bool isLoopback() const;
    bool isGlobal() const;
    bool isLinkLocal() const;
    bool isSiteLocal() const;
    bool isUniqueLocalUnicast() const;
    bool isMulticast() const;
    bool isBroadcast() const;

    QString toString() const;

    QString scopeId() const;
    void setScopeId(const QString &id);

    static QList<HostAddress> getHostAddressByName(const QString &hostName);

    friend uint qHash(const HostAddress &key, uint seed) noexcept;

private:
    friend class HostAddressPrivate;
    QSharedDataPointer<HostAddressPrivate> d;

};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HOSTADDRESS_H
