#ifndef QTNG_HOSTADDRESS_H
#define QTNG_HOSTADDRESS_H

#include <QtCore/qobject.h>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QList>
#include "config.h"

#ifdef QT_NETWORK_LIB
#include <QtNetwork>
#endif

QTNETWORKNG_NAMESPACE_BEGIN

struct  IPv6Addr
{
public:
    inline quint8 &operator [](int index) { return c[index]; }
    inline quint8 operator [](int index) const { return c[index]; }
    quint8 c[16];
};

typedef quint32 IPv4Address;
typedef IPv6Addr IPv6Address;

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
#ifdef QT_NETWORK_LIB
    HostAddress(const QHostAddress& address);
    HostAddress(QHostAddress::SpecialAddress address);
#endif
    ~HostAddress();

    HostAddress &operator=(HostAddress &&other) noexcept
    { swap(other); return *this; }
    HostAddress &operator=(const HostAddress &other);
    HostAddress &operator=(SpecialAddress address);

    bool isEqual(const HostAddress &address, ConversionMode mode = TolerantConversion) const;
    bool operator ==(const HostAddress &address) const;
    bool operator ==(SpecialAddress address) const;

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

    QString toString() const;

    QString scopeId() const;
    void setScopeId(const QString &id);

    static QList<HostAddress> getHostAddressByName(const QString &hostName);

private:
    friend class HostAddressPrivate;
    QSharedDataPointer<HostAddressPrivate> d;

};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HOSTADDRESS_H
