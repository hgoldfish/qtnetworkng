#ifndef QTNG_HOSTADDRESS_P_H
#define QTNG_HOSTADDRESS_P_H

#include "../hostaddress.h"

QTNETWORKNG_NAMESPACE_BEGIN


enum AddressClassification {
    LoopbackAddress = 1,
    LocalNetAddress,                // RFC 1122
    LinkLocalAddress,               // RFC 4291 (v6), RFC 3927 (v4)
    MulticastAddress,               // RFC 4291 (v6), RFC 3171 (v4)
    BroadcastAddress,               // RFC 919, 922

    GlobalAddress = 16,
    TestNetworkAddress,             // RFC 3849 (v6), RFC 5737 (v4),
    PrivateNetworkAddress,          // RFC 1918
    UniqueLocalAddress,             // RFC 4193
    SiteLocalAddress,               // RFC 4291 (deprecated by RFC 3879, should be treated as global)

    UnknownAddress = 0              // unclassified or reserved
};

class Netmask
{
public:
    Netmask() : length(255) {}

    bool setAddress(const HostAddress &address);
    HostAddress address(HostAddress::NetworkLayerProtocol protocol) const;

    int prefixLength() const { return length == 255 ? -1 : length; }
    void setPrefixLength(HostAddress::NetworkLayerProtocol proto, int len)
    {
        int maxlen = -1;
        if (proto == HostAddress::IPv4Protocol)
            maxlen = 32;
        else if (proto == HostAddress::IPv6Protocol)
            maxlen = 128;
        if (len > maxlen || len < 0)
            length = 255U;
        else
            length = unsigned(len);
    }

    friend bool operator==(Netmask n1, Netmask n2) { return n1.length == n2.length; }
private:
    // stores 0-32 for IPv4, 0-128 for IPv6, or 255 for invalid
    quint8 length;
};


class HostAddressPrivate : public QSharedData
{
public:
    HostAddressPrivate();

    void setAddress(const IPv4Address ipv4_ = 0);
    void setAddress(const IPv6Address ipv6);
    bool parse(const QString &ipString);
    void clear();

    QString scopeId;

    union {
        IPv6Address a6;
        struct { quint64 c[2]; } a6_64;
        struct { quint32 c[4]; } a6_32;
    } ipv6;// IPv6 address
    IPv4Address ipv4;    // IPv4 address
    qint8 protocol;

    AddressClassification classify() const;
    static AddressClassification classify(const HostAddress &address)
    { return address.d->classify(); }

    friend class HostAddress;
};


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HOSTADDRESS_P_H
