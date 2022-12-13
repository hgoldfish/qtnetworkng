#ifndef QTNG_NETWORK_INTERFACE_H
#define QTNG_NETWORK_INTERFACE_H

#include <QtCore/qlist.h>
#include <QtCore/qmetaobject.h>
#include <QtCore/qmetatype.h>
#if QT_VERSION > QT_VERSION_CHECK(5, 8, 0)
#  include <QtCore/qdeadlinetimer.h>
#endif
#include "hostaddress.h"

QTNETWORKNG_NAMESPACE_BEGIN

class NetworkAddressEntryPrivate;
class NetworkAddressEntry
{
public:
    enum DnsEligibilityStatus : qint8 { DnsEligibilityUnknown = -1, DnsIneligible = 0, DnsEligible = 1 };

    NetworkAddressEntry();
    NetworkAddressEntry(const NetworkAddressEntry &other);
#ifdef Q_COMPILER_RVALUE_REFS
    NetworkAddressEntry &operator=(NetworkAddressEntry &&other) Q_DECL_NOTHROW
    {
        swap(other);
        return *this;
    }
#endif
    NetworkAddressEntry &operator=(const NetworkAddressEntry &other);
    ~NetworkAddressEntry();

    void swap(NetworkAddressEntry &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    bool operator==(const NetworkAddressEntry &other) const;
    inline bool operator!=(const NetworkAddressEntry &other) const { return !(*this == other); }

    DnsEligibilityStatus dnsEligibility() const;
    void setDnsEligibility(DnsEligibilityStatus status);

    HostAddress ip() const;
    void setIp(const HostAddress &newIp);

    HostAddress netmask() const;
    void setNetmask(const HostAddress &newNetmask);
    int prefixLength() const;
    void setPrefixLength(int length);

    HostAddress broadcast() const;
    void setBroadcast(const HostAddress &newBroadcast);

#if QT_VERSION > QT_VERSION_CHECK(5, 8, 0)
    bool isLifetimeKnown() const;
    QDeadlineTimer preferredLifetime() const;
    QDeadlineTimer validityLifetime() const;
    void setAddressLifetime(QDeadlineTimer preferred, QDeadlineTimer validity);
    void clearAddressLifetime();
    bool isPermanent() const;
    bool isTemporary() const { return !isPermanent(); }
#endif
private:
    QScopedPointer<NetworkAddressEntryPrivate> d;
};

class NetworkInterfacePrivate;
class NetworkInterface
{
public:
    enum InterfaceFlag {
        IsUp = 0x1,
        IsRunning = 0x2,
        CanBroadcast = 0x4,
        IsLoopBack = 0x8,
        IsPointToPoint = 0x10,
        CanMulticast = 0x20
    };
    Q_DECLARE_FLAGS(InterfaceFlags, InterfaceFlag)

    enum InterfaceType {
        Loopback = 1,
        Virtual,
        Ethernet,
        Slip,
        CanBus,
        Ppp,
        Fddi,
        Wifi,
        Ieee80211 = Wifi,  // alias
        Phonet,
        Ieee802154,
        SixLoWPAN,  // 6LoWPAN, but we can't start with a digit
        Ieee80216,
        Ieee1394,

        Unknown = 0
    };
public:
    NetworkInterface();
    NetworkInterface(const NetworkInterface &other);
#ifdef Q_COMPILER_RVALUE_REFS
    NetworkInterface &operator=(NetworkInterface &&other) Q_DECL_NOTHROW
    {
        swap(other);
        return *this;
    }
#endif
    NetworkInterface &operator=(const NetworkInterface &other);
    ~NetworkInterface();
    void swap(NetworkInterface &other) Q_DECL_NOTHROW { qSwap(d, other.d); }
public:
    bool isValid() const;
    int index() const;
    int maximumTransmissionUnit() const;
    QString name() const;
    QString humanReadableName() const;
    InterfaceFlags flags() const;
    InterfaceType type() const;
    QString hardwareAddress() const;
    QList<NetworkAddressEntry> addressEntries() const;

    static int interfaceIndexFromName(const QString &name);
    static NetworkInterface interfaceFromName(const QString &name);
    static NetworkInterface interfaceFromIndex(int index);
    static QString interfaceNameFromIndex(int index);
    static QList<NetworkInterface> allInterfaces();
    static QList<HostAddress> allAddresses();
private:
    friend class QNetworkInterfacePrivate;
    QSharedDataPointer<NetworkInterfacePrivate> d;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(NetworkInterface::InterfaceFlags)

QTNETWORKNG_NAMESPACE_END

#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug debug, const QTNETWORKNG_NAMESPACE::NetworkAddressEntry &entry);
QDebug operator<<(QDebug debug, const QTNETWORKNG_NAMESPACE::NetworkInterface &networkInterface);
#endif

Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::NetworkAddressEntry)
Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::NetworkInterface)

#endif  // QTNG_NETWORK_INTERFACE_H
