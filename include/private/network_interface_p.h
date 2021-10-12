#ifndef QTNG_NETWORK_INTERFACE_P_H
#define QTNG_NETWORK_INTERFACE_P_H

#include "../network_interface.h"
#include "hostaddress_p.h"

QTNETWORKNG_NAMESPACE_BEGIN


class NetworkAddressEntryPrivate
{
public:
    HostAddress address;
    HostAddress broadcast;
#if QT_VERSION > QT_VERSION_CHECK(5, 8, 0)
    QDeadlineTimer preferredLifetime = QDeadlineTimer::Forever;
    QDeadlineTimer validityLifetime = QDeadlineTimer::Forever;
#endif
    Netmask netmask;
    bool lifetimeKnown = false;
    NetworkAddressEntry::DnsEligibilityStatus dnsEligibility = NetworkAddressEntry::DnsEligibilityUnknown;
};


class NetworkInterfacePrivate: public QSharedData
{
public:
    NetworkInterfacePrivate()
        : index(0), mtu(0), flags() {}
public:
    int index;                  // interface index, if know
    int mtu;
    NetworkInterface::InterfaceFlags flags;
    NetworkInterface::InterfaceType type = NetworkInterface::Unknown;
    QString name;
    QString friendlyName;
    QString hardwareAddress;
    QList<NetworkAddressEntry> addressEntries;
public:
    static QString makeHwAddress(int len, uchar *data);
    static void calculateDnsEligibility(NetworkAddressEntry *entry, bool isTemporary,
                                        bool isDeprecated)
    {
        // this implements an algorithm that yields the same results as Windows
        // produces, for the same input (as far as I can test)
        if (isTemporary || isDeprecated)
            entry->setDnsEligibility(NetworkAddressEntry::DnsIneligible);

        AddressClassification cl = HostAddressPrivate::classify(entry->ip());
        if (cl == LoopbackAddress || cl == LinkLocalAddress)
            entry->setDnsEligibility(NetworkAddressEntry::DnsIneligible);
        else
            entry->setDnsEligibility(NetworkAddressEntry::DnsEligible);
    }
private:
    // disallow copying -- avoid detaching
    NetworkInterfacePrivate &operator=(const NetworkInterfacePrivate &other);
    NetworkInterfacePrivate(const NetworkInterfacePrivate &other);
};


class NetworkInterfaceManager
{
public:
    NetworkInterfaceManager();
    ~NetworkInterfaceManager();

    QSharedDataPointer<NetworkInterfacePrivate> interfaceFromName(const QString &name);
    QSharedDataPointer<NetworkInterfacePrivate> interfaceFromIndex(int index);
    QList<QSharedDataPointer<NetworkInterfacePrivate> > allInterfaces();

    static uint interfaceIndexFromName(const QString &name);
    static QString interfaceNameFromIndex(uint index);

    // convenience:
    QSharedDataPointer<NetworkInterfacePrivate> empty;

private:
    QList<NetworkInterfacePrivate *> scan();
};


QTNETWORKNG_NAMESPACE_END

#endif
