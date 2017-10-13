#ifndef DATAPACK_H
#define DATAPACK_H

#include <type_traits>
#include <QDataStream>

struct CommonHeader
{
    quint64 requestId;
    quint16 command;
    inline void pack(QDataStream &ds) const {Q_UNUSED(ds)}
    inline void unpack(QDataStream &ds) const {Q_UNUSED(ds)}
};

class DataPackException
{
};

inline QDataStream &operator>>(QDataStream &ds, CommonHeader &header)
{
    return ds >> header.requestId >> header.command;
}

inline QDataStream &operator<<(QDataStream &ds, const CommonHeader &header)
{
    return ds << header.requestId << header.command;
}

inline CommonHeader peekHeader(const QByteArray &data)
{
    QDataStream ds(data);
    CommonHeader header;
    ds >> header;
    if(ds.status() != QDataStream::Ok)
        throw DataPackException();
    return header;
}

template<typename CommandPack, class = typename std::enable_if<std::is_base_of<CommonHeader, CommandPack>::value>::type >
QByteArray pack(const CommandPack &command)
{
    QByteArray data;
    QDataStream ds(&data, QIODevice::WriteOnly);
    ds << command;
    if(ds.status() != QDataStream::Ok)
        throw DataPackException();
    return data;
}

template<typename CommandPack, class = typename std::enable_if<std::is_base_of<CommonHeader, CommandPack>::value>::type >
CommandPack unpack(const QByteArray &data)
{
    CommandPack command;
    QDataStream ds(data);
    ds >> command;
    if(ds.status() != QDataStream::Ok)
        throw DataPackException();
    return command;
}

template<typename CommandPack, class = typename std::enable_if<std::is_base_of<CommonHeader, CommandPack>::value>::type >
QDataStream &operator>>(QDataStream &ds, CommandPack &command)
{
    ds >> command.requestId >> command.command;
    if(ds.status() != QDataStream::Ok)
        return ds;
    command.unpack(ds);
    return ds;
}

template<typename CommandPack, class = typename std::enable_if<std::is_base_of<CommonHeader, CommandPack>::value>::type >
QDataStream &operator<<(QDataStream &ds, const CommandPack &command)
{
    ds << command.requestId << command.command;
    if(ds.status() != QDataStream::Ok)
        return ds;
    command.pack(ds);
    return ds;
}


#endif
