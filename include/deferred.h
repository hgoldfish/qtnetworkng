#ifndef QTNG_DEFERRED_H
#define QTNG_DEFERRED_H

#include <functional>
#include <tuple>
#include <QtCore/qlist.h>
#include <QtCore/qpair.h>
#include "config.h"

QTNETWORKNG_NAMESPACE_BEGIN

template<typename ARG>
class Deferred
{
public:
    typedef std::function<void(const ARG &)> Callback;
    Deferred();
public:
    int addCallbacks(Callback callback, Callback errback);
    int addBoth(Callback callback) { return addCallbacks(callback, callback); }
    int addCallback(Callback callback);
    int addErrback(Callback errback);
    void clear() { stack.clear(); }
    void remove(int id);
    void callback(const ARG &arg) { run(arg, true); }
    void erroback(const ARG &arg) { run(arg, false); }
private:
    void run(const ARG &arg, bool ok);
private:
    QList<std::tuple<int, Callback, Callback>> stack;
    QPair<ARG, bool> originalResult;
    int nextId;
    bool ran;
};

template<>
class Deferred<void>
{
public:
    typedef std::function<void()> Callback;
    inline Deferred();
    inline int addCallbacks(Callback callback, Callback errback);
    inline int addBoth(Callback callback) { return addCallbacks(callback, callback); }
    inline int addCallback(Callback callback);
    inline int addErrback(Callback errback);
    inline void clear() { stack.clear(); }
    inline void remove(int id);
    inline void callback() { run(true); }
    inline void erroback() { run(false); }
private:
    inline void run(bool ok);
private:
    QList<std::tuple<int, Callback, Callback>> stack;
    int nextId;
    bool originalResult;
    bool ran;
};

template<typename ARG>
Deferred<ARG>::Deferred()
    : nextId(1)
    , ran(false)
{
}

template<typename ARG>
int Deferred<ARG>::addCallbacks(Callback callback, Callback errback)
{
    int id = nextId++;
    stack.append(std::make_tuple(id, callback, errback));
    if (ran) {
        if (originalResult.second) {
            callback(originalResult.first);
        } else {
            errback(originalResult.first);
        }
    }
    return id;
}

template<typename ARG>
int Deferred<ARG>::addCallback(Callback callback)
{
    Callback errorback = [](const ARG &) {};
    return addCallbacks(callback, errorback);
}

template<typename ARG>
int Deferred<ARG>::addErrback(Callback errback)
{
    Callback callback = [](const ARG &) {};
    return addCallbacks(callback, errback);
}

template<typename ARG>
void Deferred<ARG>::remove(int id)
{
    for (int i = 0; i < stack.size(); ++i) {
        if (std::get<0>(stack[i]) == id) {
            stack.removeAt(i);
            return;
        }
    }
}

template<typename ARG>
void Deferred<ARG>::run(const ARG &arg, bool ok)
{
    originalResult = qMakePair(arg, ok);
    ran = true;
    bool _ok = ok;
    for (const std::tuple<int, Callback, Callback> &item : stack) {
        try {
            if (_ok) {
                std::get<1>(item)(arg);
            } else {
                std::get<2>(item)(arg);
            }
            _ok = true;
        } catch (...) {
            _ok = false;
        }
    }
}

Deferred<void>::Deferred()
    : nextId(1)
    , ran(false)
{
}

int Deferred<void>::addCallbacks(Callback callback, Callback errback)
{
    int id = nextId++;
    stack.append(std::make_tuple(id, callback, errback));
    if (ran) {
        if (originalResult) {
            callback();
        } else {
            errback();
        }
    }
    return id;
}

int Deferred<void>::addCallback(Callback callback)
{
    Callback errorback = []() {};
    return addCallbacks(callback, errorback);
}

int Deferred<void>::addErrback(Callback errback)
{
    Callback callback = []() {};
    return addCallbacks(callback, errback);
}

void Deferred<void>::run(bool ok)
{
    originalResult = ok;
    ran = true;
    bool _ok = ok;
    for (const std::tuple<int, Callback, Callback> &item : stack) {
        try {
            if (_ok) {
                std::get<1>(item)();
            } else {
                std::get<2>(item)();
            }
            _ok = true;
        } catch (...) {
            _ok = false;
        }
    }
}

QTNETWORKNG_NAMESPACE_END

#endif  // DEFERRED_H
