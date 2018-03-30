#ifndef QTNG_DEFERRED_H
#define QTNG_DEFERRED_H

#include <QtCore/qlist.h>
#include <QtCore/qpair.h>

template<typename ARG>
class Deferred
{
public:
    typedef std::function<ARG(const ARG &)> Callback;
    Deferred() {}
public:
    void addCallbacks(Callback callback, Callback errback) { stack.append(qMakePair(callback, errback)); }
    void addBoth(Callback callback) { addCallbacks(callback, callback); }
    void addCallback(Callback callback);
    void addErrback(Callback errback);
    void clear() { stack.clear(); }
    void callback(const ARG &arg) { run(arg, true); }
    void erroback(const ARG &arg) { run(arg, false); }
private:
    void run(const ARG &arg, bool ok);
private:
    QList<QPair<Callback, Callback>> stack;
};


template<typename ARG>
void Deferred<ARG>::addCallback(Callback callback)
{
    Callback errorback = [] (const ARG &arg) -> ARG {
        return arg;
    };
    addCallbacks(callback, errorback);
}


template<typename ARG>
void Deferred<ARG>::addErrback(Callback errback)
{
    Callback callback = [] (const ARG &arg) -> ARG {
        return arg;
    };
    addCallbacks(callback, errback);
}


template<typename ARG>
void Deferred<ARG>::run(const ARG &arg, bool ok)
{
    ARG result = arg;
    bool _ok = ok;
    for(const QPair<Callback, Callback> &item: stack) {
        try {
            if(_ok) {
                result = item.first(result);
            } else {
                result = item.second(result);
            }
            _ok = true;
        } catch (const ARG &e) {
            result = e;
            _ok = false;
        }
    }
}

#endif // DEFERRED_H
