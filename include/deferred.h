#ifndef QTNG_DEFERRED_H
#define QTNG_DEFERRED_H

#include <functional>
#include <QtCore/qlist.h>
#include <QtCore/qpair.h>

template<typename ARG>
class Deferred
{
public:
    typedef std::function<ARG(const ARG &)> Callback;
    Deferred();
public:
    void addCallbacks(Callback callback, Callback errback);
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
    QPair<ARG, bool> originalResult;
    bool ran;
};


template<typename ARG>
Deferred<ARG>::Deferred()
    :ran(false)
{

}

template<typename ARG>
void Deferred<ARG>::addCallbacks(Callback callback, Callback errback)
{
     stack.append(qMakePair(callback, errback));
     if(ran) {
         if(originalResult.second) {
             callback(originalResult.first);
         } else {
             errback(originalResult.first);
         }
     }
}

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
    originalResult = qMakePair(arg, ok);
    ran = true;
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
