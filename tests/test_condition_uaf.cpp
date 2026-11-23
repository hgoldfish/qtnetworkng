// Regression test for the lifetime bug in qtng::Condition / qtng::Event.
//
// locks.cpp:366-388: Condition::wait() appends a QSharedPointer<Lock> to
// ConditionPrivate::waiters, yields, and after being woken up dereferences the
// private object again at `d->waiters.removeOne(waiter)`.
//
// locks.cpp:360-364 and locks.cpp:436-447: ~Condition()/~EventPrivate() call
// notifyAll() while waiters are still parked and then immediately delete the
// private object. notifyAll() -> Semaphore::release() -> callLater(0, ...) only
// schedules the wakeup, so the waiter always resumes after the delete.
//
// This test parks one coroutine and destroys the Condition/Event while it is
// waiting. With AddressSanitizer the unfixed code reports heap-use-after-free
// at locks.cpp:387. Without ASan the probe below quarantines the freed
// ConditionPrivate block and fills it with 0xA5 instead of returning it to the
// allocator: the block cannot be reused/overwritten before the waiter resumes,
// so `d->waiters.removeOne()` deterministically dereferences 0xA5A5... as a
// QListData::Data* and crashes. (The one quarantined block is intentionally
// leaked; it only happens while the bug is unfixed.)
//
// A correct implementation (private object kept alive for the whole wait, or
// wait() no longer touching it after being woken) passes this test.

#include <QtCore/qcoreapplication.h>
#include <QtCore/qscopedpointer.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qtimer.h>
#include <QtCore/qdebug.h>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <new>
#include "qtnetworkng.h"

using namespace qtng;

#if !defined(__SANITIZE_ADDRESS__) && !defined(QTNG_UAF_TEST_NO_POISON)
#  define QTNG_UAF_TEST_POISON 1
#endif

#ifdef QTNG_UAF_TEST_POISON
namespace {
// ConditionPrivate only contains QList<QSharedPointer<Lock>> waiters, so its
// allocation size equals sizeof(that QList) (one QListData::Data* on Qt5).
const size_t privateSize = sizeof(QList<QSharedPointer<Lock>>);
void *watched = nullptr;
size_t watchedSize = 0;
bool watching = false;
bool poisoning = false;
int poisonHits = 0;

bool quarantineIfWatched(void *p)
{
    if (poisoning && p && p == watched) {
        std::memset(p, 0xA5, watchedSize);
        watched = nullptr;
        ++poisonHits;
        // 这里处在 operator delete 的调用栈上，qDebug() 等 Qt 日志都可能再次分配
        // 内存并递归进入探针。只记数，由 probeReport() 在普通上下文统一输出。
        return true;
    }
    return false;
}
}  // namespace

void *operator new(std::size_t n)
{
    void *p = std::malloc(n ? n : 1);
    if (!p) {
        throw std::bad_alloc();
    }
    // The first QList-sized allocation after probeArm() is the
    // ConditionPrivate created by Condition::Condition()/EventPrivate's member.
    if (watching && n == privateSize && !watched) {
        watched = p;
        watchedSize = n;
        watching = false;
    }
    return p;
}

void *operator new[](std::size_t n) { return ::operator new(n); }
void *operator new(std::size_t n, const std::nothrow_t &) noexcept
{
    try {
        return ::operator new(n);
    } catch (...) {
        return nullptr;
    }
}
void *operator new[](std::size_t n, const std::nothrow_t &t) noexcept { return ::operator new(n, t); }
void operator delete(void *p) noexcept
{
    if (!quarantineIfWatched(p)) {
        std::free(p);
    }
}
void operator delete[](void *p) noexcept { ::operator delete(p); }
void operator delete(void *p, std::size_t) noexcept { ::operator delete(p); }
void operator delete[](void *p, std::size_t) noexcept { ::operator delete(p); }
void operator delete(void *p, const std::nothrow_t &) noexcept { ::operator delete(p); }
void operator delete[](void *p, const std::nothrow_t &) noexcept { ::operator delete(p); }
#endif

#ifdef QTNG_UAF_TEST_POISON
static bool useProbe = true;
#endif

static void probeArm()
{
#ifdef QTNG_UAF_TEST_POISON
    watched = nullptr;
    watchedSize = 0;
    watching = true;
    poisoning = false;
    poisonHits = 0;
#endif
}

static void probeEnable()
{
#ifdef QTNG_UAF_TEST_POISON
    watching = false;
    poisoning = useProbe;
#endif
}

static void probeDisable()
{
#ifdef QTNG_UAF_TEST_POISON
    poisoning = false;
#endif
}

static bool probeCaptured()
{
#ifdef QTNG_UAF_TEST_POISON
    return watched != nullptr && watchedSize == privateSize;
#else
    return false;
#endif
}

static void probeReport(const char *scenario)
{
#ifdef QTNG_UAF_TEST_POISON
    qDebug().noquote() << "[diag]" << scenario << "ConditionPrivate size =" << privateSize
                       << "poison hits =" << poisonHits;
#else
    Q_UNUSED(scenario);
#endif
}

struct ScenarioState
{
    bool returned = false;
    bool result = false;
};

static bool waitUntilParked(const std::function<quint32()> &getting)
{
    for (int i = 0; i < 200; ++i) {
        if (getting() > 0) {
            // getting() is incremented before Condition::wait() yields, so give
            // the waiter a few eventloop ticks to actually enter Semaphore::acquire.
            Coroutine::msleep(10);
            return true;
        }
        Coroutine::msleep(1);
    }
    return false;
}

static int scenarioCondition()
{
    ScenarioState state;
    Condition *condition = nullptr;
    QScopedPointer<Coroutine> waiter;

    probeArm();
    condition = new Condition();
    if (!probeCaptured()) {
        qDebug().noquote() << "[warn] ConditionPrivate allocation not captured; relying on ASan";
    }

    waiter.reset(Coroutine::spawn([&state, &condition] {
        qDebug().noquote() << "[diag] condition waiter entered";
        state.result = condition->wait(UINT_MAX);
        qDebug().noquote() << "[diag] condition waiter resumed from Condition::wait";
        state.returned = true;
    }));
    if (!waitUntilParked([&condition] { return condition->getting(); })) {
        qDebug().noquote() << "[fail] waiter never parked on Condition";
        return 1;
    }

    probeEnable();
    qDebug().noquote() << "[test] destroying Condition while 1 waiter is parked (locks.cpp:387)";
    delete condition;  // ~Condition: notifyAll() 只调度唤醒，等待者此时还没恢复
    condition = nullptr;
    // 关掉探针后再让等待者恢复：未修复时上面的 delete 已经命中探针并隔离内存；
    // 修复后私有对象只会在 wait() 返回时才释放，那时已无人访问它。
    probeDisable();
    probeReport("condition");
    waiter->join();

    if (!state.returned || !state.result) {
        qDebug().noquote() << "[fail] waiter did not return cleanly";
        return 1;
    }
    qDebug().noquote() << "[pass] Condition waiter returned after owner destruction";
    return 0;
}

static int scenarioEvent()
{
    // Same bug through the path seen in the production backtrace:
    // Event::tryWait -> EventPrivate::wait -> Condition::wait.
    ScenarioState state;
    Event *event = nullptr;
    QScopedPointer<Coroutine> waiter;

    probeArm();
    event = new Event();
    if (!probeCaptured()) {
        qDebug().noquote() << "[warn] ConditionPrivate allocation not captured; relying on ASan";
    }

    waiter.reset(Coroutine::spawn([&state, &event] {
        qDebug().noquote() << "[diag] event waiter entered";
        state.result = event->tryWait(UINT_MAX);
        qDebug().noquote() << "[diag] event waiter resumed from Event::tryWait";
        state.returned = true;
    }));
    if (!waitUntilParked([&event] { return event->getting(); })) {
        qDebug().noquote() << "[fail] waiter never parked on Event";
        return 1;
    }

    probeEnable();
    qDebug().noquote() << "[test] set()+destroy Event while 1 waiter is parked (locks.cpp:387)";
    event->set();     // flag = true, notifyAll() schedules the wakeup
    delete event;     // ~Event 主动唤醒等待者；EventPrivate 由等待协程保活
    event = nullptr;
    probeDisable();
    probeReport("event");
    waiter->join();

    if (!state.returned || !state.result) {
        qDebug().noquote() << "[fail] waiter did not return cleanly";
        return 1;
    }
    qDebug().noquote() << "[pass] Event waiter returned after owner destruction";
    return 0;
}

static int scenarioEventDestroyedUnset()
{
    // 没有 set() 就析构 Event：~Event() 必须主动唤醒等待者，否则会永久挂起。
    ScenarioState state;
    Event *event = new Event();
    QScopedPointer<Coroutine> waiter(Coroutine::spawn([&state, event] {
        state.result = event->tryWait(UINT_MAX);
        state.returned = true;
    }));
    if (!waitUntilParked([event] { return event->getting(); })) {
        qDebug().noquote() << "[fail] waiter never parked on Event";
        return 1;
    }
    delete event;
    waiter->join();
    if (!state.returned) {
        qDebug().noquote() << "[fail] Event destruction left waiter parked";
        return 1;
    }
    qDebug().noquote() << "[pass] Event destruction wakes parked waiter";
    return 0;
}

static int scenarioSmoke()
{
    Event event;
    if (event.isSet() || event.tryWait(0)) {
        return 1;
    }
    event.set();
    if (!event.isSet() || !event.tryWait(0) || event.getting() != 0) {
        return 1;
    }
    event.clear();
    if (event.isSet()) {
        return 1;
    }

    Condition condition;
    bool notified = false;
    QSharedPointer<Coroutine> waiter(Coroutine::spawn([&condition, &notified] {
        notified = condition.wait(1000);
    }));
    for (int i = 0; i < 200 && condition.getting() == 0; ++i) {
        Coroutine::msleep(1);
    }
    if (condition.getting() == 0) {
        return 1;
    }
    condition.notify(1);
    waiter->join();
    if (!notified || condition.getting() != 0) {
        return 1;
    }

    bool timedOut = true;
    QSharedPointer<Coroutine> timeoutWaiter(Coroutine::spawn([&condition, &timedOut] {
        timedOut = !condition.wait(20);
    }));
    timeoutWaiter->join();
    if (!timedOut || condition.getting() != 0) {
        return 1;
    }

    Event linked, target;
    linked.link(target);
    linked.set();
    if (!target.isSet()) {
        return 1;
    }
    target.clear();
    linked.clear();
    linked.unlink(target);
    linked.set();
    if (target.isSet()) {
        return 1;
    }
    qDebug().noquote() << "[pass] Condition/Event smoke checks";
    return 0;
}

int main(int argc, char **argv)
{
    // Windows 上 Qt 5.15 默认把 qDebug() 送到调试器而不是 stderr；测试需要
    // 在 ctest/控制台里看到诊断日志，尤其是崩溃前的最后一行。
    qputenv("QT_FORCE_STDERR_LOGGING", "1");
    qputenv("QT_LOGGING_TO_CONSOLE", "1");
    QCoreApplication app(argc, argv);
    const char *scenario = argc > 1 ? argv[1] : "condition";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--no-poison") == 0) {
#ifdef QTNG_UAF_TEST_POISON
            useProbe = false;
            qDebug().noquote() << "[diag] control run: probe disabled";
#endif
        }
    }
    int result = 1;

    QSharedPointer<Coroutine> runner(Coroutine::spawn([&result, scenario] {
        if (!std::strcmp(scenario, "event")) {
            result = scenarioEvent();
        } else if (!std::strcmp(scenario, "event_unset")) {
            result = scenarioEventDestroyedUnset();
        } else if (!std::strcmp(scenario, "smoke")) {
            result = scenarioSmoke();
        } else {
            result = scenarioCondition();
        }
        callInEventLoop([] {
            if (QCoreApplication::instance()) {
                QCoreApplication::instance()->quit();
            }
        });
    }));
    startQtLoop();
    return result;
}
