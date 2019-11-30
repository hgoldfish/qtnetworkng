class EventLoopThread: public QThread
{
public:
    EventLoopThread();
    virtual ~EventLoopThread() override;
public:
    bool isIdle();
    bool isReady();
    QSharedPointer<Event> idleEvent();
public:
    bool kill(const QString &name);
    bool killall();
    int size() const;
    bool isEmpty() const;
    void spawnWithName(const QString &name, const std::function<void()> &func, bool replace = false);
    void spawn(const std::function<void()> &func);
    template<typename T, typename S> QList<T> map(std::function<T(S)> func, const QList<S> &l);
    template<typename S> void each(std::function<void(S)> func, const QList<S> &l);
protected:
    virtual void createEventLoop() = 0;
    QSharedPointer<EventLoopCoroutine> eventLoop;
private:
    CoroutineGroup *operations;
    QSharedPointer<Event> mIdleEvent;
};

class EvEventLoopThread: public EventLoopThread
{
protected:
    virtual void createEventLoop() override;
};

class QtEventLoopThread: public EventLoopThread
{
protected:
    virtual void createEventLoop() override;
};


class Channel
{
public:
    Channel();
public:
    void send(const QVariant &obj);
    QVariant recv();
};

class EventLoopPool
{
public:
    EventLoopPool(int maxThreads)
    ~EventLoopPool();
public:
    template<typename T, typename S> QList<T> map(std::function<T(S)> func, const QList<S> &l);
    template<typename S> void each(std::function<void(S)> func, const QList<S> &l);
    template<typename T, typename S> T apply(std::function(T(S)> func, S s);
};
