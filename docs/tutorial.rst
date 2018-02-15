Tutorial of QtNetworkNg 
========================


Coroutines have `Event`, `Semaphore` and `RLock` like threads. but they are used rarely, because coroutines are running in single thread. Coroutines can also communicate each other using `Queue` like threads. Here is an example using `Event` to implement pausing. ::

    //sending coroutine.
    notPaused.wait()
    conn.sendall(data);
    
    //pause button
    notPaused.clear()
    
    //resume button
    notPaused.set()

