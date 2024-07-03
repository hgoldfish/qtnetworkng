#include <QtCore/qdebug.h>
#include "qtnetworkng.h"

using namespace qtng;

int main()
{
    Iterator<int> itor([] (Iterator<int> &itor) {
        for (int i = 0; i < (1024 * 8 + 1024 / 4 + 7); ++i) {
            itor.yield(i);
        }
    });

    int i;
    while (itor.next(i)) {
        qDebug() << i;
    }
    return 0;
}
