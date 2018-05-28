#include <QApplication>
#include <QTextBrowser>
#include "../../qtnetworkng.h"

using namespace qtng;

class HtmlWindow: public QTextBrowser
{
public:
    HtmlWindow()
        :operations(new CoroutineGroup) {
        operations->spawn([this] {
            qtng::Coroutine::sleep(1);
            HttpSession session;
            HttpResponse response = session.get("http://qtng.org/");
            if(response.isOk()) {
                setHtml(response.html());
            } else {
                setHtml("failed");
            }
        });
    }

    ~HtmlWindow() {
        delete operations;
    }
private:
    CoroutineGroup *operations;
};


int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    HtmlWindow w;
    w.show();
    return startQtLoop();
}
