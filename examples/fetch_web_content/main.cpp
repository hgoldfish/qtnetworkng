#include <QApplication>
#include <QTextBrowser>
#include "../../qtnetworkng.h"

using namespace qtng;

class HtmlWindow: public QTextBrowser
{
public:
    HtmlWindow();
    virtual ~HtmlWindow() override;
private:
    CoroutineGroup *operations;
};

HtmlWindow::HtmlWindow()
    :operations(new CoroutineGroup)
{
    operations->spawn([this] {
        Coroutine::sleep(1);
        HttpSession session;
        HttpResponse response = session.get("http://www.example.com/");
        if(response.isOk()) {
            setHtml(response.html());
        } else {
            setHtml("failed");
        }
    });
}

HtmlWindow::~HtmlWindow()
{
    delete operations;
}

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    HtmlWindow w;
    w.show();
    return startQtLoop(); // Qt GUI application start the eventloop using startQtLoop() instead of app.exec()
}
