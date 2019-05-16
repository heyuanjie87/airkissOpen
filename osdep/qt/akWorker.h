#ifndef AKWORKER_H
#define AKWORKER_H

#include <QObject>
#include <QThread>

class QFile;

class akWorker : public QThread
{
    Q_OBJECT

public:
    akWorker();
    ~akWorker();

    void start(QString file = "", bool nossid = true, short port = 10000);

signals:
    showMsg(QString m);

private:
    void run();

    void fromfile();
    void fromudp_bc();

    int getframe(QString &str, QByteArray &fm);

public:
    bool lenOut;
    bool cmpExit;

private:
    bool isrun;
    QString _file;
    bool _nossid;
    short _port;
};

#endif // AKWORKER_H
