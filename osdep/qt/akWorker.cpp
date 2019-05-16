#include "akWorker.h"

#include <QUdpSocket>
#include <QNetworkInterface>
#include <QHostInfo>

#include "../../airkiss.h"

#include <QFile>
#include <QTextStream>
#include <stdio.h>

static int msgprint(const char *format, ...)
{
    char buf[80];
    int i;
    va_list vlist;

    va_start(vlist, format);
    i = vsprintf(buf, format, vlist);
    va_end(vlist);

    qDebug(buf);

    return i;
}

akWorker::akWorker()
{
    isrun = true;
    lenOut = false;
    cmpExit = true;
}

akWorker::~akWorker()
{
    isrun = false;
    wait();
}

void akWorker::start(QString file, bool nossid, short port)
{
    _file = file;
    _nossid = nossid;
    _port = port;
    QThread::start();
}

int akWorker::getframe(QString &str, QByteArray &fm)
{
    QStringList list;
    int len;

    fm.clear();
    list = str.split(":");
    if (list.count() == 1)
    {
        len = list.at(0).toInt();
    }
    else
    {
        QByteArray tmp;

        tmp = list.at(0).toStdString().c_str();
        fm = fm.fromHex(tmp);
        len = list.at(1).toInt();
    }

    return len;
}

void akWorker::fromfile()
{
    QFile fd;
    airkiss_context_t ac;
    airkiss_config_t acfg = {0,0,0,0};
    int status;
    int len;
    QString data;
    QTextStream in;
    QByteArray fm;

    fd.setFileName(_file);
    if (!fd.open(QIODevice::ReadOnly))
    {
        emit showMsg("open file fail");
        return;
    }

    in.setDevice(&fd);

    acfg.printf = msgprint;
    airkiss_init(&ac, &acfg);

    while (isrun)
    {
        char *pf = NULL;

        data = in.readLine();
        if (data.size() == 0)
            break;

        len = getframe(data, fm);
        if (len == 0)
            break;
        if (fm.size() > 0)
            pf = fm.data();

        status = airkiss_recv(&ac, pf, len);
        if (status == AIRKISS_STATUS_COMPLETE)
        {
            airkiss_result_t res;
            QString str;

            airkiss_get_result(&ac, &res);
            str = str.sprintf("ssid: %s, pwd: %s\n", res.ssid, res.pwd);
            emit showMsg(str);
            break;
        }
        else if (status == AIRKISS_STATUS_CHANNEL_LOCKED)
        {
            emit showMsg("锁定通道");
        }

        msleep(1);
    }
}

void akWorker::fromudp_bc()
{
    QUdpSocket *ser;
    char buf[1024];
    airkiss_context_t ac;
    int status = -1;

    ser = new QUdpSocket;
    if (!ser->bind(QHostAddress::AnyIPv4, _port, QUdpSocket::ShareAddress))
    {
        emit showMsg("bind fail");
        goto _out;
    }

    airkiss_init(&ac, NULL);

    while (isrun)
    {
        int len;

        if (ser->hasPendingDatagrams())
        {
            len = ser->pendingDatagramSize();
            ser->readDatagram(buf, len);
            if (lenOut)
            {
                QString s;

                s = s.sprintf("%X", len);
                emit showMsg(s);
            }

            if (_nossid)
                status = airkiss_recv_nossid(&ac, NULL, len);
            else
                status = airkiss_recv(&ac, NULL, len);

            if (status == AIRKISS_STATUS_COMPLETE)
            {
                airkiss_result_t res;
                QString str;

                airkiss_get_result(&ac, &res);
                if (_nossid)
                    str = str.sprintf("ssidcrc: %X, pwd: %s\n", res.ssid_crc, res.pwd);
                else
                    str = str.sprintf("ssid: %s, pwd: %s\n", res.ssid, res.pwd);
                emit showMsg(str);

                airkiss_change_channel(&ac);
                if (cmpExit)
                    break;
            }
        }
    }

_out:
    delete ser;
}

void akWorker::run()
{
    if (_file.isEmpty())
        fromudp_bc();
    else
        fromfile();

    emit showMsg("退出解析");
}
