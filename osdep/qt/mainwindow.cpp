#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "akWorker.h"
#include "../../airkiss.h"

#include <QFileDialog>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    wk = 0;
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showMsg(QString m)
{
    ui->peres->appendPlainText(m);
}

void MainWindow::workerExit()
{
    if (wk)
    {
        QString str = "启动";

        ui->pbparese->setText(str);
        ui->pbst->setText(str);

        delete wk;
        wk = NULL;
    }
}

void MainWindow::on_pbst_clicked()
{
    if (wk)
    {
        delete wk;
        wk = 0;
        ui->pbst->setText(QString("启动"));
    }
    else
    {
        wk = new akWorker;

        connect(wk, SIGNAL(showMsg(QString)),
                this, SLOT(showMsg(QString)));
        connect(wk, SIGNAL(finished()),
                this, SLOT(workerExit()));

        ui->peres->clear();
        wk->lenOut = ui->cblen->isChecked();
        wk->cmpExit = ui->cbcmpe->isChecked();
        wk->start("", ui->nossid->isChecked(), ui->sbport->value());

        ui->pbst->setText(QString("停止"));
    }
}

void MainWindow::on_pbparese_clicked()
{
    QString file;

    file = ui->lepath->currentText();
    if (file.isEmpty())
        return;

    if (wk)
    {
        delete wk;
        wk = 0;
        ui->pbparese->setText(QString("启动"));
    }
    else
    {
        wk = new akWorker;

        connect(wk, SIGNAL(showMsg(QString)),
                this, SLOT(showMsg(QString)));
        connect(wk, SIGNAL(finished()),
                this, SLOT(workerExit()));

        wk->start(file, ui->nossid->isChecked());

        ui->pbparese->setText(QString("停止"));
    }
}

void MainWindow::on_pbpath_clicked()
{
    QString dir;

    dir = QFileDialog::getOpenFileName(this, "选择文件", "./");
    if (!dir.isEmpty())
    {
       ui->lepath->setCurrentText(dir);
    }
}

void MainWindow::on_cblen_toggled(bool checked)
{
    if (wk)
        wk->lenOut = checked;
}

void MainWindow::on_cbcmpe_toggled(bool checked)
{
    if (wk)
        wk->cmpExit = checked;
}

void MainWindow::on_seqgen_clicked()
{
    QString str;


}
