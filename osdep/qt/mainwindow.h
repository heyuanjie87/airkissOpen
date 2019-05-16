#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class akWorker;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void showMsg(QString m);
    void workerExit();

private slots:
    void on_pbst_clicked();

    void on_pbparese_clicked();

    void on_pbpath_clicked();

    void on_cblen_toggled(bool checked);

    void on_cbcmpe_toggled(bool checked);

private:
    Ui::MainWindow *ui;
    akWorker *wk;
};

#endif // MAINWINDOW_H
