/*
 * This file is part of LuHPoS project. This software may be used and distributed
 * according to the terms of the GNU General Public License version 3, incorporated herein by reference
 * at repository: https://github.com/otavioarj/KiInjector
 =]
*/

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QCoreApplication>
#include <QTime>
//#include "mythread.h"


//#include <iostream>
#include "inject.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();



private slots:
    void on_checkBox_toggled(bool checked);
    void on_toolButton_clicked();
  //  void showEvent( QShowEvent *event );
    int IsUserAdmin();
     void errorp(const char * str, bool a);
     DWORD PrintProcessNameAndID( DWORD processID[],const char * ProcName, int cProcesses);

    // void on_toolButton_2_clicked();

 //   void setLine1(const QString &newText);
 //   void onValueChanged(int);
    void on_checkBox_2_toggled(bool checked);
    void on_commandLinkButton_clicked();

    void on_pushButton_clicked();
    DWORD GetTargetThreadIDFromProcName(const char * ProcName);
    int Inject(int pID, const char * DLL_NAME);
    HANDLE NtCreateThreadEx(HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpSpace);
    void closeEvent (QCloseEvent *event);
    void on_pushButton_2_clicked();


private:
    Ui::MainWindow *ui;
    int isInitialized;
    bool verbose;
    bool ainject;
    FILE *f;

};


#endif // MAINWINDOW_H
