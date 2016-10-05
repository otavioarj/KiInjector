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
     void errorp(const char * str, bool);
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



    void on_radioButton_clicked();

    void on_comboBox_currentIndexChanged(int index);

    void on_checkBox_4_stateChanged(int arg1);

    void on_checkBox_9_toggled(bool checked);

    void on_toolButton_2_clicked();

    void on_comboBox_2_activated(const QString &arg1);

    void on_checkBox_10_toggled(bool checked);


    void on_checkBox_3_clicked(bool checked);

private:
    Ui::MainWindow *ui;
    int isInitialized;
    bool verbose;
    bool ainject;
    bool obs;
    FILE *f;

};

void delay( int millisecondsToWait );
#endif // MAINWINDOW_H
