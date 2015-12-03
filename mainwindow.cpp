/*
 * This file is part of LuHPoS project. This software may be used and distributed
 * according to the terms of the GNU General Public License version 3, incorporated herein by reference
 * at repository: https://github.com/otavioarj/KiInjector
 =]
*/

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>


#define Version "Ki Injector 2.2 - otavioarj"




void delay( int millisecondsToWait )
{
    QTime dieTime = QTime::currentTime().addMSecs( millisecondsToWait );
    while( QTime::currentTime() < dieTime )
    {
        QCoreApplication::processEvents( QEventLoop::AllEvents, 100 );
    }
}




MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
   // isInitialized = false;
    ui->setupUi(this);
    this->setFixedSize(this->size());
  //  myth= new MyThread;
  //  connect(myth, SIGNAL(valueChanged(int)),this, SLOT(onValueChanged(int)));
    verbose=false;
    ainject=false;
    if((f=fopen("conf.txt","r"))!=NULL)
    {
        char *exe,*dll;
        exe=new char[64];
        dll=new char[512];
        if(fscanf(f,"%s : %s\n",exe,dll)==2)
        {
          ui->line1->setText(exe);
          ui->line2->setText(dll);
        }
        free(exe);
        free(dll);
        fclose(f);
    }

    MError= NULL;
}

MainWindow::~MainWindow()
{
    delete ui;
}
/*
void MainWindow::onValueChanged(int count)
{
    char out[30];
    sprintf(out,"Closing injector in %d seconds...",count);
    ui->label_3->setText(out);
    if(!count)
      exit(1);
    if(count==3)
       Beep(750,350);

}*/



int  MainWindow::IsUserAdmin()
{
    int b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = AllocateAndInitializeSid(&NtAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0, 0, 0, 0, 0, 0,&AdministratorsGroup);
    if(b)
    {
        if (!CheckTokenMembership( NULL, AdministratorsGroup, &b))
        {
            b = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }

    return(b);
}




void MainWindow::on_toolButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open Dll"),"",tr("*.dll"));
    ui->line2->setText(fileName);
}


/*void MainWindow::on_toolButton_2_clicked()
{
    Dialog a;
    a.setModal(true);
    connect(a, SIGNAL(Line1Changed(QString)), this, SLOT(setLine1(QString)));
    a.exec();

   unsigned long int aProcesses[1024], cbNeeded, cProcesses;
   while( a.isVisible())
   {
    if (!EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
     errorp("[-] EnumProcesses failed: " );
    cProcesses = cbNeeded / sizeof(int);
    //PrintProcessNameAndID( aProcesses , ProcName,cProcesses);

  }
}*/

void MainWindow::errorp(const char * str,bool e)
{

    char * output=(char *)malloc(strlen(str)+6);   
    sprintf(output,"%s! E:%d .",str,(int) GetLastError() );
    //cout<< output << ". ."<< endl;
    //Beep( 350, 950 );
   // QMessageBox::critical(NULL, "Error!",output);
    ui->plainTextEdit->appendPlainText(output);
    const size_t len = strlen(output) + 1;
    HGLOBAL hMem =  GlobalAlloc(GMEM_MOVEABLE, len);
    memcpy(GlobalLock(hMem), output, len);
    GlobalUnlock(hMem);
    OpenClipboard(0);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
    free(output);
    if(e)
    {
     ui->checkBox->setEnabled(false);
     ui->pushButton->setEnabled(false);
     Beep(750,350);
     char out[30];
     for(int c=4;c>0;c--)
     {
      sprintf(out,"Closing injector in %d seconds...",c);
      ui->label_3->setText(out);
      delay(1000);
     }
      exit(1);
    // myth->start();
    }

}


void MainWindow::on_checkBox_toggled(bool checked)
{
   //errorp("Execute as Admin!!",true);
    if(ui->line1->text().length()<1 && ui->line2->text().length()<1)
    {
       ui->checkBox->setChecked(false);
       return;
    }

    bool closeme=false;
    if(!ainject){
    QMessageBox::StandardButton resBtn = QMessageBox::question( this, Version,
                                                           tr("Auto close on injection?\n"), QMessageBox::No | QMessageBox::Yes,QMessageBox::Yes);
    if (resBtn == QMessageBox::Yes)
       closeme=true;}


    ainject=checked;
    ui->pushButton->setEnabled(!checked);
    if(checked) on_pushButton_clicked();
    else ui->label_3->setText("");
    if(ainject & checked)
    {
         ui->pushButton->setEnabled(!checked);
         if(!closeme)
          ui->checkBox->setChecked(false);
          ainject=false;
          delay(250);
          ui->label_3->clear();
    }

    if(closeme)
        exit(1);


}

void MainWindow::on_checkBox_2_toggled(bool checked)
{

      verbose=checked;

}

void MainWindow::on_commandLinkButton_clicked()
{
     ui->label_3->setText(Version);
}




void MainWindow::on_pushButton_clicked()
{

    int pID=0,pid2=1;
    if((f=fopen("conf.txt","w"))!=NULL)
    {

        fprintf(f,"%s : %s \n",ui->line1->text().toStdString().c_str(),ui->line2->text().toStdString().c_str());
        fclose(f);
    }
    do {

    if(ui->line1->text().length()>1 && ui->line2->text().length()>1 && pID!=pid2)
    {


        char *proc;
        proc=(char *)malloc(ui->line1->text().length()>1);
        strcpy(proc,ui->line1->text().toStdString().c_str());
        if(strlen(proc)<4 || strncmp(proc+(strlen(proc)-4),".exe",4))
        {
          errorp("[-] This isn't a process executable(.exe)",false);
          ui->line1->setText("");
          ainject=!ainject;
          return;
        }
        pid2=pID;
        pID = GetTargetThreadIDFromProcName(proc);
        if(!pID)
          return;

        if(verbose)
        {
         char *out;out=(char*)malloc(25);
         sprintf(out,"[+] Process PID: %d",pID);
         ui->plainTextEdit->appendPlainText(out);
         free(out);
        }
         free(proc);
        if(!Inject(pID, ui->line2->text().toStdString().c_str()))
         {
          errorp("[-] DLL cannot be loaded!",true);
          Beep( 750, 350 );
         }
        else
        {
          ui->plainTextEdit->appendPlainText("[+] DLL sucefully loaded!");
          Beep( 750, 150 );
        }
    }
    delay(atoi(ui->line1_2->text().toStdString().c_str())+25);
    } while( ui->checkBox_3->isChecked());
}



int MainWindow::Inject(int pID, const char * DLL_NAME)
{
    HANDLE Proc;
    //HMODULE hLib;
    LPVOID RemoteString, LoadLibAddy;
    if(ui->comboBox->currentIndex()<=1)
    {
        Proc = OpenProcess(CREATE_THREAD_ACCESS , FALSE, pID);
        if(!Proc)
            errorp("[-] OpenProcess2 failed.",true);

        if(!PathFileExists(DLL_NAME))
            errorp("[-] DLL can't be found.",false);

        if((LoadLibAddy= (void *)GetProcAddress(GetModuleHandle("kernel32.dll"),(LPCSTR) "LoadLibraryA"))==NULL)
            errorp("[-] GetProcAddress failed.",true );
        if(verbose)
        {
            char *out;out=(char*)malloc(25);
            sprintf(out,"[*] LoadLibrary: %x ",(unsigned int)LoadLibAddy);
            ui->plainTextEdit->appendPlainText(out);
            free(out);
        }
        // Allocate space in the process for our DLL
        if((RemoteString = VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))==NULL)
            errorp("[-] VirtualAllocEx failed.",true );

        // Write the string name of our DLL in the memory allocated
        if(!WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL))
            errorp("[-] WriteProcessMemory failed.",true );
    }

    // Load our DLL
    switch(ui->comboBox->currentIndex())
    {
    case 0:
        if(!IsUserAdmin())
            errorp("[-] Admin needed for this injection!",true);
        if(CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL)==NULL)
            errorp("[-] CreateRemoteThread failed.",true);
        CloseHandle(Proc);
        break;
    case 1:
        if(!IsUserAdmin())
            errorp("[*] Not Admin. If it fails, try as Admin!",false);
        if(NtCreateThreadEx(Proc, LoadLibAddy, (LPVOID)RemoteString)==NULL)
            errorp("[-] NtCreateThreadEx failed.",true);
        CloseHandle(Proc);
        break;
    case 2:
        if(!IsUserAdmin())
            errorp("[*] Not Admin! If it fails, try as Admin!",false);
        char *DLL;
        DLL=(char *)malloc(strlen(DLL_NAME));
        strcpy(DLL,DLL_NAME);
        if(!MapRemoteModule(pID, DLL))
        {
          free(DLL);
          ui->plainTextEdit->appendPlainText(MError);
          free(MError);
          errorp("[-] ManualMap failed.",true);
        }
         free(DLL);
        break;
    default:
        errorp("[-] Inject method invalid!",true);
    }

    return 1;
}


DWORD MainWindow::PrintProcessNameAndID( DWORD processID[],const char * ProcName, int cProcesses)
{
    char szProcessName[MAX_PATH];
    HANDLE hProcess;
    HMODULE hMod;
    DWORD cbNeeded;

     //QMessageBox::critical(NULL, "Error!",out);
    // Get a handle to the process.
    if(verbose)
    {
     char *out;out=(char*)malloc(55);
     sprintf(out,"[+] Found: %d process, injectable list: ",cProcesses);
     ui->plainTextEdit->appendPlainText(out);
     free(out);
    }
    for(int a=0; a< cProcesses; a++)
     {
       if((hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE, processID[a]))==NULL)
          continue;

       if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod),&cbNeeded) )
        {
          GetModuleBaseName( hProcess, hMod, szProcessName,sizeof(szProcessName)/sizeof(char));
          if(verbose)
          {
           char *out;out=(char*)malloc(35);
           sprintf(out,"[%d]: %s ",a,szProcessName);
           ui->plainTextEdit->appendPlainText(out);
           free(out);
          }
          if(!strcmp(szProcessName,ProcName))
           return processID[a];

        }
       else
         CloseHandle( hProcess );
     }
    return 0;
}



DWORD MainWindow::GetTargetThreadIDFromProcName(const char * ProcName)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    char out[30];
    unsigned int result=0;
    short int wait;
    wait= atoi(ui->line1_2->text().toStdString().c_str());
    while(ainject || !result)
    {
      if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
       errorp("[-] EnumProcesses failed.",true );
      cProcesses = cbNeeded / sizeof(DWORD);
      result=PrintProcessNameAndID( aProcesses , ProcName,cProcesses);
      if( result)
      {
        //count << endl;
        return result;
      }
      else if (!ainject)
      {
          sprintf(out,"[-] Process %s not found.",ProcName);
          errorp(out,false);
          return 0;
      }

      //QMessageBox::critical(NULL, "Error!","Preso");

          sprintf(out,"Waiting for %s ..  .",ProcName);
          ui->label_3->setText(out);
          delay(wait/2);
          sprintf(out,"Waiting for %s . . .",ProcName);
          ui->label_3->setText(out);
          delay(wait);
          sprintf(out,"Waiting for %s .  ..",ProcName);
          ui->label_3->setText(out);
          delay(wait/2);
    }
    return 0;
}


void MainWindow::on_pushButton_2_clicked()
{
     ui->plainTextEdit->clear();
}

void MainWindow::closeEvent (QCloseEvent *event)
{
    if(ainject)
    {

         QMessageBox::StandardButton resBtn = QMessageBox::question( this, Version,
                                                                tr("Are you sure?\n"), QMessageBox::No | QMessageBox::Yes,QMessageBox::Yes);
    if (resBtn == QMessageBox::Yes)
    {
        ainject=false;
        event->accept();
    }
    else
        event->ignore();
    }
}



HANDLE  MainWindow::NtCreateThreadEx(HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpSpace)
{
    //The prototype of NtCreateThreadEx from undocumented.ntinternals.com
    typedef DWORD (WINAPI * functypeNtCreateThreadEx)(
        PHANDLE                 ThreadHandle,
        ACCESS_MASK             DesiredAccess,
        LPVOID                  ObjectAttributes,
        HANDLE                  ProcessHandle,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        LPVOID                  lpParameter,
        BOOL                    CreateSuspended,
        DWORD                   dwStackSize,
        DWORD                   Unknown1,
        DWORD                   Unknown2,
        LPVOID                  Unknown3
    );

    HANDLE                      hRemoteThread           = NULL;
    HMODULE                     hNtDllModule            = NULL;
    functypeNtCreateThreadEx    funcNtCreateThreadEx    = NULL;


    //Get handle for ntdll which contains NtCreateThreadEx
    hNtDllModule = GetModuleHandle( "ntdll.dll" );
    if ( hNtDllModule == NULL )
    {
        return NULL;
    }

    funcNtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress( hNtDllModule, "NtCreateThreadEx" );
    if ( !funcNtCreateThreadEx )
    {
        return NULL;
    }

    funcNtCreateThreadEx( &hRemoteThread,  GENERIC_ALL, 0, hProcess, (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, FALSE, 0, 0, 0, NULL );

    return hRemoteThread;
}
