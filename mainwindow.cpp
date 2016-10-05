#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QProcess>
#define error(X, Y) {errorp(X,Y); return 0;}
#define uimsg(X) ui->plainTextEdit->appendPlainText(X);


#define Version "Ki Injector 3.6 - otavioarj"

int showin(DWORD processID ){
HWND hWnd=NULL;
hWnd=FindWindowFromProcessId(processID);
if(hWnd==NULL)
{
  MMapError("Can't display process windows.");
  return 0;
}
else
{
ShowWindow(hWnd,SW_SHOWMAXIMIZED);
ShowWindow(hWnd, SW_RESTORE);
return 1;
}
}

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
   // this->setWindowFlags(Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::WindowMinimizeButtonHint );// | Qt::WindowCloseButtonHint);
    this->setFixedSize(this->size());
  //  myth= new MyThread;
  //  connect(myth, SIGNAL(valueChanged(int)),this, SLOT(onValueChanged(int)));
    verbose=false;
    ainject=false;
    hijack=0;
    hijack_stub=false;
    obs=false;
    ui->comboBox_2->setVisible(false);
    QString no=QCoreApplication::applicationDirPath();
    //QFileInfo( QCoreApplication::applicationFilePath()).fileName();
    if (no.contains("AppData"))
    {
        this->setWindowTitle(QFileInfo(QCoreApplication::applicationFilePath()).fileName());
        obs=true;
        no=QFileInfo(QCoreApplication::applicationFilePath()).fileName().replace("exe","dll");
        ui->radioButton->setChecked(true);
        ui->radioButton->setEnabled(false);
    }

    if((f=fopen("conf.txt","r"))!=NULL)
    {
        char *exe,*dll;
        exe=new char[64];
        dll=new char[512];
        if(fscanf(f,"%s : %s\n",exe,dll)==2)
        {
          ui->line1->setText(exe);
          if(obs)
            ui->line2->setText((QCoreApplication::applicationDirPath().replace('/', '\\')).append('\\').append(no));
           // QCoreApplication::applicationDirPath()
          else
          ui->line2->setText(dll);
        }
        free(exe);
        free(dll);
        fclose(f);
    }


    MError= NULL;
   /* */
}

MainWindow::~MainWindow()
{
    delete ui;
}




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



void MainWindow::errorp(const char * str,bool e)
{

    char * output=(char *)malloc(strlen(str)+6);   
    sprintf(output,"%s! E:%d .",str,(int) GetLastError() );
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
     ainject=false;
     Beep(750,350);    
     ui->label_3->setText("[-] Injection aborted...");
     ui->checkBox_3->setChecked(false);
     ui->checkBox->setChecked(false);
     ui->line1->setDisabled(false);
     ui->line2->setDisabled(false);

    }


}


void MainWindow::on_checkBox_toggled(bool checked)
{
   ui->label_3->clear();
   //errorp("Execute as Admin!!",true);
    if(ui->line1->text().length()<1 && ui->line2->text().length()<1)
    {
       ui->checkBox->setChecked(false);
       return;
    }

    bool closeme=false;
    if(!ainject && checked){
    QMessageBox::StandardButton resBtn = QMessageBox::question( this, Version,
                                                           tr("Auto close on injection?\n"), QMessageBox::No | QMessageBox::Yes,QMessageBox::Yes);
    if (resBtn == QMessageBox::Yes)
       closeme=true;}


    ainject=checked;
    ui->pushButton->setEnabled(!checked);
    if(checked) on_pushButton_clicked();
    else ui->label_3->clear();
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

    int pID=0,pid2=1,re_count=0,count=atoi(ui->line1_3->text().toStdString().c_str());
    char *proc;
    char out[30];
    short int wait;
    wait= atoi(ui->line1_2->text().toStdString().c_str());

    if(ui->line1->text().length()<4 && ui->line2->text().length()<3 )
    {
        errorp("[-] This isn't a valid a process/dll name",false);
        return;
    }

    if(!obs && (f=fopen("conf.txt","w"))!=NULL)
    {

        fprintf(f,"%s : %s \n",ui->line1->text().toStdString().c_str(),ui->line2->text().toStdString().c_str());
        fclose(f);
    }

    ui->line1->setDisabled(true);
    ui->line2->setDisabled(true);
    ui->tabWidget->setCurrentIndex(0);
    proc=(char *)malloc(ui->line1->text().length());
    strncpy(proc,ui->line1->text().toStdString().c_str(),ui->line1->text().length());
    proc[ui->line1->text().length()]='\0';
    if(strlen(proc)<4 || strncmp(proc+(strlen(proc)-4),".exe",4))
    {
      errorp("[-] This isn't a process executable(.exe)",false);
      //qDebug("%s\n",proc);
      ui->line1->setText("");
      ainject=!ainject;
      ui->checkBox_3->setChecked(false);
      ui->line1->setDisabled(false);
      ui->line2->setDisabled(false);
      free(proc);
      return;
    }


    do {
        pID = GetTargetThreadIDFromProcName(proc);
        if(!pID)
        {
          errorp("[-] Can't get pID from process!",true);
          ui->checkBox_3->setChecked(false);
          ui->line1->setDisabled(false);
          ui->line2->setDisabled(false);
          free(proc);
          return;
        }

      if(pID!=pid2)
       {

        if(verbose)
        {
         char *out;out=(char*)malloc(25);
         sprintf(out,"[+] Process PID: %d",pID);
         ui->plainTextEdit->appendPlainText(out);
         free(out);
        }

        if(ui->checkBox_8->isChecked())
        {
            stubs obj;
            obj.in=(void *)find_undll;
            obj.fin=(void *)find_end;
            param p;
            DWORD as[3];
            fix_undll(as);
            p.data=&as;
            p.a=sizeof(as);
           if(mytrick ( pID, obj, p,true))
           {
            ui->plainTextEdit->appendPlainText("[+] Bypass Stub ran!");
            if(hijack==(HMODULE)1)
                 ui->plainTextEdit->appendPlainText("[+] Bypassed Dll Notify!");
            else
                 ui->plainTextEdit->appendPlainText("[-] Bypass failed :(");
           }
           else
           {
               errorp(MError,false);
               free(MError);
               errorp("[-] Bypass failed!",true);
           }
        }

        if(!Inject(pID, ui->line2->text().toStdString().c_str()))
         {
          errorp("[-] DLL can't be loaded!",true);
          free(proc);
          Beep( 750, 350 );
          return;
         }
        else
        {
          ui->plainTextEdit->appendPlainText("[+] DLL sucefully loaded!");
          Beep( 750, 150 );
          if (count)
           re_count++;
          else
            re_count=-1;

          if(ui->checkBox_7->isChecked())
          {
              char *dname,*dl;
              int tam=0,cn=0;
              tam=strlen(ui->line2->text().toStdString().c_str());
              dname=(char *)malloc(tam);
              strncpy(dname,ui->line2->text().toStdString().c_str(),tam);
              for(cn=tam;cn>0;cn--)
               if(dname[cn]=='/')
                   break;
              cn++;
              dl=(char *)malloc(tam-cn);
              strncpy(dl,dname+cn,tam-cn);
              dl[tam-cn]='\0';
              HMODULE hDLL=NULL;
             ui->plainTextEdit->appendPlainText("[*] Hiding DLL");
             if((hDLL=GetRemoteModuleHandle(pID,dl)))
             {
                 if(ui->checkBox_5->isChecked())
                     hijack=hDLL;
                 stubs obj;
                 obj.in=(void *)HideInList;
                 obj.fin=(void *)Hide_end;
                 param p;
                 p.data=&hDLL;
                 p.a=sizeof(hDLL);
                if(mytrick ( pID, obj, p,true))
                 ui->plainTextEdit->appendPlainText("[+] DLL Hidden");
                else
                {
                    errorp(MError,false);
                    free(MError);
                    errorp("[-] Hidding failed.",true);
                }

             }
             else
              errorp("[-] Can't find DLL on process!",false);
             free(dl);
             free(dname);
          }

          if(ui->checkBox_5->isChecked())
          {
             ui->plainTextEdit->appendPlainText("[*] Wiping DLL Header");

             char *dname,*dl;
             int tam=0,cn=0;
             tam=strlen(ui->line2->text().toStdString().c_str());
             dname=(char *)malloc(tam);
             strncpy(dname,ui->line2->text().toStdString().c_str(),tam);
             for(cn=tam;cn>0;cn--)
              if(dname[cn]=='/')
                  break;
             cn++;
             dl=(char *)malloc(tam-cn);
             strncpy(dl,dname+cn,tam-cn);
             dl[tam-cn]='\0';
             void * wiper;
             HMODULE hDLL=NULL;
             if(ui->checkBox_7->isChecked() || ui->comboBox->currentIndex()==2 || (hDLL=GetRemoteModuleHandle(pID,dl)))
              {
               DWORD OldProtect = 0;
               HANDLE Proc=NULL;
               wiper=malloc(4096);
               showin(pID);
               Proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pID);
               if(ui->checkBox_7->isChecked() ||  ui->comboBox->currentIndex()==2) //(ui->comboBox->currentIndex()==3)
                hDLL=hijack;
               VirtualProtect(hDLL, 4096, PAGE_READWRITE, &OldProtect);
               memset(wiper,0x0,4096);
               WriteProcessMemory(Proc,hDLL,wiper,4096,NULL);
            //   qDebug("Ae2 \n",dl);
               VirtualProtect(hDLL, 4096, OldProtect,NULL);
               ui->plainTextEdit->appendPlainText("[+] DLL Header wiped!");
               free(wiper);
               CloseHandle(Proc);
              }
             else
                errorp("[-] Can't wipe DLL Header!",false);
             free(dl);
             free(dname);
          }


        }
         pid2=pID;
       }
      sprintf(out,"Waiting for %s ..  .",proc);
      ui->label_3->setText(out);
      delay(wait/2);
      sprintf(out,"Waiting for %s .  ..",proc);
      ui->label_3->setText(out);
      delay(wait/2);
    } while( ui->checkBox_3->isChecked() && ainject && re_count < count );
    ui->checkBox_3->setChecked(false);
    ui->line1->setDisabled(false);
    ui->line2->setDisabled(false);
    ui->label_3->clear();
    free(proc);
}



int MainWindow::Inject(int pID, const char * DLL_NAME)
{
    HANDLE Proc=NULL;
    //HMODULE hLib;
    LPVOID RemoteString=NULL, LoadLibAddy=NULL, memwipe=NULL;
    pvoids p={NULL,NULL,NULL};
    if(ui->checkBox_9->isChecked())
    {
      uimsg("[*] PreInject Delay...");
      delay(ui->line1_5->text().toInt());
    }
    char *DLL;
    if(ui->comboBox->currentIndex()<=1)
    {
        Proc = OpenProcess(CREATE_THREAD_ACCESS , FALSE, pID);
        if(!Proc)
            error("[-] OpenProcess2 failed.",true);

        if(!PathFileExists(DLL_NAME))
            error("[-] DLL can't be found.",true);
        if(ui->checkBox_4->isChecked())
        {
          p=LoadMan((char * )DLL_NAME,Proc);
          if(p.p1==NULL || p.p2==NULL)
          {
              errorp(MError,false);
              free(MError);
              error("[-] Load_stub failed :(",true);
          }
          LoadLibAddy=p.p1;
          RemoteString=p.p2;
        }
        else
        {
            if((LoadLibAddy= (void *)GetProcAddress(GetModuleHandle("kernel32.dll"),(LPCSTR) "LoadLibraryA"))==NULL)
                error("[-] GetProcAddress failed.",true );
            if(verbose)
            {
                char *out;out=(char*)malloc(25);
                sprintf(out,"[*] LoadLibrary: %x ",(unsigned int)LoadLibAddy);
                ui->plainTextEdit->appendPlainText(out);
                free(out);
            }
            // Allocate space in the process for our DLL
            if((RemoteString = VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))==NULL)
                error("[-] VirtualAllocEx failed.",true );

            // Write the string name of our DLL in the memory allocated
            if(!WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL))
                error("[-] WriteProcessMemory failed.",true );
       }
    }

    // Load our DLL
    switch(ui->comboBox->currentIndex())
    {
    case 0:
        if(!IsUserAdmin())
            error("[-] Admin needed for this injection!",true);
        uimsg("[*] Using CreateRemoteThread.");
        if(CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL)==NULL)
         {errorp("[-] CreateRemoteThread failed.",true); return 0;}
        else if(ui->checkBox_6->isChecked())
        {
            memwipe=malloc(128);
            memset(memwipe,0x0,128);           
            showin(pID);
            delay(ui->line1_4->text().toInt()*1000);
            WriteProcessMemory(Proc,p.p1,memwipe,124,NULL);
            WriteProcessMemory(Proc,p.p2,memwipe,124,NULL);
            VirtualFreeEx(Proc,p.p1,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p2,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p3,0,MEM_RELEASE);
            free(memwipe);
        }
        CloseHandle(Proc);
        break;
    case 1:
        if(!IsUserAdmin())
            error("[*] Not Admin. If it fail, run as Admin!",false);
        uimsg("[*] Using NtCreateThreadEx.");
        if(NtCreateThreadEx(Proc, LoadLibAddy, (LPVOID)RemoteString)==NULL){
            errorp("[-] NtCreateThreadEx failed.",true); return 0;}
        else if(ui->checkBox_6->isChecked())
         {

            showin(pID);
            delay(ui->line1_4->text().toInt()*1000);
            memwipe=malloc(128);
            memset(memwipe,0x0,128);
            WriteProcessMemory(Proc,p.p1,memwipe,124,NULL);
            WriteProcessMemory(Proc,p.p2,memwipe,124,NULL);
            VirtualFreeEx(Proc,p.p1,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p2,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p3,0,MEM_RELEASE);
            free(memwipe);
         }
        CloseHandle(Proc);
        break;
    case 2:
        if(!IsUserAdmin())
            error("[*] Not Admin! If it fail, run as Admin!",false);
        DLL=(char *)malloc(strlen(DLL_NAME));
        strcpy(DLL,DLL_NAME);
        uimsg("[*] Using ManualMap");
        if(!mmap(pID, DLL))
            {
                errorp(MError,false);
                free(MError);
                free(DLL);
                error("[-] ManualMap failed.",true);
            }

         free(DLL);
        break;
     case 3:
        if(!IsUserAdmin())
            error("[*] Not Admin! If it fail, run as Admin!",false);
        DLL=(char *)malloc(strlen(DLL_NAME));
        strcpy(DLL,DLL_NAME);
        uimsg("[*] Using Thread Hijack");
        if(!thijack(pID, DLL))
        {         
          errorp(MError,false);
          free(MError);
          free(DLL);
          error("[-] Hijack failed :(",true);
        }
        free(DLL);        
        break;
    default:
        error("[-] Inject method invalid!",true);
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

    short int wait;
    char out[30];
    wait= atoi(ui->line1_2->text().toStdString().c_str());
    unsigned int result=0;

    while(ainject || !result)
    {
      if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
       error("[-] EnumProcesses failed.",true );
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
      sprintf(out,"Waiting for %s . ..",ProcName);
      ui->label_3->setText(out);
      delay(wait/2);
      sprintf(out,"Waiting for %s .. .",ProcName);
      ui->label_3->setText(out);
      delay(wait);
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
        delay(450);
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

void MainWindow::on_radioButton_clicked()
{
    //97-122
    QTime now = QTime::currentTime();
    qsrand(now.msec());
    int tam=5 + qrand()%5;
    char *novo, *name, *cmd;
    novo=(char *)malloc(tam);    
   // name=(char *)malloc(32);
    for( int a=0;a<tam;a++)    
     novo[a] = (int) 97 + qrand()%25;

    novo[tam]='\0';
    char *var;
    var=getenv("USERPROFILE");
     if(!PathFileExists(ui->line2->text().toStdString().c_str()))
     {
       Beep(750,350);
       ui->label_3->setText("[-] Invalid DLL path, skipping DLL move");
       delay(4000);
     }
    else
     {
         cmd=(char *)malloc(126);
         sprintf(cmd," /C copy %s %s\\AppData\\Local\\Temp\\%s.dll",ui->line2->text().replace('/', '\\').toStdString().c_str(),var,novo);
        // printf("%s\n",cmd);
         QProcess::execute("cmd.exe",QStringList() << QString(cmd));
         obs=true;
         free(cmd);
     }

   // QFileInfo file(QCoreApplication::applicationFilePath());
    name=(char *)QCoreApplication::applicationFilePath().replace('/', '\\').toStdString().c_str();
            //file.fileName().toStdString().c_str();




    cmd=(char *)malloc(256);
    sprintf(cmd," /C copy %s %s\\AppData\\Local\\Temp\\%s.exe",name,var,novo);
    QProcess::execute("cmd.exe",QStringList() << QString(cmd));
    free(cmd);
    cmd=(char *)malloc(128);
    sprintf(cmd,"%s\\AppData\\Local\\Temp\\%s.exe",var,novo);

    QProcess::startDetached( QString(cmd));
    // printf("%s\n",cmd);
     //QProcess::startDetached("copy",QStringList() << "/C" <<QString(cmd) );
   // system(cmd);
    delay(1500);
    free(cmd);
    free(name);
    free(novo);
    free(var);
    ainject=false;
    exit(1);

}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    if(index>1)
    {
        ui->checkBox_4->setEnabled(false);
        ui->checkBox_4->setChecked(false);
        //ui->checkBox_5->setEnabled(false);
        //ui->checkBox_5->setChecked(false);
        ui->checkBox_6->setEnabled(false);
        ui->checkBox_6->setChecked(false);        
    }
    else {
         ui->checkBox_4->setEnabled(true);
         //ui->checkBox_5->setEnabled(true);
       //  ui->checkBox_6->setEnabled(true);
    }
    if(index==2)
    {
       ui->checkBox_10->setEnabled(true);
       ui->checkBox_7->setEnabled(false);
    }
    else
    {
      ui->checkBox_10->setEnabled(false);
      ui->checkBox_7->setEnabled(true);
    }

}


void MainWindow::on_checkBox_4_stateChanged(int arg1)
{
    ui->checkBox_6->setEnabled(arg1);
    ui->checkBox_6->setChecked(false);
    ui->label_9->setEnabled(arg1);
    ui->label_10->setEnabled(arg1);
    ui->line1_4->setEnabled(arg1);
}

void MainWindow::on_checkBox_9_toggled(bool checked)
{
    ui->line1_5->setEnabled(checked);
    ui->label_11->setEnabled(checked);
    ui->label_12->setEnabled(checked);
}

void MainWindow::on_toolButton_2_clicked()
{
    ui->comboBox_2->setVisible(true);
    ui->toolButton_2->setVisible(false);
    DWORD aProcesses[1024], cbNeeded, cProcesses,i;
    char *dll;
       ui->comboBox_2->addItem(QString("[Processes List]"));
    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
        errorp("[-] EnumProcesses failed.",false);
        return;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    for ( i = 0; i < cProcesses; i++ )
        if( aProcesses[i] != 0 )
        {
            HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                           PROCESS_VM_READ,
                                           FALSE,  aProcesses[i] );
            if(!hProcess)
                continue;
            dll=(char*)malloc(256);
            if(!GetModuleBaseName(hProcess,NULL,dll,256))
                continue;
            ui->comboBox_2->addItem(QString(dll));
         //   qDebug("%s %s\n",dll,QString(dll));
            free(dll);
        }




}

void MainWindow::on_comboBox_2_activated(const QString &arg1)
{
    if(!ui->comboBox_2->currentIndex())
        return;
    ui->line1->setText(arg1);
    ui->comboBox_2->clear();
    ui->comboBox_2->setVisible(false);
    ui->toolButton_2->setVisible(true);
}

void MainWindow::on_checkBox_10_toggled(bool checked)
{
    hijack_stub=checked;
    ui->label_13->setEnabled(checked);
    ui->label_14->setEnabled(checked);
    ui->line1_6->setEnabled(checked);
    hijack_stub_delay=ui->line1_6->text().toInt();
}



void MainWindow::on_checkBox_3_clicked(bool checked)
{
    ui->label_8->setEnabled(checked);
    ui->line1_3->setEnabled(checked);
}
