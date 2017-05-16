#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QProcess>
#include <QTextCodec>
#define error(X, Y) {errorp(X,Y); return 0;}
#define uimsg(X) ui->plainTextEdit->appendPlainText(X);
#include "antis.h"



#define Version "Ki Injector 4.0 - otavioarj"

#ifdef _WIN64
#define CONF "conf64.txt"
#else
#define CONF "conf.txt"
#endif

int showin(DWORD processID ){
    HWND hWnd=NULL;
    hWnd=FindWindowFromProcessId(processID);
    if(hWnd==NULL)
    {
        using namespace andrivet::ADVobfuscator;
        MMapError(OBFUSCATED4("[-] Can't display process windows."));
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
    using namespace andrivet::ADVobfuscator;
    // isInitialized = false;
    ui->setupUi(this);
    // this->setWindowFlags(Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::WindowMinimizeButtonHint );// | Qt::WindowCloseButtonHint);
    this->setFixedSize(this->size());
    verbose=false;
    ainject=false;
    hijack=0;
    hijack_stub=false;
    obs=false;
    ui->comboBox_2->setVisible(false);
    QString no=QCoreApplication::applicationDirPath();
    int sof=0,ssz=0,xof=0;
    //QFileInfo( QCoreApplication::applicationFilePath()).fileName();
    // Inc. image base size :)
    swapBase();

    if((f=fopen(OBFUSCATED4(CONF),OBFUSCATED4("r")))!=NULL)
    {
        char *exe,*dll;
        exe=new char[64];
        dll=new char[512];
        if(fscanf(f,OBFUSCATED4("%s : %s\n"),exe,dll)==2)
        {
            ui->line1->setText(exe);
            if(!obs)
                ui->line2->setText(dll);
        }
        free(exe);
        free(dll);
        fclose(f);
    }

    if (no.contains(OBFUSCATED4("AppData")))
    {
        this->setWindowTitle(QFileInfo(QCoreApplication::applicationFilePath()).fileName());
        obs=true;
        ui->toolButton->setEnabled(false);
        ui->toolButton_2->setEnabled(false);
        ui->line1->setEnabled(false);
        ui->line2->setEnabled(false);
        no=QFileInfo(QCoreApplication::applicationFilePath()).fileName().replace(OBFUSCATED4("exe"),OBFUSCATED4("dll"));
        ui->radioButton->setChecked(true);
        ui->radioButton->setEnabled(false);
        ui->line2->setText((QCoreApplication::applicationDirPath().replace(OBFUSCATED4("/"),OBFUSCATED4("\\"))).append(OBFUSCATED4("\\")).append(no));
        MYWORD base=(MYWORD)GetModuleHandle(NULL);
        IMAGE_NT_HEADERS  *nt=NULL;
        DWORD OldProtect = 0;
        nt=(IMAGE_NT_HEADERS *)(base  + 0x80);
        if(nt->Signature==IMAGE_NT_SIGNATURE)
        {

            // nt->OptionalHeader.SizeOfImage=0x100000;
            VirtualProtect((LPVOID)base,nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &OldProtect);
            ZeroMemory((LPVOID)base,nt->OptionalHeader.SizeOfHeaders);
            VirtualProtect((LPVOID)base,nt->OptionalHeader.SizeOfHeaders,OldProtect,NULL);
        }
#ifdef DEV
        else { QMessageBox::critical(NULL,OBFUSCATED4("Header!"),OBFUSCATED4(":(")); }
#endif

        MError= NULL;
#ifndef _WIN64
        sof=0xa3008e;//a8;
        xof=0x1a;
        ssz=0x9cf; //+size procname
#else
        sof=0xa3605a;//78;
        xof=0x1e;
        ssz=0x9fb;
#endif


        char *mysig=(char *)base+sof;
        if(!strncmp(mysig+xof,"<html>",6)) // Proces
        {
            VirtualProtect((LPVOID)mysig,ssz, PAGE_READWRITE, &OldProtect); // high!!
            ZeroMemory((LPVOID)mysig,13);//ssz);
            ZeroMemory((LPVOID)(mysig+xof),ssz-xof);
            VirtualProtect((LPVOID)mysig,ssz,OldProtect,NULL);
        }
#ifdef DEV
        else { QMessageBox::critical(NULL,OBFUSCATED4("Sig!"),OBFUSCATED4(":(")); }
#endif

    }


#ifndef _WIN64
        ui->label_3->setText(QString(OBFUSCATED4("Arch: x32")));
#else
        ui->label_3->setText(QString(OBFUSCATED4("Arch: x64")));
#endif



#ifdef DEV
       QMessageBox::critical(NULL,OBFUSCATED4("Dev!"),OBFUSCATED4(":("));
     //  char ai[64];
    //   sprintf(ai,"% d %d",test,test2);
   //   QMessageBox::critical(NULL, "Vm",QString(ai));
#endif

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
     using namespace andrivet::ADVobfuscator;
    if(!(test<<sizeof(MYWORD)*8))
    {
        QString fileName = QFileDialog::getOpenFileName(this, tr(OBFUSCATED4("Open Dll")),"",tr(OBFUSCATED4("*.dll")));
        ui->line2->setText(fileName);
    }
}



void MainWindow::errorp(const char * str,bool e)
{
    using namespace andrivet::ADVobfuscator;
    char * output=(char *)malloc(strlen(str)+6);
    sprintf(output,OBFUSCATED4("%s! E:%d ."),str,(int) GetLastError() );
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
        ainject=false;
        Beep(750,350);
        ui->label_3->setText(OBFUSCATED4("[-] Injection aborted..."));
        ui->checkBox_3->setChecked(false);
        ui->checkBox->setChecked(false);
        ui->line1->setDisabled(false);
        ui->line2->setDisabled(false);

    }


}


void MainWindow::on_checkBox_toggled(bool checked)
{
     using namespace andrivet::ADVobfuscator;
    ui->label_3->clear();
    //errorp("Execute as Admin!!",true);
    if(ui->line1->text().length()<1 && ui->line2->text().length()<1)
    {
        ui->checkBox->setChecked(false);
        return;
    }

    bool closeme=false;
    if(!ainject && checked){
        QMessageBox::StandardButton resBtn = QMessageBox::question( this,OBFUSCATED4(Version),
                                                                    tr(OBFUSCATED4("Auto close on injection?\n")), QMessageBox::No | QMessageBox::Yes,QMessageBox::Yes);
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
    using namespace andrivet::ADVobfuscator;
    ui->label_3->setText(OBFUSCATED4(Version));
}




void MainWindow::on_pushButton_clicked()
{
    using namespace andrivet::ADVobfuscator;

    int pID=0,pid2=1,re_count=0,count=atoi(ui->line1_3->text().toStdString().c_str());
    char *proc;
    char out[30];
    short int wait;
    wait= atoi(ui->line1_2->text().toStdString().c_str());

    if( (rdtsc_diff_vmexit()<<(sizeof(MYWORD)*8)) || (ui->line1->text().length()<4 && ui->line2->text().length()<3) )
    {
        errorp(OBFUSCATED4("[-] This isn't a valid a process/dll name"),false);
        return;
    }

    if(!obs && (f=fopen(OBFUSCATED4(CONF),OBFUSCATED4("w")))!=NULL)
    {

        fprintf(f,OBFUSCATED4("%s : %s \n"),ui->line1->text().toStdString().c_str(),ui->line2->text().toStdString().c_str());
        fclose(f);
    }

    ui->line1->setDisabled(true);
    ui->line2->setDisabled(true);
    ui->tabWidget->setCurrentIndex(0);
    proc=(char *)malloc(ui->line1->text().length());
    strncpy(proc,ui->line1->text().toStdString().c_str(),ui->line1->text().length());
    proc[ui->line1->text().length()]='\0';
    if(strlen(proc)<4 || strncmp(proc+(strlen(proc)-4),OBFUSCATED4(".exe"),4) || ( !this->obs && (IsPExe()%2)))
    {
        errorp(OBFUSCATED4("[-] This isn't a valid executable(.exe)"),false);
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
        pID = QtThreadId(proc);
        if(!pID || (test%2))
        {
            errorp(OBFUSCATED4("[-] Can't get pID from process!"),true);
            ui->checkBox_3->setChecked(false);
            ui->line1->setDisabled(false);
            ui->line2->setDisabled(false);
            free(proc);
            return;
        }

        if(pID!=pid2 || (test2<<sizeof(MYWORD)*8))
        {
            char *out;out=(char*)malloc(25);
            sprintf(out,OBFUSCATED4("[*] Process PID: %d"),pID);
            ui->plainTextEdit->appendPlainText(out);
            free(out);
            if(ui->checkBox_8->isChecked())
            {
                stubs obj;
                obj.in=(void *)find_undll;
                obj.fin=(void *)find_end;
                param p;
                MYWORD as[3];
                fix_undll(as);
                p.data=&as;
                p.a=sizeof(as);
                if(mytrick ( pID, obj, p,true)==1)
                {
                    ui->plainTextEdit->appendPlainText(OBFUSCATED4("[+] Bypass Stub ran!"));
                    // qDebug("Ret: %d\n",hijack);
                    if(hijack==(HMODULE)1)
                        ui->plainTextEdit->appendPlainText(OBFUSCATED4("[+] Bypassed Dll Notify!"));
                    else if (hijack==(HMODULE)-1)
                        ui->plainTextEdit->appendPlainText(OBFUSCATED4("[-] Bypass failed Nt:("));
                    else
                        ui->plainTextEdit->appendPlainText(OBFUSCATED4("[-] Bypass failed :("));
                }
                else
                {
                    errorp(MError,false);
                    free(MError);
                    errorp(OBFUSCATED4("[-] Bypass failed!"),true);
                }
            }

            if(!Inject(pID, ui->line2->text().toStdString().c_str()))
            {
                errorp(OBFUSCATED4("[-] DLL can't be loaded!\n"),true);
                free(proc);
                Beep( 750, 350 );
                return;
            }
            else
            {
                ui->plainTextEdit->appendPlainText(OBFUSCATED4("[+] DLL sucefully loaded!"));
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
                        if(dname[cn]=='\\' || dname[cn]=='/')
                            break;
                    cn++;
                    dl=(char *)malloc(tam-cn);
                    strncpy(dl,dname+cn,tam-cn);
                    dl[tam-cn]='\0';

                    HMODULE hDLL=NULL;
                    ui->plainTextEdit->appendPlainText(OBFUSCATED4("[*] Hiding DLL"));
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
                        if(mytrick ( pID, obj, p,true)!=1)
                        {
                            errorp(MError,false);
                            free(MError);
                            errorp(OBFUSCATED4("[-] Hidding failed."),true);
                        }
                        else
                            ui->plainTextEdit->appendPlainText(OBFUSCATED4("[+] DLL Hidden"));

                    }
                    else
                        errorp(OBFUSCATED4("[-] Can't find DLL on process!"),false);
                    free(dl);
                    free(dname);
                }

                if(ui->checkBox_5->isChecked())
                {
                    ui->plainTextEdit->appendPlainText(OBFUSCATED4("[*] Wiping DLL Header"));
                    delay( ui->line1_4->text().toInt());
                    char *dname,*dl;
                    int tam=0,cn=0;
                    tam=strlen(ui->line2->text().toStdString().c_str());
                    dname=(char *)malloc(tam);
                    strncpy(dname,ui->line2->text().toStdString().c_str(),tam);
                    for(cn=tam;cn>0;cn--)
                        if(dname[cn]=='\\' || dname[cn]=='/')
                            break;
                    cn++;
                    dl=(char *)malloc(tam-cn);
                    strncpy(dl,dname+cn,tam-cn);
                    dl[tam-cn]='\0';
                    void * wiper;
                    HMODULE hDLL=NULL;
                    if(ui->checkBox_7->isChecked() || ui->comboBox->currentIndex()==2 || (hDLL=GetRemoteModuleHandle(pID,dl)))
                    {
                        //DWORD OldProtect = 0;
                        HANDLE Proc=NULL;
                        wiper=malloc(4096);
                        showin(pID);
                        Proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pID);
                        if(ui->checkBox_7->isChecked() ||  ui->comboBox->currentIndex()==2) //(ui->comboBox->currentIndex()==3)
                            hDLL=hijack;
                       // VirtualProtect(hDLL, 4096, PAGE_READWRITE, &OldProtect);
                        memset(wiper,0x0,4096);
                        myWriteProcessMemory(Proc,hDLL,wiper,4096,NULL);
                        //   qDebug("Ae2 \n",dl);
                       // VirtualProtect(hDLL, 4096, OldProtect,NULL);
                        ui->plainTextEdit->appendPlainText(OBFUSCATED4("[+] DLL Header wiped!"));
                        free(wiper);
                        CloseHandle(Proc);
                    }
                    else if(!(hDLL=GetRemoteModuleHandle(pID,dl)))
                            errorp(OBFUSCATED4("[-] Can't find DLL Header!"),false);
                    else
                        errorp(OBFUSCATED4("[-] Can't wipe DLL Header!"),false);
                    free(dl);
                    free(dname);
                }
                ui->plainTextEdit->appendPlainText("\n");
            }
            pid2=pID;
        }
        auto wtn=DEF_OBFUSCATED4("Waiting for");
        char *str;
        int size=wtn.ssize();
        str=(char *)malloc(size);
        strncpy(str,wtn.decrypt(),size);
        sprintf(out,OBFUSCATED4("%s %s ..  ."),str,proc);
        ui->label_3->setText(out);
        delay(wait/2);
        sprintf(out,OBFUSCATED4("%s %s .  .."),str,proc);
        ui->label_3->setText(out);
        delay(wait/2);
        free(str);
    } while( ui->checkBox_3->isChecked() && ainject && re_count < count  && !(IsPExe()%2 ^ this->obs ) );
    ui->checkBox_3->setChecked(false);
    ui->line1->setDisabled(false);
    ui->line2->setDisabled(false);
    ui->label_3->clear();
    free(proc);

}



int MainWindow::Inject(int pID, const char * DLL_NAME)
{
    using namespace andrivet::ADVobfuscator;
    HANDLE Proc=NULL;
    //HMODULE hLib;
    LPVOID RemoteString=NULL, LoadLibAddy=NULL, memwipe=NULL;
    pvoids p={NULL,NULL,NULL};
    if(ui->checkBox_9->isChecked())
    {
        uimsg(OBFUSCATED4("[*] PreInject Delay..."));
        delay(ui->line1_5->text().toInt());
    }
    char *DLL;
    if(ui->comboBox->currentIndex()<=1)
    {
        Proc = OpenProcess(CREATE_THREAD_ACCESS , FALSE, pID);
        if(!Proc)
            error(OBFUSCATED4("[-] OpenProcess2 failed."),true);

        if(!PathFileExists(DLL_NAME))
            error(OBFUSCATED4("[-] DLL can't be found."),true);
        if(ui->checkBox_4->isChecked())
        {
            p=LoadMan((char * )DLL_NAME,Proc);
            if(p.p1==NULL || p.p2==NULL)
            {
                errorp(MError,false);
                free(MError);
                error(OBFUSCATED4("[-] Load_stub failed :("),true);
            }
            LoadLibAddy=p.p1;
            RemoteString=p.p2;
        }
        else
        {

             //  wchar_t* sModuleName = new wchar_t[MAX_PATH];
             //  mbstowcs(sModuleName,OBFUSCATED4("kernel32.dll"), MAX_PATH);
           // auto load2=GetProcAddress(GetModuleHandle("kernel32.dll"),"LoadLibraryA");
            if((LoadLibAddy=(void *) GetModuleFunc(OBFUSCATED4("kernel32.dll"),(LPCSTR) OBFUSCATED4("LoadLibraryA")))==NULL)
                error(OBFUSCATED4("[-] GetProcAddress failed."),true );
           //qDebug("M: %p U:%p",LoadLibAddy,load2);

            // Allocate space in the process for our DLL
            if((RemoteString = VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))==NULL)
                error("[-] VirtualAllocEx failed.",true );

            // Write the string name of our DLL in the memory allocated
            if(!myWriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL))
                error("[-] WriteProcessMemory failed.",true );

        }
    }

    // Load our DLL
    switch(ui->comboBox->currentIndex())
    {
    case 0:
        if(!IsUserAdmin())
            error(OBFUSCATED4("[-] Admin needed for this injection!"),true);
        uimsg(OBFUSCATED4("[*] Using CreateRemoteThread."));
        if(CreateRemoteThread(Proc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, 0, NULL)==NULL)
        {errorp(OBFUSCATED4("[-] CreateRemoteThread failed."),true); return 0;}
        else if(ui->checkBox_6->isChecked())
        {
            memwipe=malloc(128);
            memset(memwipe,0x0,128);
            showin(pID);
            delay(ui->line1_4->text().toInt()*1000);
            myWriteProcessMemory(Proc,p.p1,memwipe,124,NULL);
            myWriteProcessMemory(Proc,p.p2,memwipe,124,NULL);
            VirtualFreeEx(Proc,p.p1,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p2,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p3,0,MEM_RELEASE);
            free(memwipe);
        }
        CloseHandle(Proc);
        break;
    case 1:
        if(!IsUserAdmin())
            error(OBFUSCATED4("[*] Not Admin. If it fail, run as Admin!"),false);
        uimsg(OBFUSCATED4("[*] Using NtCreateThreadEx."));
        if(NtCreateThreadEx(Proc, LoadLibAddy, (LPVOID)RemoteString)==NULL){
            errorp(OBFUSCATED4("[-] NtCreateThreadEx failed."),true); return 0;}
        else if(ui->checkBox_6->isChecked())
        {

            showin(pID);
            delay(ui->line1_4->text().toInt()*1000);
            memwipe=malloc(128);
            memset(memwipe,0x0,128);
            myWriteProcessMemory(Proc,p.p1,memwipe,124,NULL);
            myWriteProcessMemory(Proc,p.p2,memwipe,124,NULL);
            VirtualFreeEx(Proc,p.p1,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p2,0,MEM_RELEASE);
            VirtualFreeEx(Proc,p.p3,0,MEM_RELEASE);
            free(memwipe);
        }
        CloseHandle(Proc);
        break;
    case 2:
        if(!IsUserAdmin())
            error(OBFUSCATED4("[*] Not Admin! If it fail, run as Admin!"),false);
        DLL=(char *)malloc(strlen(DLL_NAME));
        strcpy(DLL,DLL_NAME);
        uimsg(OBFUSCATED4("[*] Using ManualMap"));
        /* if(ui->checkBox_10->isChecked())
        {
            uimsg("[+] Using Manual Imports!");
            uimsg("[*] Expect instability :(");
            if(!MapRemoteModule(pID, DLL))
            {
                errorp(MError,false);
                free(MError);
                free(DLL);
                error("[-] ManualMap failed.",true);
            }
        }
        else
        {*/
        if(!mmap(pID, DLL))
        {
            errorp(MError,false);
            free(MError);
            free(DLL);
            error(OBFUSCATED4("[-] ManualMap failed."),true);
        }
        //}
        free(DLL);
        break;
    case 3:
        if(!IsUserAdmin())
            error(OBFUSCATED4("[*] Not Admin! If it fail, run as Admin!"),false);
        DLL=(char *)malloc(strlen(DLL_NAME));
        strcpy(DLL,DLL_NAME);
        uimsg(OBFUSCATED4("[*] Using Thread Hijack"));
        if(!thijack(pID, DLL))
        {
            errorp(MError,false);
            free(MError);
            free(DLL);
            error(OBFUSCATED4("[-] Hijack failed :("),true);
        }
        free(DLL);
        break;
    default:
        error(OBFUSCATED4("[-] Inject method invalid!"),true);
    }

    return 1;
}


DWORD MainWindow::QtEventId( DWORD processID[],const char * ProcName, int cProcesses)
{
    char szProcessName[MAX_PATH];
    HANDLE hProcess;
    HMODULE hMod;
    DWORD cbNeeded;
    using namespace andrivet::ADVobfuscator;

    //QMessageBox::critical(NULL, "Error!",out);
    // Get a handle to the process.
    if(verbose)
    {
        char *out;out=(char*)malloc(55);
        sprintf(out,OBFUSCATED4("[+] Found: %d process, injectable list: "),cProcesses);
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
                sprintf(out,OBFUSCATED4("[%d]: %s "),a,szProcessName);
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



DWORD MainWindow::QtThreadId(const char * ProcName)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    using namespace andrivet::ADVobfuscator;
    short int wait;
    char out[30];
    wait= atoi(ui->line1_2->text().toStdString().c_str());
    unsigned int result=0;

    while(ainject || !result)
    {
        if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
            error(OBFUSCATED4("[-] EnumProcesses failed."),true );
        cProcesses = cbNeeded / sizeof(DWORD);
        result=QtEventId( aProcesses , ProcName,cProcesses);
        if( result)
        {
            //count << endl;
            return result;
        }
        else if (!ainject)
        {
            sprintf(out,OBFUSCATED4("[-] Process %s not found."),ProcName);
            errorp(out,false);
            return 0;
        }

        //QMessageBox::critical(NULL, "Error!","Preso");
        auto wtn=DEF_OBFUSCATED4("Waiting for");
        char *str;
        int size=wtn.ssize();
        str=(char *)malloc(size);
        strncpy(str,wtn.decrypt(),size);
        sprintf(out,OBFUSCATED4("%s %s . .."),str,ProcName);
        ui->label_3->setText(out);
        delay(wait/2);
        sprintf(out,OBFUSCATED4("%s %s .. ."),str,ProcName);
        ui->label_3->setText(out);
        free(str);
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
    using namespace andrivet::ADVobfuscator;
    if(ainject)
    {

        QMessageBox::StandardButton resBtn = QMessageBox::question( this,OBFUSCATED4(Version),
                                                                    tr(OBFUSCATED4("Are you sure?\n")), QMessageBox::No | QMessageBox::Yes,QMessageBox::Yes);
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


void MainWindow::on_radioButton_clicked()
{

    using namespace andrivet::ADVobfuscator;
    bool is;
    QTime now = QTime::currentTime();
    qsrand(now.msec());
    int tam=5 + qrand()%3;
    char *novo, *name, *cmd;
    novo=(char *)malloc(tam);
    // name=(char *)malloc(32);
    for( int a=0;a<tam-1;a++)
        novo[a] = (int) 97 + qrand()%25;

    novo[tam-1]='\0';
    char *var;
    var=getenv(OBFUSCATED4("USERPROFILE"));
    if(!PathFileExists(ui->line2->text().toStdString().c_str()))
    {
        Beep(750,350);
        ui->label_3->setText(OBFUSCATED4("[-] Invalid DLL path, aborting!"));
        ui->radioButton->setChecked(false);
        return;
    }
    else
    {
        cmd=(char *)malloc(126);
        sprintf(cmd,OBFUSCATED4(" /C copy %s %s\\AppData\\Local\\Temp\\%s.dll"),ui->line2->text().replace('/', '\\').toStdString().c_str(),var,novo);
        //  printf("%s\n",cmd);
        if(!QProcess::execute(OBFUSCATED4("cmd.exe"),QStringList() << QString(cmd)))
        {
            obs=true;
            free(cmd);
        }
        else
        {
            Beep(750,350);
            free(cmd);
            ui->radioButton->setChecked(false);
            ui->label_3->setText(OBFUSCATED4("[-] Can't move DLL, aborting!"));
            return;
        }
    }

    // QFileInfo file(QCoreApplication::applicationFilePath());
    name=(char *)QCoreApplication::applicationFilePath().replace('/', '\\').toStdString().c_str();
    //file.fileName().toStdString().c_str();

    cmd=(char *)malloc(256);
    sprintf(cmd,OBFUSCATED4(" /C copy %s %s\\AppData\\Local\\Temp\\%s.exe"),name,var,novo);
    if(!QProcess::execute(OBFUSCATED4("cmd.exe"),QStringList() << QString(cmd)))
    {
        free(cmd);
        cmd=(char *)malloc(128);
        sprintf(cmd,OBFUSCATED4("%s\\AppData\\Local\\Temp\\%s.exe"),var,novo);
    }
    else
    {
        Beep(750,350);
        free(cmd);
        ui->radioButton->setChecked(false);
        ui->label_3->setText(OBFUSCATED4("[-] Can't move .exe, aborting!"));
        return;
    }

    is=QProcess::startDetached( QString(cmd));


    //QProcess::startDetached("copy",QStringList() << "/C" <<QString(cmd) );
    // system(cmd);

    free(cmd);
    free(name);
    free(novo);
    free(var);
    ainject=false;
    if(is)
    {
        delay(350);
        exit(0);
    }
    else
        ui->label_3->setText(OBFUSCATED4("[-] Can't restart injector, aborting!"));
    ui->radioButton->setChecked(false);

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
        ui->checkBox_4->setChecked(false);
        //ui->checkBox_5->setEnabled(true);
        //  ui->checkBox_6->setEnabled(true);
    }
    if(index==2)
    {
        ui->checkBox_10->setEnabled(true);
        ui->checkBox_7->setEnabled(false);
        ui->checkBox_7->setChecked(false);
    }
    else
    {
        ui->checkBox_10->setEnabled(false);
        ui->checkBox_10->setChecked(false);
        ui->checkBox_7->setEnabled(true);
        ui->checkBox_7->setChecked(false);
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
    using namespace andrivet::ADVobfuscator;
    ui->comboBox_2->setVisible(true);
    ui->toolButton_2->setVisible(false);
    DWORD aProcesses[1024], cbNeeded, cProcesses,i;
    char *dll;
    ui->comboBox_2->addItem(QString(OBFUSCATED4("[Refresh Processes List]")));
    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
        errorp(OBFUSCATED4("[-] EnumProcesses failed."),false);
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

void MainWindow::on_checkBox_5_clicked(bool checked)
{
    ui->label_9->setEnabled(checked | ui->checkBox_6->isChecked());
    ui->label_10->setEnabled(checked | ui->checkBox_6->isChecked());
    ui->line1_4->setEnabled(checked |  ui->checkBox_6->isChecked());
}

void MainWindow::on_checkBox_6_clicked(bool checked)
{
    ui->label_9->setEnabled(checked | ui->checkBox_5->isChecked());
    ui->label_10->setEnabled(checked | ui->checkBox_5->isChecked());
    ui->line1_4->setEnabled(checked |  ui->checkBox_5->isChecked());
}

void MainWindow::on_comboBox_2_activated(int index)
{
    if(!index)
    {
        ui->comboBox_2->clear();
        on_toolButton_2_clicked();
    }

}



void MainWindow::on_comboBox_2_highlighted(int index)
{
    using namespace andrivet::ADVobfuscator;
    if(!index)
    {
        ui->comboBox_2->removeItem(0);
        ui->comboBox_2->insertItem(0, QString(OBFUSCATED4("[Updating]")));
        delay(80);
        ui->comboBox_2->clear();
        on_toolButton_2_clicked();
    }
}
