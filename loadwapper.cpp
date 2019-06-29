#include "inject.h"
#include "mainwindow.h"
#include "antis.h"


//#include <QDebug>
//#include <QMessageBox>

using namespace andrivet::ADVobfuscator;

pdata Wap_LoadDll(LPSTR lpFileName){
    HMODULE hntdll=NULL;
    pdata points;
    fRtlInitUnicodeString _RtlInitUnicodeString=NULL;
    hntdll = GetModuleHandleA(OBFUSCATED4("ntdll.dll"));
    points.p1 = (fLdrLoadDll) GetProcAddress(hntdll, OBFUSCATED4("LdrLoadDll"));
    _RtlInitUnicodeString = (fRtlInitUnicodeString) GetProcAddress ( hntdll, OBFUSCATED4("RtlInitUnicodeString"));

    int StrLen = lstrlenA(lpFileName);
    BSTR WideStr = SysAllocStringLen(NULL, StrLen);
    MultiByteToWideChar(CP_ACP, 0, lpFileName, StrLen, WideStr, StrLen);

    UNICODE_STRING usDllName;
    _RtlInitUnicodeString(&usDllName, WideStr);
    SysFreeString(WideStr);
    points.p2=usDllName;
    return points;
}


pvoids LoadMan(LPSTR file, HANDLE hProcess)
{
    PVOID mem, mem2, mem3;
    DWORD Llen;
    unsigned long int Nt;
    pvoids p;
    mem=VirtualAllocEx(hProcess,NULL,124,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    mem2=VirtualAllocEx(hProcess,NULL,124,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    mem3=VirtualAllocEx(hProcess,NULL,1024,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

    if(!(( MYWORD)mem & ( MYWORD)mem2 & ( MYWORD)mem3))
    {

        MMapError(OBFUSCATED4("[-] Can't alloc memory  slub_inject!"));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem3,0,MEM_RELEASE);
        return {NULL, NULL,NULL};
    }

    Nt=NtStatus();
    //  qDebug("D: %d",Nt);
    if(Nt%2)
        Llen= ( MYWORD)LoadDll - ( MYWORD)LoadDLL_stub;
    else
        Llen= ( MYWORD)LoadDLL_stub - ( MYWORD)LoadDll;
    //  qDebug("L: %d",Llen);

    if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem),(LPCVOID) LoadDll,Llen,NULL))
    {
        MMapError(OBFUSCATED4("[-] Can't Continue1."));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem3,0,MEM_RELEASE);
        return {NULL, NULL,NULL};
    }

    pdata jswap= Wap_LoadDll(file);
    size_t swap_size=jswap.p2.Length;
    myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem3),jswap.p2.Buffer,swap_size,NULL);
    jswap.p2.Buffer=(PWSTR)mem3;
    //  qDebug("WC.Buffer: %#x J.Tam: %d\n",memstr, jswap.p2.Length);
    if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem2),&jswap,sizeof(jswap),NULL))
    {
        MMapError(OBFUSCATED4("[-] Can't Continue4."));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem3,0,MEM_RELEASE);
        return {NULL, NULL,NULL};
    }
    p.p1=mem;
    p.p2=mem2;
    p.p3=mem3;
    return p;


}




int mytrick(int pid, stubs obj, param p, bool slub)
{
    DWORD processID = (DWORD)pid;
    HANDLE hProcess,hThread,hToken;
    DWORD Plen,Llen;
    PVOID myLoad=NULL,myStub=NULL,mem=NULL,memwipe=NULL,mem2=NULL;
    TOKEN_PRIVILEGES tp;
    CONTEXT ctx;
    //unsigned long int NtGlobalFlags=0;

    tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid.LowPart=20; // 20 = SeDebugPrivilege
    tp.Privileges[0].Luid.HighPart=0;
    if(!OpenProcessToken((HANDLE)-1,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
    {
        MMapError(OBFUSCATED4("[-] Not enought permission!"));
        return false;
    }
    AdjustTokenPrivileges(hToken,FALSE,&tp,0,NULL,0);
    CloseHandle(hToken);

    DWORD threadID = getThreadID(processID);

    if(threadID == (DWORD)0)
    {
        MMapError(OBFUSCATED4("[-] Thread not found"));
        return false;
    }

    hThread=OpenThread( THREAD_ACCESS,FALSE,threadID);

    if(!hThread)
    {
        MMapError(OBFUSCATED4("[-] Can't open thread handle"));
        return false;
    }



    ctx.ContextFlags=CONTEXT_FULL;
    SuspendThread(hThread);

    if(!GetThreadContext(hThread,&ctx)) // Get the thread context
    {
        MMapError(OBFUSCATED4("[-] Can't get thread context"));
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }


    hProcess=OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,FALSE,processID);
    if(hProcess==NULL)
    {

        MMapError(OBFUSCATED4("[-] Can't open process!"));
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }


    mem=VirtualAllocEx(hProcess,NULL,124,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    mem2=VirtualAllocEx(hProcess,NULL,1024,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

    if(!(( MYWORD)mem & ( MYWORD)mem2 ))
    {

        MMapError(OBFUSCATED4("[-] Can't alloc memory for inject!"));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }
    // qDebug( "Using Thread ID %lu\n", threadID);
    if(NtStatus()%2)
    {
        Plen=( MYWORD)Pload - ( MYWORD)Pload_stub;
        myLoad=(LPVOID)LoadLibraryW;
        mem=(void *)(( MYWORD)mem2 + (MYWORD)myLoad);

    }
#ifndef _WIN64
    else if(slub)
    {
        Plen=( MYWORD)Pload_stub2 - ( MYWORD)Pload2;
        myStub=(LPVOID)Pload2;
        myLoad=(LPVOID)mem2;
    }
#endif
    else
    {
        Plen=( MYWORD)Pload_stub - ( MYWORD)Pload;
        myStub=(LPVOID)Pload;
        myLoad=(LPVOID)mem2;
    }

    Llen= ( MYWORD) obj.fin - ( MYWORD) obj.in;
    //  myLoad=(LPVOID)mem2;
    //Slen= strlen(dllname);

    if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)myLoad),obj.in,Llen,NULL))
    {
        MMapError(OBFUSCATED4("[-] Can't Continue1."));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        ResumeThread(hThread);
        return false;
    }

    if(!myWriteProcessMemory(hProcess,mem,&myLoad,sizeof(PVOID),NULL))
    {
        MMapError(OBFUSCATED4("[-] Can't Continue2."));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))),(LPCVOID) myStub,Plen,NULL))
    {
        MMapError(OBFUSCATED4("[-] Can't Continue3."));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }
    //  qDebug("Escrito: %#x\n",mem);
    //    if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),dllname,Slen,NULL))

    //qDebug("Addr: %#x AddrData: %#x Tam: %d\n",&p.data,p.data,p.a);
    if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))+Plen),p.data,p.a,NULL))
    {
        MMapError(OBFUSCATED4("[-] Can't Continue4."));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    //     qDebug("Current eip value: %#x\n",ctx.Eip);
    //      qDebug("Current esp value: %#x\n",ctx.Esp);
#ifdef _WIN64    // Decrement esp to simulate a push instruction. Without this the target process will crash when the shellcode returns!
    ctx.Rsp-=0x8;
    myWriteProcessMemory(hProcess,(PVOID)ctx.Rsp,&ctx.Rip,sizeof(long int),NULL); // Write orginal eip into target thread's stack
    ctx.Rip=( MYWORD)((LPBYTE)mem+8);
    //qDebug("Swap rip value: %#x\n",ctx.Rip);

#else
    ctx.Esp-=0x4;
    myWriteProcessMemory(hProcess,(PVOID)ctx.Esp,&ctx.Eip,sizeof(long int),NULL); // Write orginal eip into target thread's stack
    ctx.Eip=( MYWORD)((LPBYTE)mem+4); // Set eip to the injected shellcode
    //qDebug("Swap eip value: %#x\n",ctx.Eip);

#endif





    if(!SetThreadContext(hThread,&ctx)) // Hijack the thread
    {

        MMapError(OBFUSCATED4("[-] Can't Continue5."));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // QMessageBox::critical(NULL, "Error!",":)");
    ResumeThread(hThread); // Resume the thread to allow the thread execute the shellcode
    CloseHandle(hThread);
    HWND hWnd=NULL;
    hWnd=FindWindowFromProcessId(processID);
    if(hWnd==NULL)
        MMapError(OBFUSCATED4("[-] Can't display process windows."));
    else
    {
        ShowWindow(hWnd,SW_SHOWMAXIMIZED);
        ShowWindow(hWnd, SW_RESTORE);
    }
    //   HMODULE hMod;
    memwipe=malloc(1024);
    memset(memwipe,0x0,1024);
    MYWORD hMod=0,cnt=0;
    MYWORD * swap=( MYWORD *)p.data;
    do{
        ReadProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))+Plen),&hMod,sizeof(hMod),NULL);
        delay(50);
        cnt++;
        //qDebug("D: %#x D2 %#x D3 %#x H:%#x\n",(DWORD)p.data,swap,*swap,hMod);
    }
    while(hMod==( MYWORD)*swap && cnt<60);
    //  QMessageBox::critical(NULL, "Error!",":(");
    if (hMod==( MYWORD)*swap)
    {
        MMapError(OBFUSCATED4("[-] Stub timed out! "));
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        CloseHandle(hProcess);
        free(memwipe);
        return 2;
    }

    if(hijack_stub)
        delay(hijack_stub_delay);
    else
        delay(50);
    hijack=(HMODULE)hMod;
    myWriteProcessMemory(hProcess,mem,memwipe,124,NULL);
    myWriteProcessMemory(hProcess,mem2,memwipe,1024,NULL);
    VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
    VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
    CloseHandle(hProcess);
    free(memwipe);
    return true;

}


