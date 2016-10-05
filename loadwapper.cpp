#include "inject.h"
#include "mainwindow.h"

//#include <QDebug>
//#include <QMessageBox>

pdata Wap_LoadDll(LPSTR lpFileName){

HMODULE hntdll=NULL;
pdata points;
fRtlInitUnicodeString _RtlInitUnicodeString=NULL;
hntdll = GetModuleHandleA("ntdll.dll");
points.p1 = (fLdrLoadDll) GetProcAddress ( hntdll, "LdrLoadDll");
_RtlInitUnicodeString = (fRtlInitUnicodeString) GetProcAddress ( hntdll, "RtlInitUnicodeString");

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

    if(!((DWORD)mem & (DWORD)mem2 & (DWORD)mem3))
    {

        MMapError("Can't alloc memory  slub_inject!");
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem3,0,MEM_RELEASE);
        return {NULL, NULL,NULL};
    }

    asm volatile( "mov %%fs:(0x30),%%eax;"
                  "mov 0x68(%%eax),%%eax;"
                  "mov %%eax,%0;"
                  "add $0x57,%0;"
                  :"=r" (Nt)
                  :
                  :);
    if(Nt == 0xc7)
      Llen= (DWORD)LoadDll - (DWORD)LoadDLL_stub;
    else
      Llen= (DWORD)LoadDLL_stub - (DWORD)LoadDll;

    if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem),(LPCVOID) LoadDll,Llen,NULL))
     {
        MMapError("Can't Continue1.");
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
        VirtualFreeEx(hProcess,mem3,0,MEM_RELEASE);
        return {NULL, NULL,NULL};
     }

    pdata jesus= Wap_LoadDll(file);
    size_t fodasse=jesus.p2.Length;
    WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem3),jesus.p2.Buffer,fodasse,NULL);
    jesus.p2.Buffer=(PWSTR)mem3;
//  qDebug("WC.Buffer: %#x J.Tam: %d\n",memstr, jesus.p2.Length);
    if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem2),&jesus,sizeof(jesus),NULL))
     {
        MMapError("Can't Continue4.");
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
    unsigned long int NtGlobalFlags=0;

    tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid.LowPart=20; // 20 = SeDebugPrivilege
    tp.Privileges[0].Luid.HighPart=0;
    if(!OpenProcessToken((HANDLE)-1,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
    {
        MMapError("Not enought permission!");
        return false;
    }
    AdjustTokenPrivileges(hToken,FALSE,&tp,0,NULL,0);
    CloseHandle(hToken);

    DWORD threadID = getThreadID(processID);

    if(threadID == (DWORD)0)
     {
        MMapError("Thread not found");
        return false;
      }

    hThread=OpenThread( THREAD_ACCESS,FALSE,threadID);

       if(!hThread)
       {
           MMapError("Can't open thread handle");
           return false;
       }

       asm volatile( "mov %%fs:(0x30),%%eax;"
                     "mov 0x68(%%eax),%%eax;"
                     "mov %%eax,%0;"
                     "add $0x38,%0;"
                     :"=r" (NtGlobalFlags)
                     :
                     :);

       ctx.ContextFlags=CONTEXT_FULL;
       SuspendThread(hThread);

       if(!GetThreadContext(hThread,&ctx)) // Get the thread context
       {
           MMapError("Can't get thread context");
           ResumeThread(hThread);
           CloseHandle(hThread);
           return false;
       }



      hProcess=OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,FALSE,processID);
      if(hProcess==NULL)
      {

          MMapError("Can't open process!");
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
      }


      mem=VirtualAllocEx(hProcess,NULL,124,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
      mem2=VirtualAllocEx(hProcess,NULL,1024,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

       if(!((DWORD)mem & (DWORD)mem2 ))
       {

           MMapError("Can't alloc memory for inject!");
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           ResumeThread(hThread);
           CloseHandle(hThread);
           CloseHandle(hProcess);
           return false;
       }
      // qDebug( "Using Thread ID %lu\n", threadID);
       if(NtGlobalFlags == 0xa8)
        {
           Plen=(DWORD)Pload - (DWORD)Pload_stub;
           myLoad=(LPVOID)LoadLibraryW;
           mem=(void *)((DWORD)mem2 + NtGlobalFlags);
          // mem=mem2 + NtGlobalFlags;
        }
       else if(slub)
       {
         Plen=(DWORD)Pload_stub2 - (DWORD)Pload2;
         myStub=(LPVOID)Pload2;
         myLoad=(LPVOID)mem2;
       }
       else
       {
          Plen=(DWORD)Pload_stub - (DWORD)Pload;
           myStub=(LPVOID)Pload;
           myLoad=(LPVOID)mem2;
       }

       Llen= (DWORD) obj.fin - (DWORD) obj.in;


       if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)myLoad),obj.in,Llen,NULL))
        {
           MMapError("Can't Continue1.");
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           ResumeThread(hThread);
           return false;
        }

       if(!WriteProcessMemory(hProcess,mem,&myLoad,sizeof(PVOID),NULL))
        {
          MMapError("Can't Continue2.");
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }
// EM 64 SÃO 8 BYTES
        if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4),(LPCVOID) myStub,Plen,NULL))
        {
          MMapError("Can't Continue3.");
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }
   //    qDebug("Escrito: %#x\n",mem);
   //    if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),dllname,Slen,NULL))

    //  qDebug("Addr: %#x AddrData: %#x Tam: %d\n",&p.data,p.data,p.a);
      if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),p.data,p.a,NULL))
       {
         MMapError("Can't Continue4.");
         VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
         VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
         ResumeThread(hThread);
         CloseHandle(hThread);
         CloseHandle(hProcess);
         return false;
       }

  //     qDebug("Current eip value: %#x\n",ctx.Eip);
 //      qDebug("Current esp value: %#x\n",ctx.Esp);
       ctx.Esp-=0x4; // Decrement esp to simulate a push instruction. Without this the target process will crash when the shellcode returns!

       //qDebug("Swap esp value: %#x\n",ctx.Esp);
       WriteProcessMemory(hProcess,(PVOID)ctx.Esp,&ctx.Eip,sizeof(long int),NULL); // Write orginal eip into target thread's stack

       ctx.Eip=(DWORD)((LPBYTE)mem+4); // Set eip to the injected shellcode
    //   qDebug("Swap eip value: %#x\n",ctx.Eip);



       if(!SetThreadContext(hThread,&ctx)) // Hijack the thread
       {

           MMapError("Can't Continue5.");
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
         MMapError("Can't display process windows.");
       else
       {
       ShowWindow(hWnd,SW_SHOWMAXIMIZED);
       ShowWindow(hWnd, SW_RESTORE);
       }
   //   HMODULE hMod;
      memwipe=malloc(1024);
      memset(memwipe,0x0,1024);
      DWORD hMod=0;
      do{      
      ReadProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),&hMod,sizeof(hMod),NULL);
      delay(50);
      }
      while(hMod==(DWORD)p.data);     
   //   qDebug("Mod %#x . * %#x\n",(PVOID)((LPBYTE)mem+4+Plen),hMod);
      if(hijack_stub)
      delay(hijack_stub_delay);
      else
       delay(350);
      hijack=(HMODULE)hMod;
      WriteProcessMemory(hProcess,mem,memwipe,124,NULL);
      WriteProcessMemory(hProcess,mem2,memwipe,1024,NULL);
      VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
      VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
      CloseHandle(hProcess);
      free(memwipe);
      return true;

}


