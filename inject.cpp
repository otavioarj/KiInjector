

#include "inject.h"
#include "mainwindow.h"
#include "antis.h"
#include <QDebug>
#include <QMessageBox>

char * MError= NULL;
HMODULE hijack = NULL;
bool hijack_stub=0;
int hijack_stub_delay=0;





 DWORD getThreadID( unsigned long pid)
{
   // puts("Getting Thread ID"));
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(h != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if( Thread32First(h, &te))
        {
            do
            {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
                {
                    if(te.th32OwnerProcessID == pid)
                    {
                        HANDLE hThread = OpenThread( THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                        if(!hThread)
                        {
                            return -1;
                        }
                        else
                        {

                            //qDebug("Got one: %lu\n", te.th32OwnerProcessID);
                            return te.th32ThreadID;                           
                        }
                    }
                }
            } while( Thread32Next(h, &te));
        }
    }
    CloseHandle(h);
    return ( DWORD)0;
}


int thijack(int pid, char * dllname)
{
     DWORD processID = ( DWORD)pid;
    HANDLE hProcess,hThread,hToken;
     DWORD Plen,Llen;
    PVOID LoadLibraryA_Addr,mem,memwipe,mem2, memstr;
    TOKEN_PRIVILEGES tp;
    CONTEXT ctx;
    unsigned long int NtGlobalFlags=0;
    using namespace andrivet::ADVobfuscator;

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

    if(threadID == ( DWORD)0)
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

//       asm volatile( "mov %%fs:(0x30),%%eax;"
//                     "mov 0x68(%%eax),%%eax;"
//                     "mov %%eax,%0;"
//                     "add $0x38,%0;"
//                     :"=r" (NtGlobalFlags)
//                     :
//                     :);

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
      mem2=VirtualAllocEx(hProcess,NULL,124,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
      memstr=VirtualAllocEx(hProcess,NULL,1024,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

       if(!(( MYWORD)mem & ( MYWORD)mem2 & ( MYWORD)memstr))
       {

           MMapError(OBFUSCATED4("[-] Can't alloc memory for inject!"));
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);         
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
           ResumeThread(hThread);
           CloseHandle(hThread);
           CloseHandle(hProcess);
           return false;
       }
      // qDebug( "Using Thread ID %lu\n", threadID);
       if(CheckTh()%2)
        {
           Plen=( MYWORD)Pload - ( MYWORD)Pload_stub;
           LoadLibraryA_Addr=(LPVOID)LoadLibraryW;
           mem=(void *)(( MYWORD)mem2 + NtGlobalFlags);
        }
       else
       {
         Plen=( MYWORD)Pload_stub - ( MYWORD)Pload;
         LoadLibraryA_Addr=(LPVOID)LoadLibraryA;
       }

       Llen= ( MYWORD)LoadDLL_stub - ( MYWORD)LoadDll;
       LoadLibraryA_Addr=(LPVOID)mem2;
       //Slen= strlen(dllname);

       if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem2),(LPCVOID) LoadDll,Llen,NULL))
        {
           MMapError(OBFUSCATED4("[-] Can't continue1."));
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
           ResumeThread(hThread);
           return false;
        }

   //   qDebug("GetModHand: %#x\n Addr: %#x",GetModuleHandleA,  GetProcAddress);

       if(!myWriteProcessMemory(hProcess,mem,&LoadLibraryA_Addr,sizeof(PVOID),NULL))
        {
          MMapError(OBFUSCATED4("[-] Can't continue2."));
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }

        if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))),(LPCVOID)Pload,Plen,NULL))
        {
          MMapError(OBFUSCATED4("[-] Can't continue3."));
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }
     //  qDebug("Escrito: %#x\n",mem);
   //    if(!(hProcess,(PVOID)((LPBYTE)mem+4+Plen),dllname,Slen,NULL))
      pdata jswap= Wap_LoadDll(dllname);
       size_t swap_size=jswap.p2.Length;
       myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)memstr),jswap.p2.Buffer,swap_size,NULL);
       jswap.p2.Buffer=(PWSTR)memstr;
    //  qDebug("WC.Buffer: %#x J.Tam: %d\n",memstr, jswap.p2.Length);
      if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))+Plen),&jswap,sizeof(jswap),NULL))
       {
         MMapError(OBFUSCATED4("[-] Can't continue4."));
         VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
         VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
         VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
         ResumeThread(hThread);
         CloseHandle(hThread);
         CloseHandle(hProcess);
         return false;
       }

  //     qDebug("Current eip value: %#x\n",ctx.Eip);
 //      qDebug("Current esp value: %#x\n",ctx.Esp);
#ifdef _WIN64
       ctx.Rsp-=0x8;
       myWriteProcessMemory(hProcess,(PVOID)ctx.Rsp,&ctx.Rip,sizeof(long int),NULL); // Write orginal eip into target thread's stack
       ctx.Rip=( MYWORD)((LPBYTE)mem+8);
       //qDebug("Swap eip value: %#x\n",ctx.Rip);


#else
       ctx.Esp-=0x4;
       myWriteProcessMemory(hProcess,(PVOID)ctx.Esp,&ctx.Eip,sizeof(long int),NULL); // Write orginal eip into target thread's stack
       ctx.Eip=( MYWORD)((LPBYTE)mem+4); // Set eip to the injected shellcode
       //qDebug("Swap eip value: %#x\n",ctx.Eip);

#endif
       //qDebug("Swap esp value: %#x\n",ctx.Esp); 



       if(!SetThreadContext(hThread,&ctx)) // Hijack the thread
       {

           MMapError(OBFUSCATED4("[-] Can't continue5."));
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
           ResumeThread(hThread);
           CloseHandle(hThread);
           CloseHandle(hProcess);
           return false;
       }

//       QMessageBox::critical(NULL, "Error!",":)");
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
      memwipe=malloc(124);
      memset(memwipe,0x0,124);
       MYWORD hMod=0;
      do{
      delay(50);
      ReadProcessMemory(hProcess,(PVOID)((LPBYTE)mem+sizeof(MYWORD)+Plen),&hMod,sizeof(hMod),NULL);
      }
      while(hMod==( MYWORD)jswap.p1);
      hijack=(HMODULE)hMod;
     // qDebug("Mod %#x . * %#x\n",(PVOID)((LPBYTE)mem+4+Plen),hMod);
     //  QMessageBox::critical(NULL, "Error!",":)"));
      myWriteProcessMemory(hProcess,mem,memwipe,124,NULL);
      myWriteProcessMemory(hProcess,mem2,memwipe,124,NULL);
      myWriteProcessMemory(hProcess,memstr,memwipe,124,NULL);
      VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
      VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
      VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
      CloseHandle(hProcess);
      free(memwipe);
      return true;

}




unsigned long GetProcessIdByName(char *process)
{
   PROCESSENTRY32 pe;
   HANDLE thSnapshot;
   BOOL retval;

   thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

   if(thSnapshot == INVALID_HANDLE_VALUE)   
      return false;


   pe.dwSize = sizeof(PROCESSENTRY32);

    retval = Process32First(thSnapshot, &pe);

   while(retval)
   {
      if(StrStrI(pe.szExeFile, process) )     
         break;


      retval    = Process32Next(thSnapshot,&pe);
      pe.dwSize = sizeof(PROCESSENTRY32);
   }

   return pe.th32ProcessID;
}


HMODULE GetRemoteModuleHandle(unsigned long pId, char *module)
{
   MODULEENTRY32 modEntry;
   HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);

   modEntry.dwSize = sizeof(MODULEENTRY32);
    Module32First(tlh, &modEntry);

   do
   {
      if(!stricmp(modEntry.szModule, module))
         return modEntry.hModule;
    //  else
    //      qDebug("a:%s m:%s",modEntry.szModule, module);
      modEntry.dwSize = sizeof(MODULEENTRY32);
   }
   while(Module32Next(tlh, &modEntry));

   return NULL;
}


char * MMapError(const char * str)
{
    MError= new char[strlen(str)+1];
    MError[strlen(str)]='\0';
    return strncpy(MError,str,strlen(str));
}

// Application-defined callback for EnumWindows
BOOL CALLBACK EnumProc( HWND hWnd, LPARAM lParam ) {
    // Retrieve storage location for communication data
    EnumData& ed = *(EnumData*)lParam;
     DWORD dwProcessId = 0x0;
    // Query process ID for hWnd
    GetWindowThreadProcessId( hWnd, &dwProcessId );
    // Apply filter - if you want to implement additional restrictions,
    // this is the place to do so.
    if ( ed.dwProcessId == dwProcessId ) {
        // Found a window matching the process ID
        ed.hWnd = hWnd;
        // Report success
        SetLastError( ERROR_SUCCESS );
        // Stop enumeration
        return FALSE;
    }
    // Continue enumeration
    return TRUE;
}

HWND FindWindowFromProcessId(  unsigned long dwProcessId ) {
    EnumData ed = { dwProcessId, NULL  };
    if ( !EnumWindows( EnumProc, (LPARAM)&ed ) &&
         ( GetLastError() == ERROR_SUCCESS ) ) {
        return ed.hWnd;
    }
    return NULL;
}



HANDLE  NtCreateThreadEx(HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpSpace)
{
#define HIDEDEBUGGER 0x00000004
    //The prototype of NtCreateThreadEx from undocumented.ntinternals.com
    typedef  MYWORD (WINAPI * functypeNtCreateThreadEx)(
        PHANDLE                 ThreadHandle,
        ACCESS_MASK             DesiredAccess,
        LPVOID                  ObjectAttributes,
        HANDLE                  ProcessHandle,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        LPVOID                  lpParameter,
        BOOL                    CreateSuspended,
         MYWORD                   dwStackSize,
         MYWORD                   Unknown1,
         MYWORD                   Unknown2,
        LPVOID                  Unknown3
    );

    HANDLE                      hRemoteThread           = NULL;
    HMODULE                     hNtDllModule            = NULL;
    functypeNtCreateThreadEx    funcNtCreateThreadEx    = NULL;
    using namespace andrivet::ADVobfuscator;

    //Get handle for ntdll which contains NtCreateThreadEx
    hNtDllModule = GetModuleHandle(OBFUSCATED4("ntdll.dll"));
    if ( hNtDllModule == NULL )
    {
        return NULL;
    }

    funcNtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress( hNtDllModule,OBFUSCATED4("NtCreateThreadEx"));
    if ( !funcNtCreateThreadEx )
    {
        return NULL;
    }

    funcNtCreateThreadEx( &hRemoteThread,  GENERIC_ALL, 0, hProcess, (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, HIDEDEBUGGER, 0, 0, 0, NULL );

    return hRemoteThread;
}

// Yep, my implementation of NtWriteVirtualMemory as directly call to sys dispatch call to ZwWriteVirtualMemory :)
//  Using ZwProtectVirtualMemory seems not necessary, although it crash on x32 for some reason :(
//  Some anti-cheats my register callbacks (ring-0) into NtWriteVirtualMemory or hook (ring3) WriteProcessMemory (WINAPI)
//  Others register callbacks for ZwProtectVirtualMemory also, be sharp! :}

BOOL myWriteProcessMemory(HANDLE  hProcess,LPVOID  lpBaseAddress,LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten)
{
    using namespace andrivet::ADVobfuscator;
   // pZwProtectVirtualMemory ZwProtectVirtualMemory;
    pZwWriteVirtualMemory   ZwWriteVirtualMemory;
   // DWORD OldProtect,d2;
    NTSTATUS status=0;
   // ULONG roundup=4096*((nSize -1)/4096 + 1);

    typedef ULONG (WINAPI *pRtlNtStatusToDosError)(NTSTATUS Status);
    pRtlNtStatusToDosError RtlNtStatusToDosError=(pRtlNtStatusToDosError)GetModuleFunc(OBFUSCATED4("ntdll.dll"),OBFUSCATED4("RtlNtStatusToDosError"));

    typedef void (WINAPI *pSetLastError)(DWORD dwErrCode);
    pSetLastError SetLError=(pSetLastError)GetModuleFunc(OBFUSCATED4("kernel32.dll"),OBFUSCATED4("SetLastError"));

    if(!(NtStatus()%2))
    {
       // ZwProtectVirtualMemory=(pZwProtectVirtualMemory)GetModuleFunc(OBFUSCATED4("ntdll.dll"),OBFUSCATED4("ZwProtectVirtualMemory"));
        //qDebug("ZProtc: %p",ZwProtectVirtualMemory);
        ZwWriteVirtualMemory=(pZwWriteVirtualMemory)GetModuleFunc(OBFUSCATED4("ntdll.dll"),OBFUSCATED4("ZwWriteVirtualMemory"));
    }
    if(!((IsPExe() & cpuid_is_hypervisor())<<(sizeof(MYWORD)*8)))
    {
       // qDebug("ZWrt: %p",ZwWriteVirtualMemory);
        //status2=ZwProtectVirtualMemory(hProcess,lpBaseAddress,&roundup,PAGE_READWRITE, &OldProtect);
       // qDebug("S2: %x",status2);
        status=ZwWriteVirtualMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten);
       // qDebug("S: %x - W:%x S:%x",status,lpNumberOfBytesWritten,nSize);
    //    qDebug("S3: %x",ZwProtectVirtualMemory(hProcess,&lpBaseAddress,&roundup,OldProtect,&d2));

      if (status)
        SetLError( RtlNtStatusToDosError(status) );
      return !status;
    }
    SetLError(cpuid_is_hypervisor()^nSize);
    return true;
}

