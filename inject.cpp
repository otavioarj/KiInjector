

#include "inject.h"
#include "mainwindow.h"


char * MError= NULL;
HMODULE hijack = NULL;
bool hijack_stub=0;
int hijack_stub_delay=0;





DWORD getThreadID(DWORD pid)
{

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
    return (DWORD)0;
}





int thijack(int pid, char * dllname)
{
    DWORD processID = (DWORD)pid;
    HANDLE hProcess,hThread,hToken;
    DWORD Plen,Llen;
    PVOID LoadLibraryA_Addr,mem,memwipe,mem2, memstr;
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


    //   printf("\nAllocating memory in target process.\n");
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
      mem2=VirtualAllocEx(hProcess,NULL,124,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
      memstr=VirtualAllocEx(hProcess,NULL,1024,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

       if(!((DWORD)mem & (DWORD)mem2 & (DWORD)memstr))
       {

           MMapError("Can't alloc memory for inject!");
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);         
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
           ResumeThread(hThread);
           CloseHandle(hThread);
           CloseHandle(hProcess);
           return false;
       }
      // qDebug( "Using Thread ID %lu\n", threadID);
       if(NtGlobalFlags == 0xa8)
        {
           Plen=(DWORD)Pload - (DWORD)Pload_stub;
           LoadLibraryA_Addr=(LPVOID)LoadLibraryW;
           mem=(void *)((DWORD)mem2 + NtGlobalFlags);
        }
       else
       {
         Plen=(DWORD)Pload_stub - (DWORD)Pload;
         LoadLibraryA_Addr=(LPVOID)LoadLibraryA;
       }

       Llen= (DWORD)LoadDLL_stub - (DWORD)LoadDll;
       LoadLibraryA_Addr=(LPVOID)mem2;
       //Slen= strlen(dllname);

       if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem2),(LPCVOID) LoadDll,Llen,NULL))
        {
           MMapError("Can't continue1.");
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
           ResumeThread(hThread);
           return false;
        }

   //   qDebug("GetModHand: %#x\n Addr: %#x",GetModuleHandleA,  GetProcAddress);

      // printf("\nWriting the shellcode, LoadLibraryA address and DLL path into target process.\n");

       if(!WriteProcessMemory(hProcess,mem,&LoadLibraryA_Addr,sizeof(PVOID),NULL))
        {
          MMapError("Can't continue2.");
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }

        if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4),(LPCVOID)Pload,Plen,NULL))
        {
          MMapError("Can't continue3.");
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }
   //    qDebug("Escrito: %#x\n",mem);
   //    if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),dllname,Slen,NULL))
      pdata jesus= Wap_LoadDll(dllname);
       size_t fodasse=jesus.p2.Length;
       WriteProcessMemory(hProcess,(PVOID)((LPBYTE)memstr),jesus.p2.Buffer,fodasse,NULL);
       jesus.p2.Buffer=(PWSTR)memstr;
  //     qDebug("WC.Buffer: %#x J.Tam: %d\n",memstr, jesus.p2.Length);
      if(!WriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),&jesus,sizeof(jesus),NULL))
       {
         MMapError("Can't continue4.");
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
       ctx.Esp-=0x4; // Decrement esp to simulate a push instruction. Without this the target process will crash when the shellcode returns!

       //qDebug("Swap esp value: %#x\n",ctx.Esp);
       WriteProcessMemory(hProcess,(PVOID)ctx.Esp,&ctx.Eip,sizeof(long int),NULL); // Write orginal eip into target thread's stack

       ctx.Eip=(DWORD)((LPBYTE)mem+4); // Set eip to the injected shellcode
  //     qDebug("Swap eip value: %#x\n",ctx.Eip);



       if(!SetThreadContext(hThread,&ctx)) // Hijack the thread
       {

           MMapError("Can't continue5.");
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,memstr,0,MEM_RELEASE);
           ResumeThread(hThread);
           CloseHandle(hThread);
           CloseHandle(hProcess);
           return false;
       }


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
      memwipe=malloc(124);
      memset(memwipe,0x0,124);
      DWORD hMod=0;
      do{
      delay(50);
      ReadProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),&hMod,sizeof(hMod),NULL);     
      }
      while(hMod==(DWORD)jesus.p1);
      hijack=(HMODULE)hMod;
     // qDebug("Mod %#x . * %#x\n",(PVOID)((LPBYTE)mem+4+Plen),hMod);
     //  QMessageBox::critical(NULL, "Error!",":)");
      WriteProcessMemory(hProcess,mem,memwipe,124,NULL);
      WriteProcessMemory(hProcess,mem2,memwipe,124,NULL);
      WriteProcessMemory(hProcess,memstr,memwipe,124,NULL);
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
  /*    else
          qDebug("a:%s m:%s",modEntry.szModule, module);*/
      modEntry.dwSize = sizeof(MODULEENTRY32);
   }
   while(Module32Next(tlh, &modEntry));

   return NULL;
}


char * MMapError(const char * str)
{
    MError= new char[strlen(str)+1];
    MError[strlen(MError)]='\0';
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

HWND FindWindowFromProcessId( DWORD dwProcessId ) {
    EnumData ed = { dwProcessId, NULL  };
    if ( !EnumWindows( EnumProc, (LPARAM)&ed ) &&
         ( GetLastError() == ERROR_SUCCESS ) ) {
        return ed.hWnd;
    }
    return NULL;
}
