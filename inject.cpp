/*
 * This file is part of KiInjector project. This software may be used and distributed
 * according to the terms of the GNU General Public License version 3, incorporated herein by reference
 * at repository: https://github.com/otavioarj/KiInjector
 =]
*/

#include "inject.h"

char * MError= NULL;
//#include <QDebug>

/*
typedef struct _UNICODE_STRING { // UNICODE_STRING structure
         USHORT Length;
         USHORT MaximumLength;
         PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;


typedef long (WINAPI *fLdrLoadDll) //LdrLoadDll function prototype
    (
         IN PWCHAR PathToFile OPTIONAL,
         IN ULONG Flags OPTIONAL,
         IN PUNICODE_STRING ModuleFileName,
         OUT PHANDLE ModuleHandle
    );


typedef VOID (WINAPI *fRtlInitUnicodeString) //RtlInitUnicodeString function prototype
    (
         PUNICODE_STRING DestinationString,
         PCWSTR SourceString
    );

HMODULE hntdll;
fLdrLoadDll _LdrLoadDll;
fRtlInitUnicodeString _RtlInitUnicodeString;



DWORD getThreadID(DWORD pid)
{
   // puts("Getting Thread ID");
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

                            qDebug("Got one: %u\n", te.th32OwnerProcessID);
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

    DWORD threadID = getThreadID(processID);

   qDebug( "Using Thread ID %u\n", threadID);

    if(threadID == (DWORD)0)
       return -1;


    HMODULE dll = LoadDll(dllname);//,NULL,LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if(dll == NULL)
    {
        qDebug("Fail dll: .%s.",dllname);
        return -2;
    }


    HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "test");
    if(addr == NULL)
    {
        qDebug("ProcAdd failed");
        return -3;
    }

    //Uses the threadID from getThreadID to inject into specific process
    HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, threadID);

    if(handle == NULL)
    {
        qDebug("Hook failed");
        return -4;
    }


    //Sleep(1000);
    //UnhookWindowsHookEx(handle);
    return 0;
}

*/


 //Coded by Viotto - http://viotto-security.net
/*
HMODULE LoadDll( LPCSTR lpFileName){

   if (hntdll      == NULL) { hntdll = GetModuleHandleA("ntdll.dll"); }
   if (_LdrLoadDll == NULL) { _LdrLoadDll = (fLdrLoadDll) GetProcAddress ( hntdll, "LdrLoadDll"); }
   if (_RtlInitUnicodeString == NULL)
   { _RtlInitUnicodeString = (fRtlInitUnicodeString) GetProcAddress ( hntdll, "RtlInitUnicodeString"); }

   int StrLen = lstrlenA(lpFileName);
   BSTR WideStr = SysAllocStringLen(NULL, StrLen);
   MultiByteToWideChar(CP_ACP, 0, lpFileName, StrLen, WideStr, StrLen);

   UNICODE_STRING usDllName;
   _RtlInitUnicodeString(&usDllName, WideStr);
   SysFreeString(WideStr);

   HANDLE DllHandle;
   _LdrLoadDll(0, 0, &usDllName, &DllHandle);

   return (HMODULE)DllHandle;
}*/

/*
int main() //Usage example
{
HMODULE hmodule = LoadDll("Kernel32.dll");
//HMODULE hmodule = LoadLibraryA("Kernel32.dll");
return (int)hmodule;
}*/




//   Pietrek's macro
//
//   MakePtr is a macro that allows you to easily add to values (including
//   pointers) together without dealing with C's pointer arithmetic.  It
//   essentially treats the last two parameters as DWORDs.  The first


//   Stub that calls the Dll from within the remote process.
//   This is necessary because a DllMain function takes 3
//   arguments, and CreateRemoteThread can pass only 1.
/*
__declspec(naked) void DllCall_stub(HMODULE hMod)
{
    int no;
    __asm __volatile__
     (
        "push 0;"
        "push 1;"
        "push %1;"      //   Pointer to the hMod argument
        "mov 0xDEADBEEF,%%eax;"   //   Patch this in with the real value at run-time
        "call *%%eax;"         //   MSVC++ doesn't like direct absolute calls, so we have to be
                      //   clever about it.

        "ret;"
        :"=r"(no)
        :"r"(hMod)
        :"eax");

            //   Don't have to clean up the stack because the calling function
                       //   is just going to call ExitThread() immediately after this
                       //   function returns.



}

//   Marker for the end of the DllCall_stub function
__declspec(naked) void DC_stubend(void) { }*/


 //  MapRemoteModule(GetProcessIdByName("notepad.exe"), "Cmdline.dll");



bool MapRemoteModule(unsigned long pId, char *module)
{
   IMAGE_DOS_HEADER *dosHd;
   IMAGE_NT_HEADERS *ntHd;

   HANDLE hFile = CreateFile(module,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);

   if(hFile == INVALID_HANDLE_VALUE)
      return false;

   unsigned int fSize;

   if(GetFileAttributes(module) & FILE_ATTRIBUTE_COMPRESSED)
      fSize = GetCompressedFileSize(module, NULL);
   else
      fSize = GetFileSize(hFile, NULL);

   unsigned char *dllBin = new unsigned char[fSize];
   unsigned int nBytes;

   ReadFile(hFile, dllBin, fSize, (LPDWORD)&nBytes, FALSE);
   CloseHandle(hFile);

   //   Every PE file contains a little DOS stub for backwards compatibility
   //   it's only real relevance is that it contains a pointer to the actual
   //   PE header.
   dosHd = MakePtr(IMAGE_DOS_HEADER *, dllBin, 0);

   //   Make sure we got a valid DOS header
   if(dosHd->e_magic != IMAGE_DOS_SIGNATURE)
   {
      MMapError("Invalid DOS header");
      delete dllBin;
      return false;
   }

   //   Get the real PE header from the DOS stub header
   ntHd = MakePtr(IMAGE_NT_HEADERS *, dllBin, dosHd->e_lfanew);

   //   Verify the PE header
   if(ntHd->Signature != IMAGE_NT_SIGNATURE)
   {
      MMapError("PE Header not found");
      delete dllBin;
      return false;
   }


   if( (ntHd->FileHeader.Characteristics & IMAGE_FILE_DLL) == false )
    {
       MMapError("File isn't a DLL.");
        delete dllBin;
        return false;
    }

   HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);

   if(!hProcess)
   {
     MMapError("Can't OpenProcess");
      return false;
   }


   if( ntHd->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
   {

       MMapError("Injector only supports PE32 executable");
       delete dllBin;
       return false;
     }

   //   Allocate space for the module in the remote process
   void *moduleBase = VirtualAllocEx(hProcess,
      NULL,
      ntHd->OptionalHeader.SizeOfImage,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_EXECUTE_READWRITE);

   //   Make sure we got the memory space we wanted
   if(!moduleBase)
      return false;

   //   Allocate space for our stub
   void *stubBase = VirtualAllocEx(hProcess,
      NULL,
      MakeDelta(SIZE_T, DC_stubend, DllCall_stub),
      MEM_COMMIT | MEM_RESERVE,
      PAGE_EXECUTE_READWRITE);

   //   Make sure we got the memory space we wanted
   if(!stubBase)
   {
       MMapError("Can't get memory space");
      delete dllBin;
      return false;
   }

   //   Fix up the import table of the new module
   if( ntHd->OptionalHeader.NumberOfRvaAndSizes > 1 )
   {
       IMAGE_IMPORT_DESCRIPTOR *impDesc = (IMAGE_IMPORT_DESCRIPTOR *)GetPtrFromRVA(
                   (DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
                   ntHd,
                   (PBYTE)dllBin);

       if(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
           FixImports(pId,
                      (unsigned char *)dllBin,
                      ntHd,
                      impDesc);
       else
       {
           MMapError("Import directory size is 0");
           delete dllBin;
           return false;
       }
   }
   else
   {
       MMapError("Import table cannot be found");
       delete dllBin;
       return false;
   }
   //   Fix "base relocations" of the new module.  Base relocations are places
   //   in the module that use absolute addresses to reference data.  Since
   //   the base address of the module can be different at different times,
   //   the base relocation data is necessary to make the module loadable
   //   at any address.
   IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)GetPtrFromRVA(
      (DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
      ntHd,
      (PBYTE)dllBin);

   if(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
      FixRelocs(dllBin,
         moduleBase,
         ntHd,
         reloc,
         ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

   //   Write the PE header into the remote process's memory space
   WriteProcessMemory(hProcess,
      moduleBase,
      dllBin,
      ntHd->FileHeader.SizeOfOptionalHeader + sizeof(ntHd->FileHeader) + sizeof(ntHd->Signature),
      (SIZE_T *)&nBytes);

   //   Map the sections into the remote process(they need to be aligned
   //   along their virtual addresses)
   MapSections(hProcess, moduleBase, dllBin, ntHd);

   //   Change the page protection on the DllCall_stub function from PAGE_EXECUTE_READ
   //   to PAGE_EXECUTE_READWRITE, so we can patch it.
   VirtualProtect((LPVOID)DllCall_stub,
      MakeDelta(SIZE_T, DC_stubend, DllCall_stub),
      PAGE_EXECUTE_READWRITE,
      (DWORD *)&nBytes);

   //   Patch the stub so it calls the correct address
   *MakePtr(unsigned long *, DllCall_stub, 7) = MakePtr(unsigned long, moduleBase, ntHd->OptionalHeader.AddressOfEntryPoint);


   //   Write the stub into the remote process
   WriteProcessMemory(hProcess,
      stubBase,
      (LPVOID)DllCall_stub,
      MakeDelta(SIZE_T, DC_stubend, DllCall_stub),
      (SIZE_T *)&nBytes);

   //   Execute our stub in the remote process
   CreateRemoteThread(hProcess,
      NULL,
      0,
      (LPTHREAD_START_ROUTINE)stubBase,
      moduleBase,      //   Pass the base address of the module as the argument to the stub.
                  //   All a module handle is, is the base address of the module(except
                  //   in windows CE), so we're really passing a handle to the module
                  //   so that it can refer to itself, create dialogs, etc..
      0,
      NULL);

   delete dllBin;
   return true;
}

bool MapSections(HANDLE hProcess, void *moduleBase, void *dllBin, IMAGE_NT_HEADERS *ntHd)
{
   IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(ntHd);
   unsigned int nBytes = 0;
   unsigned int virtualSize = 0;
   unsigned int n = 0;

   //   Loop through the list of sections
   for(unsigned int i = 0; ntHd->FileHeader.NumberOfSections; i++)
   {
      //   Once we've reached the SizeOfImage, the rest of the sections
      //   don't need to be mapped, if there are any.
      if(nBytes >= ntHd->OptionalHeader.SizeOfImage)
         break;

      WriteProcessMemory(hProcess,
         MakePtr(LPVOID, moduleBase, header->VirtualAddress),
         MakePtr(LPCVOID, dllBin, header->PointerToRawData),
         header->SizeOfRawData,
         (LPDWORD)&n);

      virtualSize = header->VirtualAddress;
      header++;
      virtualSize = header->VirtualAddress - virtualSize;
      nBytes += virtualSize;

      //   Set the proper page protections for this section.
      //   This really could be skipped, but it's not that
      //   hard to implement and it makes it more like a
      //   real loader.
      VirtualProtectEx(hProcess,
         MakePtr(LPVOID, moduleBase, header->VirtualAddress),
         virtualSize,
         header->Characteristics & 0x00FFFFFF,
         NULL);
   }

   return true;
}

bool FixImports(unsigned long pId, void *base, IMAGE_NT_HEADERS *ntHd, IMAGE_IMPORT_DESCRIPTOR *impDesc)
{
   char *module;

   //   Loop through all the required modules
   while((module = (char *)GetPtrFromRVA((DWORD)(impDesc->Name), ntHd, (PBYTE)base)))
   {
      //   If the library is already loaded(like kernel32.dll or ntdll.dll) LoadLibrary will
      //   just return the handle to that module.
       HMODULE localMod = LoadLibrary(module);
       if (localMod==NULL)
       {
           // There was an error using LoadLibrary was probably on a side by side runtime like MSVCR90.dll
           //return false;
           MMapError("Module can't be mapped");
           impDesc++;
           continue;
       }

      //   If the module isn't loaded in the remote process, we recursively call the
      //   module mapping code.  This has the added benefit of ensuring that any of
      //   the current modules dependencies will be just as invisble as this one.
      if(!GetRemoteModuleHandle(pId, module))
         MapRemoteModule(pId, module);

      //   Lookup the first import thunk for this module
      //   NOTE: It is possible this module could forward functions...which is something
      //   that I really should handle.  Maybe i'll add support for forwared functions
      //   a little bit later.
      IMAGE_THUNK_DATA *itd =
         (IMAGE_THUNK_DATA *)GetPtrFromRVA((DWORD)(impDesc->FirstThunk), ntHd, (PBYTE)base);

      while(itd->u1.AddressOfData)
      {
         IMAGE_IMPORT_BY_NAME *iibn;
         iibn = (IMAGE_IMPORT_BY_NAME *)GetPtrFromRVA((DWORD)(itd->u1.AddressOfData), ntHd, (PBYTE)base);

             itd->u1.Function = MakePtr(DWORD, GetRemoteProcAddress(pId,
            module,
            (char *)iibn->Name), 0);

         itd++;
      }
      impDesc++;
   }

   return true;
}

bool FixRelocs(void *base, void *rBase, IMAGE_NT_HEADERS *ntHd, IMAGE_BASE_RELOCATION *reloc, unsigned int size)
{
   unsigned long ImageBase = ntHd->OptionalHeader.ImageBase;
   unsigned int nBytes = 0;

   unsigned long delta = MakeDelta(unsigned long, rBase, ImageBase);

   while(1)
   {
      unsigned long *locBase =
         (unsigned long *)GetPtrFromRVA((DWORD)(reloc->VirtualAddress), ntHd, (PBYTE)base);
      unsigned int numRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

      if(nBytes >= size) break;

      unsigned short *locData = MakePtr(unsigned short *, reloc, sizeof(IMAGE_BASE_RELOCATION));
      for(unsigned int i = 0; i < numRelocs; i++)
      {
         if(((*locData >> 12) & IMAGE_REL_BASED_HIGHLOW))
             *MakePtr(unsigned long *, locBase, (*locData & 0x0FFF)) += delta;

         locData++;
      }

      nBytes += reloc->SizeOfBlock;
      reloc = (IMAGE_BASE_RELOCATION *)locData;
   }

   return true;
}


FARPROC GetRemoteProcAddress(unsigned long pId, char *module, char *func)
{
   HMODULE remoteMod = GetRemoteModuleHandle(pId, module);
   HMODULE localMod = GetModuleHandle(module);

   //   Account for potential differences in base address
   //   of modules in different processes.
   unsigned long delta = MakeDelta(unsigned long, remoteMod, localMod);
   return MakePtr(FARPROC, GetProcAddress(localMod, func), delta);
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
      modEntry.dwSize = sizeof(MODULEENTRY32);
   }
   while(Module32Next(tlh, &modEntry));

   return NULL;
}

//   Matt Pietrek's function
PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned int i;

    for ( i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
      // This 3 line idiocy is because Watcom's linker actually sets the
      // Misc.VirtualSize field to 0.  (!!! - Retards....!!!)
      DWORD size = section->Misc.VirtualSize;
      if ( 0 == size )
         size = section->SizeOfRawData;

        // Is the RVA within this section?
        if ( (rva >= section->VirtualAddress) &&
             (rva < (section->VirtualAddress + size)))
            return section;
    }

    return 0;
}

//   This function is also Pietrek's
LPVOID GetPtrFromRVA( DWORD rva, IMAGE_NT_HEADERS *pNTHeader, PBYTE imageBase )
{
   PIMAGE_SECTION_HEADER pSectionHdr;
   INT delta;

   pSectionHdr = GetEnclosingSectionHeader( rva, pNTHeader );
   if ( !pSectionHdr )
      return 0;

   delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
   return (PVOID) ( imageBase + rva - delta );
}


char * MMapError(const char * str)
{
    MError= new char[strlen(str)];
    return strncpy(MError,str,strlen(str));
}
