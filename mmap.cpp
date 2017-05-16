#include "inject.h"
#include <stdio.h>
#include "../ADVobfuscator/ADVobfuscator/MetaString4.h"
#pragma GCC push_options
#pragma GCC optimize("O2")
using namespace andrivet::ADVobfuscator;

//#include <QDebug>
//#include <QMessageBox>


int mmap(DWORD ProcessId,char* dll)
{
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINH;
    PIMAGE_SECTION_HEADER pISH;

    HANDLE hProcess,hThread,hFile;
    PVOID buffer,image,mem;
    DWORD i,FileSize,ExitCode,read;


    MANUAL_INJECT ManualInject;


    hFile=CreateFile(dll,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL); // Open the DLL

    if(hFile==INVALID_HANDLE_VALUE)
    {
        MMapError(OBFUSCATED4("[-] Unable to open DLL"));
        return 0;
    }

    FileSize=GetFileSize(hFile,NULL);
    buffer=VirtualAlloc(NULL,FileSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

    if(!buffer)
    {
        MMapError(OBFUSCATED4("[-] Can't allocate Lmemory for DLL "));

        CloseHandle(hFile);
        return 0;
    }

    // Read the DLL

    if(!ReadFile(hFile,buffer,FileSize,&read,NULL))
    {
        MMapError(OBFUSCATED4("[-] Unable to read the DLL "));

        VirtualFree(buffer,0,MEM_RELEASE);
        CloseHandle(hFile);

        return 0;
    }

    CloseHandle(hFile);
 //   buffer=(HMODULE)LoadLibraryEx(dll,NULL,DONT_RESOLVE_DLL_REFERENCES);

    pIDH=(PIMAGE_DOS_HEADER)buffer;


    if(pIDH->e_magic!=IMAGE_DOS_SIGNATURE)
    {
        MMapError(OBFUSCATED4("[-] Invalid executable image."));

        VirtualFree(buffer,0,MEM_RELEASE);
        return 0;
    }

    pINH=(PIMAGE_NT_HEADERS)((LPBYTE)buffer+pIDH->e_lfanew);

    if(pINH->Signature!=IMAGE_NT_SIGNATURE)
    {
        MMapError(OBFUSCATED4("[-] Invalid PE header"));

        VirtualFree(buffer,0,MEM_RELEASE);
        return 0;
    }

    if(!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        MMapError(OBFUSCATED4("[-] The image is not DLL."));

        VirtualFree(buffer,0,MEM_RELEASE);
        return 0;
    }

    //ProcessId=atoi(argv[2]);

    hProcess=OpenProcess(CREATE_THREAD_ACCESS | THREAD_ACCESS,FALSE,ProcessId);

    if(!hProcess)
    {
        MMapError(OBFUSCATED4("[-] Cant open process "));

        VirtualFree(buffer,0,MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }


    image=VirtualAllocEx(hProcess,NULL,pINH->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE); // Allocate memory for the DLL

    if(!image)
    {
        MMapError(OBFUSCATED4("[-] Can't allocate remote Rmemory for DLL"));

        VirtualFree(buffer,0,MEM_RELEASE);
        CloseHandle(hProcess);

        return 0;
    }



    if(!myWriteProcessMemory(hProcess,image,buffer,pINH->OptionalHeader.SizeOfHeaders,NULL))
    {
        MMapError(OBFUSCATED4("[-] Cant copy headers to process"));

        VirtualFreeEx(hProcess,image,0,MEM_RELEASE);
        CloseHandle(hProcess);

        VirtualFree(buffer,0,MEM_RELEASE);
        return 0;
    }

    pISH=(PIMAGE_SECTION_HEADER)(pINH+1);

    // Copy the DLL to target process


    for(i=0;i<pINH->FileHeader.NumberOfSections;i++)
        myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)image+pISH[i].VirtualAddress),(PVOID)((LPBYTE)buffer+pISH[i].PointerToRawData),pISH[i].SizeOfRawData,NULL);



    memset(&ManualInject,0,sizeof(MANUAL_INJECT));
    ManualInject.ImageBase=image;
    ManualInject.NtHeaders=(PIMAGE_NT_HEADERS)((LPBYTE)image+pIDH->e_lfanew);
    ManualInject.BaseRelocation=(PIMAGE_BASE_RELOCATION)((LPBYTE)image+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory=(PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.fnLoadLibraryA=LoadLibraryA;
    ManualInject.fnGetProcAddress=GetProcAddress;
  //  qDebug("%#x\n",image);
 //   QMessageBox::critical(NULL, "Error!",":)");

   // qDebug("End: %#x %#x %#x %#x\n",ManualInject.ImageBase,ManualInject.NtHeaders,ManualInject.BaseRelocation,ManualInject.ImportDirectory);
    if(hijack_stub)
    {
        stubs obj;
        obj.in=(void *)LoadDll2;
        obj.fin=(void *)LoadDllEnd;
        param p;
        char * str2;
        p.data=&ManualInject;
        p.a=sizeof(ManualInject);
        if(mytrick(ProcessId, obj, p,false)!=1)
        {
            auto str=DEF_OBFUSCATED4("[-] Hijack stub failed :(");
        /*    char *str1;
            str1=(char *)malloc(size);
            strncpy(str1,wtn.decrypt(),size);*/
            int size=str.ssize();
            str2=(char *) malloc(strlen(MError)+size);
            sprintf(str2,"%s\n%s",str,MError);
            free(MError);
            MMapError(str2);
            free(str2);
            VirtualFreeEx(hProcess,image,0,MEM_RELEASE);
            CloseHandle(hProcess);
            VirtualFree(buffer,0,MEM_RELEASE);
            return 0;
        }

    }
    else
    {
        mem=VirtualAllocEx(hProcess,NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

        if(!mem)
        {
            MMapError(OBFUSCATED4("[-] Can't allocate memory for the loader code"));
            VirtualFreeEx(hProcess,image,0,MEM_RELEASE);
            CloseHandle(hProcess);
            VirtualFree(buffer,0,MEM_RELEASE);
            return 0;
        }
        if(!myWriteProcessMemory(hProcess,mem,&ManualInject,sizeof(ManualInject),NULL))  // Write the loader information to target process
        {
            MMapError(OBFUSCATED4("[-] Can't write to remote process!"));
            VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
            VirtualFreeEx(hProcess,image,0,MEM_RELEASE);
            CloseHandle(hProcess);
            VirtualFree(buffer,0,MEM_RELEASE);
            return 0;
        }

        if(!myWriteProcessMemory(hProcess,(PVOID)((PMANUAL_INJECT)mem+1),(PVOID)LoadDll2,(MYWORD)LoadDllEnd-(MYWORD)LoadDll2,NULL)) // Write the loader code to target process
        {
            MMapError(OBFUSCATED4("[-] Can't write to remote process!"));
            VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
            VirtualFreeEx(hProcess,image,0,MEM_RELEASE);
            CloseHandle(hProcess);
            VirtualFree(buffer,0,MEM_RELEASE);
            return 0;
        }

    //    qDebug("Addr %#x\n",mem+1);
  //       QMessageBox::critical(NULL, "Error!",":)");

        hThread= NtCreateThreadEx(hProcess,(PVOID)((PMANUAL_INJECT)mem+1),mem); // Create a remote thread to execute the loader code

        if(!hThread)
        {
            MMapError(OBFUSCATED4("[-] Unable to execute loader code "));
            VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
            VirtualFreeEx(hProcess,image,0,MEM_RELEASE);
            CloseHandle(hProcess);
            VirtualFree(buffer,0,MEM_RELEASE);
            return 0;
        }

        WaitForSingleObject(hThread,INFINITE);
        GetExitCodeThread(hThread,&ExitCode);

        if(!ExitCode)
        {
            VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
            VirtualFreeEx(hProcess,image,0,MEM_RELEASE);

            CloseHandle(hThread);
            CloseHandle(hProcess);

            VirtualFree(buffer,0,MEM_RELEASE);
            return 0;
        }

        CloseHandle(hThread);
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
    }
    CloseHandle(hProcess);
    // talvez free image, caso a execução terminou?
    VirtualFree(buffer,0,MEM_RELEASE);
    hijack=(HMODULE)ManualInject.ImageBase;
    return 1;
}
