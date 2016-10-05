#include "inject.h"


typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA LoaderData;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    PVOID FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    BYTE Spare2[0x4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID **ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    ULONG OSBuildNumber;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG GdiHandleBuffer[0x22];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionBitmap;
    BYTE TlsExpansionBitmapBits[0x80];
    ULONG SessionId;
} PEB, *PPEB;




typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    VOID* DllBase;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;



int HideInList(HMODULE * hHide)
{
    HMODULE hHideModule;
    hHideModule=*hHide;
    PPEB pPeb = NULL;
    int ret=0;
    asm volatile (
        //"push %%eax;"
#ifdef _WIN64
        "mov %%fs:(0x60),%%eax;"
#else
        "mov %%fs:(0x30),%%eax;"
#endif
        "mov %%eax,%0;"
  //      "pop %%eax;"
       :"=r" (pPeb)
       :
       :);
    PPEB_LDR_DATA pLdr = pPeb->LoaderData;
    PLDR_MODULE pModule = (PLDR_MODULE) pLdr->InLoadOrderModuleList.Flink;
    PLDR_MODULE pFirstModule = (PLDR_MODULE) &pLdr->InLoadOrderModuleList;
    LIST_ENTRY le;

    do
    {
        if (pModule->BaseAddress == (PVOID)hHideModule)
        {
            memcpy(&le,&pModule->InInitializationOrderModuleList,sizeof(le));
            pModule->InInitializationOrderModuleList.Blink->Flink = le.Flink;
            pModule->InInitializationOrderModuleList.Flink->Blink = le.Blink;

            memcpy(&le,&pModule->InLoadOrderModuleList,sizeof(le));
            pModule->InLoadOrderModuleList.Blink->Flink = le.Flink;
            pModule->InLoadOrderModuleList.Flink->Blink = le.Blink;

            memcpy(&le,&pModule->InMemoryOrderModuleList,sizeof(le));
            pModule->InMemoryOrderModuleList.Blink->Flink = le.Flink;
            pModule->InMemoryOrderModuleList.Flink->Blink = le.Blink;
            ret=1;
        }

        pModule = (PLDR_MODULE) pModule->InLoadOrderModuleList.Flink;
    } while(pFirstModule != pModule);
  //  asm  volatile( "pop %ebx");
    return ret;
}

void Hide_end()
{}


void fix_undll(DWORD ret[])
{  
   ret[0] = (MYWORD)GetProcAddress( GetModuleHandle( "ntdll.dll" ), "LdrUnregisterDllNotification" );
   ret[1] =  (MYWORD)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "GetModuleHandleA");
   ret[2] =  (MYWORD)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "VirtualQuery");

 }

int find_undll(void *addr)
{
    void *p, *p2;//, *edr;
    unsigned long int * swp;
    MYWORD *a;
    a=(MYWORD *)addr;
    MEMORY_BASIC_INFORMATION info;  
    //IMAGE_OPTIONAL_HEADER pe;
    IMAGE_NT_HEADERS  ai; //ImageNtHeaders(GetModuleHandle(NULL));
    tGetModuleHandle Get= (tGetModuleHandle) a[1];
    tVirtualQuery Virt = (tVirtualQuery) a[2];
    DWORD base=(DWORD)Get(NULL);
    DWORD database;
    unsigned  int n;

    memcpy(&ai,(void *)(base+0x80),sizeof(IMAGE_NT_HEADERS));
    database=base+ai.OptionalHeader.BaseOfData;
   // printf("Base:%#x DataBase: %#x\n",base+0x80,database);
   /* if(ai.Signature != IMAGE_NT_SIGNATURE)
        printf("Wrong NtImage!\n");*/

    DWORD s=ai.OptionalHeader.SizeOfImage;
    tLdrUnregisterDllNotification LdrUnregisterDllNotification = (tLdrUnregisterDllNotification) a[0];
    for ( p = (PVOID)database; Virt(p, &info, sizeof(info)) == sizeof(info) && p<(PVOID)(base+s); p += info.RegionSize )
      if ((p!=NULL) && (info.Protect | PAGE_READWRITE ))
      //  {
         //   printf("[D] Last region 0x%x , size: %d \n",(unsigned int) p,(int) info.RegionSize);
            for(n=0;n<info.RegionSize;n+=sizeof(PVOID))
            {
               swp=(unsigned long int *)((DWORD)p+(DWORD)n);
               p2=(PVOID)*swp;
               // if(p2>=ntbase)
                 if(!LdrUnregisterDllNotification(p2))
                  return 1;
            }

        //}
    return 0;

}

void find_end(){}
