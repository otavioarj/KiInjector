/* Just a bunch of small tricks I used in the past to increase the R.E time by  A/C devs :)
   In 2019 it's all deprecated :) 
*/


#ifndef ANTIS_H
#define ANTIS_H


#define WIN32_LEAN_AND_MEAN
//#define _WIN32_WINNT 0x500
#include <windows.h>
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    void* PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION;
#include <wincrypt.h>

#include <intrin.h>

#include "../ADVobfuscator/ADVobfuscator/MetaString4.h"
#include "inject.h"

#define IsVistaOrHigher  GetVersionWord() >= _WIN32_WINNT_VISTA

void swapBase();

inline unsigned char *randb(int num)
{
    BYTE *ret;

    ret=(unsigned char *)malloc(num);
    HCRYPTPROV hProv;

    CryptAcquireContext(&hProv,0,0,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);

    if(CryptGenRandom(hProv,num,ret))
        return ret;
    else
        return NULL;
}

inline PVOID GetPEB()
{
#ifdef _WIN64
    return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
    return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

LPVOID GetModuleFunc(LPCSTR csModuleName, LPCSTR sFuncName);

inline int rdtsc_diff_vmexit()
{
    ULONGLONG tsc1 = 0;
    ULONGLONG tsc2 = 0;
    ULONGLONG avg = 0;
    INT cpuInfo[4] = {};

    // Try this 1000 times in case of small fluctuations
    for (INT i = 0; i < 1000; i++)
    {
        tsc1 = __rdtsc();
        __cpuid(cpuInfo, 0);
        tsc2 = __rdtsc();

        // Get the delta of the two RDTSC
        avg += (tsc2 - tsc1);
    }


    avg = avg / 1000;
    return (avg < 3000 && avg > 0) ?  avg*2 : 1+ avg*2;
}

/*
inline MYWORD get_idt_base (void)
{
    struct _idtr {
        short int limit;
        MYWORD base;
    };
    _idtr idtr;


    asm( "sidt %0\n\t"
    : "=m" (idtr));

    return idtr.base;
}


inline MYWORD get_ldt_base (void)
{
    MYWORD  ldtr=0xdeadbeef; //[5] = "\xef\xbe\xad\xde";



    asm( "sldt %0\n\t"
    :"=r" (ldtr));   

    return ldtr;
}

inline MYWORD get_gdt_base (void)
{
   // unsigned char   gdtr[6];
    struct _gdtr {
        short int limit;
        MYWORD base;
    };
    _gdtr gdtr;

    asm( "sgdt %0\n\t"
    :"=m" (gdtr));
    return gdtr.base;
}

inline int ldt_trick()
{
    MYWORD idt_base = get_idt_base();
    MYWORD gdt_base = get_gdt_base();
    MYWORD ldt_base = get_ldt_base();

    printf("%x %x %x\n",idt_base,gdt_base,ldt_base);

    if ((idt_base >> 24) == 0xff || (gdt_base >> 24) == 0xff || ldt_base == 0xdead0000)
        return 1+ (idt_base * gdt_base*2);
    else
        return 2*ldt_base;
}
*/

inline int cpuid_is_hypervisor()
{
    INT CPUInfo[4] = { 0 };

    /* Query hypervisor precense using CPUID (EAX=1), BIT 31 in ECX */
    __cpuid(CPUInfo, 1);
    if ((CPUInfo[2] >> 31) & 1)
        return 3 + CPUInfo[2]*2;
    else
        return CPUInfo[2]*2;
}

inline int memory_space()
{
     using namespace andrivet::ADVobfuscator;
    DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 4LL))); // 4GB
    MEMORYSTATUSEX statex = {0};
    typedef BOOL (WINAPI *pGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
    statex.dwLength = sizeof(statex);
    pGlobalMemoryStatusEx pG=(pGlobalMemoryStatusEx)GetModuleFunc(OBFUSCATED4("kernel32.dll"),OBFUSCATED4("GlobalMemoryStatusEx"));
    pG(&statex);

    return (statex.ullTotalPhys < ullMinRam) ? 3+ statex.dwLength *2 : statex.dwLength *2;
}

inline int disk_size_getdiskfreespace()
{
     using namespace andrivet::ADVobfuscator;
    ULONGLONG minHardDiskSize = (80ULL * (1024ULL * (1024ULL * (1024ULL)))); //80GB
    //LPCSTR pszDrive = NULL;
    BOOL bStatus = FALSE;

    // 64 bits integer, low and high bytes
    ULARGE_INTEGER totalNumberOfBytes;
    typedef BOOL (WINAPI * pGetDiskFreeSpaceEx)(LPCTSTR,PULARGE_INTEGER,PULARGE_INTEGER ,PULARGE_INTEGER);
    pGetDiskFreeSpaceEx pD=(pGetDiskFreeSpaceEx)GetModuleFunc(OBFUSCATED4("kernel32.dll"),OBFUSCATED4("GetDiskFreeSpaceExA"));

    // If the function succeeds, the return value is nonzero. If the function fails, the return value is 0 (zero).
    bStatus = pD(NULL, NULL, &totalNumberOfBytes, NULL);
    if (bStatus) {
        if (totalNumberOfBytes.QuadPart < minHardDiskSize)  // 80GB
            return 1+ 2*bStatus;
    }

    return 2*bStatus;
}


#ifdef DEV



inline int IsPExe(){return 2;}


inline int NtStatus(){return 2;}


inline int CheckTh(){return 2;}

#else


inline WORD GetVersionWord()
{
    OSVERSIONINFO verInfo = { sizeof(OSVERSIONINFO) };
    GetVersionEx(&verInfo);
    return MAKEWORD(verInfo.dwMinorVersion, verInfo.dwMajorVersion);
}





inline int GetHeapFlagsOffset(bool x64)
{
    return x64 ?
                IsVistaOrHigher? 0x70 : 0x14: //x64 offsets
                                 IsVistaOrHigher ? 0x40 : 0x0C; //x86 offsets
}

inline int GetHeapForceFlagsOffset(bool x64)
{
    return x64 ?
                IsVistaOrHigher ? 0x74 : 0x18: //x64 offsets
                                  IsVistaOrHigher ? 0x44 : 0x10; //x86 offsets
}



#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
inline int CheckTh()
{
    PVOID pPeb = GetPEB();
    int * r,ra,ret;
    r=(int*) randb(32);
    ra=*r;
    DWORD offsetNtGlobalFlag = 0;
#ifdef _WIN64
    offsetNtGlobalFlag = 0xBC;
#else
    offsetNtGlobalFlag = 0x68;
#endif
    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
    if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
        ret= 1 + 2*ra;
    else
        ret= 2*ra;
    free(r);
    return ret ^ cpuid_is_hypervisor();

}



inline DWORD GetParentProcessId()
{
    // Much easier in ASM but C/C++ looks so much better
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)
            (HANDLE ,UINT ,PVOID ,ULONG , PULONG);
    using namespace andrivet::ADVobfuscator;
    // Some locals
    NTSTATUS Status = 0;
    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

    // Get NtQueryInformationProcess
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess) GetModuleFunc(OBFUSCATED4("ntdll.dll"),OBFUSCATED4("NtQueryInformationProcess"));
    // GetProcAddress(
    //  GetModuleHandle( (OBFUSCATED4("ntdll.dll")) ),
    //  OBFUSCATED4("NtQueryInformationProcess"));

    // Sanity check although there's no reason for it to have failed
    if(NtQIP == 0)
        return 0;

    // Now we can call NtQueryInformationProcess, the second
    // param 0 == ProcessBasicInformation
    Status = NtQIP(GetCurrentProcess(), 0, (void*)&pbi,
                   sizeof(PROCESS_BASIC_INFORMATION), 0);

    if(Status != 0x00000000)
        return 0;
    else
        return pbi.ParentProcessId;
}

inline DWORD GetExplorerPIDbyShellWindow()
{
    using namespace andrivet::ADVobfuscator;
    DWORD PID = 0;
    typedef DWORD (WINAPI * getwinpd)(HWND,LPDWORD lpdwProcessId);
    typedef HWND (WINAPI* getshell)(void);
    getwinpd getp=(getwinpd) GetModuleFunc(OBFUSCATED4("user32.dll"),OBFUSCATED4("GetWindowThreadProcessId"));
    /*GetProcAddress(
                                    GetModuleHandle( (OBFUSCATED4("user32.dll")) ),
                                    OBFUSCATED4("GetWindowThreadProcessId"));*/
    getshell gets=(getshell) GetModuleFunc(OBFUSCATED4("user32.dll"),OBFUSCATED4("GetShellWindow"));
    /* GetProcAddress(
                                    GetModuleHandle((OBFUSCATED4("user32.dll")) ),
                                    OBFUSCATED4("GetShellWindow"));*/

    // Get the PID
    getp(gets(), &PID);

    return PID;
}


inline int IsPExe()
{
    DWORD PPID = GetParentProcessId();
    if(PPID == GetExplorerPIDbyShellWindow())
        return 2*PPID;
    else
        return 2*PPID+1;
}



inline int NtStatus()
{
    PVOID pPeb = GetPEB();
    PVOID heap = 0;
    DWORD offsetProcessHeap = 0;
    PDWORD heapFlagsPtr = 0, heapForceFlagsPtr = 0;
    BOOL x64 = FALSE;
#ifdef _WIN64
    x64 = TRUE;
    offsetProcessHeap = 0x30;
#else
    offsetProcessHeap = 0x18;
#endif
    heap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb + offsetProcessHeap);
    heapFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapFlagsOffset(x64));
    heapForceFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapForceFlagsOffset(x64));
    if (*heapFlagsPtr & ~HEAP_GROWABLE || *heapForceFlagsPtr != 0)
        return 1 + 2*(rand() % 32);
    return 2 * (rand() % 32) ^ cpuid_is_hypervisor();

}

#endif


#endif // ANTIS_H
