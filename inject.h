#ifndef INJ
#define INJ

#define WIN32_LEAN_AND_MEAN
//#define _WIN32_WINNT 0x500
#include <windows.h>
#include <Psapi.h>
//#include <cstdio>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <Ntsecapi.h>

#ifdef __x86_64__
#define MYWORD   DWORD64
#else
#define MYWORD DWORD
#endif

#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

#define THREAD_ACCESS (THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |  THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SUSPEND_RESUME )

//DWORD getThreadID(DWORD pid);
int thijack(int pid, char *dllname);

/*typedef struct _UNICODE_STRING { // UNICODE_STRING structure
         USHORT Length;
         USHORT MaximumLength;
         PWSTR  Buffer;
} UNICODE_STRING;*/
typedef UNICODE_STRING *PUNICODE_STRING;

typedef VOID (WINAPI *fRtlInitUnicodeString) //RtlInitUnicodeString function prototype
    (
         PUNICODE_STRING DestinationString,
         PCWSTR SourceString
    );



typedef long (WINAPI *fLdrLoadDll) //LdrLoadDll function prototype
    (
         IN PWCHAR PathToFile OPTIONAL,
         IN ULONG Flags OPTIONAL,
         IN PUNICODE_STRING ModuleFileName,
         OUT PHANDLE ModuleHandle
    );



struct EnumData {
    DWORD dwProcessId;
    HWND hWnd;
};

struct pdata {
    fLdrLoadDll p1;
    UNICODE_STRING p2;
};

struct pvoids{
    PVOID p1;
    PVOID p2;
    PVOID p3;
};

HWND FindWindowFromProcessId( DWORD dwProcessId );

HMODULE GetRemoteModuleHandle(unsigned long, char *);
//FARPROC GetRemoteProcAddress(unsigned long, char *, char *);

DWORD getThreadID(DWORD pid);

struct stubs
{
  void *in ;
  void *fin;

};

struct param
{
    void *data;
    unsigned int a;
};
int mytrick(int pid, stubs obj, param p, bool slub);


pvoids LoadMan(LPSTR file, HANDLE hProcess);

extern "C" void DC_stubend(void);
extern "C" void DllCall_stub(HMODULE hMod);

extern "C" MYWORD Pload(void);
extern "C" void Pload_stub(void);

#ifndef _WIN64
extern "C" MYWORD Pload2(void);
extern "C" void Pload_stub2(void);
#endif

HMODULE WINAPI LoadDll(pdata *points);
void LoadDLL_stub();
pdata Wap_LoadDll(LPSTR lpFileName);
extern char  *MError;

int HideInList(HMODULE *hHideModule);
void Hide_end();

char * MMapError(const char * str);
extern HMODULE hijack;


typedef NTSTATUS (NTAPI * tLdrUnregisterDllNotification)( PVOID );
typedef HMODULE (WINAPI * tGetModuleHandle)(LPCTSTR);

typedef SIZE_T (WINAPI * tVirtualQuery)(LPCVOID ,
                                        PMEMORY_BASIC_INFORMATION,SIZE_T dwLength);

void fix_undll( MYWORD []);
int find_undll(void *addr);
void find_end();

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE,LPCSTR);
typedef BOOL (WINAPI *PDLL_MAIN)(HMODULE,DWORD,PVOID);
typedef NTSTATUS (NTAPI *pZwWriteVirtualMemory)(IN HANDLE               ProcessHandle,
                                                 IN PVOID                BaseAddress,
                                                 IN LPCVOID                Buffer,
                                                 IN ULONG                NumberOfBytesToWrite,
                                                 OUT SIZE_T  *           NumberOfBytesWritten);

/*
typedef NTSTATUS (*pZwProtectVirtualMemory)(
 IN HANDLE               ProcessHandle,
 IN OUT PVOID            *BaseAddress,
 IN OUT PULONG           NumberOfBytesToProtect,
 IN ULONG                NewAccessProtection,
 OUT PULONG              OldAccessProtection );*/

BOOL myWriteProcessMemory(HANDLE  hProcess,LPVOID  lpBaseAddress,LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);

typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT,*PMANUAL_INJECT;

MYWORD WINAPI LoadDll2(PVOID p);
void WINAPI LoadDllEnd();
int mmap( DWORD ProcessId,char* dll);

extern bool hijack_stub;
extern int hijack_stub_delay;
HANDLE  NtCreateThreadEx(HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpSpace);


//void* getprocaddress(HMODULE module, const char *proc_name);

#endif
