#include <windows.h>


__declspec() void DllCall_stub(HMODULE hMod)
{
    int no;
    __asm __volatile__
     (
        "push 0;"
        "push 1;"
        "push %1;"      
        "mov 0xDEADBEEF,%%eax;"   
        "call *%%eax;"        
                     

        "ret;"
        :"=r"(no)
        :"r"(hMod)
        :"eax");

            
                       
                     



}


__declspec() void DC_stubend(void) { }
