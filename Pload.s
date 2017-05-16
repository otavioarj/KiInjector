.intel_syntax noprefix
	.text
	
	
	.globl	_Pload
	
_Pload:
	pushad
	pushfd
	call start
	
	start: 
		pop ecx
		sub ecx,7
	lea eax,[ecx+26] 
	push ecx
	push eax
	call dword ptr [ecx-4] 	  
	 pop ecx	
     mov [ecx+26],eax   
	 popfd 
	 popad 
	 ret

	

	
	.globl	_Pload_stub

_Pload_stub:
	ret

	.globl	_Pload2
	
_Pload2:
	pushad
	pushfd
	call start2
	
	start2: 
		pop ecx
		sub ecx,7
	lea eax,[ecx+27] 
	push ecx
	push eax
	call dword ptr [ecx-4] 	
     pop ebx 
	 pop ecx	
     mov [ecx+27],eax   
	 popfd 
	 popad 
	 ret

	

	
	.globl	_Pload_stub2

_Pload_stub2:
	ret
	
