	.intel_syntax noprefix
	.text
	.globl	_DllCall_stub
	.def	_DllCall_stub;	.scl	2;	.type	32;	.endef

_DllCall_stub:
	push 0
	push 1
	push [esp]     
	mov eax, 0xDEADBEEF
	call eax 
	ret   

	.globl	_DC_stubend
#	.def	_DC_stubend;	.scl	2;	.type	32;	.endef
_DC_stubend:
	ret

