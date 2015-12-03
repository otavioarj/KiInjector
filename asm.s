	.file	"asm.c"
	.intel_syntax noprefix
	.text
	.globl	_DllCall_stub
	.def	_DllCall_stub;	.scl	2;	.type	32;	.endef
_DllCall_stub:
LFB5:
	
/APP
 # 7 "asm.c" 1
	push 0
        push 1
        push [edx]
        mov eax,0xDEADBEEF
        call eax
        ret
 # 0 "" 2

	
LFE5:
	.globl	_DC_stubend
	.def	_DC_stubend;	.scl	2;	.type	32;	.endef
_DC_stubend:
LFB6:
/APP
	ret
