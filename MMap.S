	.intel_syntax
	.section .text
	.glob DllCall_stub
	.glob DC_stubend


.type DC_stubend, @function
DC_stubend:
		ret
		

	
.type DllCall_stub, @function
DllCall_stub:
	  push 0
      push 1
      push [esp+0Ch]     
      mov eax, 0xDEADBEEF  
      call eax   
      ret    