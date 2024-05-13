EXTERN MyCallbackRoutine:PROC
EXTERN __imp_RtlCaptureContext:dq


.CODE
	MyCallbackEntry PROC
		mov gs:[2E0H], rsp				;Win10 TEB InstrumentationCallbackPreviousSp (保存的线程参数地址)
		mov gs:[2D8H], r10				;Win10 TEB InstrumentationCallbackPreviousPc (syscall 的返回地址)

		mov r10, rcx					;保存rcx
		sub rsp, 4D0H					;Context结构大小
		and rsp, -10H					;align rsp
		mov rcx, rsp					;parameters are fun
		call __imp_RtlCaptureContext	;保存线程Context上下文

		sub rsp, 20H					;开辟栈空间
		call MyCallbackRoutine			;调用我们的函数

		int 3							;不应该执行到这里
	MyCallbackEntry ENDP

END