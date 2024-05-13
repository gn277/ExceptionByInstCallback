

.CODE
	NtSetContextThreadProc PROC
	    mov        r10, rcx
        mov        eax, 00000000H
        add        rsp, 16
        syscall
        sub        rsp, 16
        ret
	NtSetContextThreadProc ENDP

	NtSuspendThreadProc PROC
	    mov        r10, rcx
        mov        eax, 00000000H
        add        rsp, 16
        syscall
        sub        rsp, 16
        ret
	NtSuspendThreadProc ENDP

	NtContinueProc PROC
	    mov        r10, rcx
        mov        eax, 00000000H
        add        rsp, 16
        syscall
        sub        rsp, 16
        ret
	NtContinueProc ENDP

	NtResumeThreadProc PROC
	    mov        r10, rcx
        mov        eax, 00000000H
        add        rsp, 16
        syscall
        sub        rsp, 16
        ret
	NtResumeThreadProc ENDP
END

