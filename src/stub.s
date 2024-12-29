.data
	wSyscall	DWORD	0h
	pJmpAddr	QWORD	0h  


.code

	HellsGate PROC
		mov wSyscall, ecx
		mov pJmpAddr, rdx
		ret
	HellsGate ENDP

	HellDescent PROC 
		mov rax, rcx
		mov r10, rax 
		mov eax, wSyscall
		jmp pJmpAddr
	HellDescent ENDP

end