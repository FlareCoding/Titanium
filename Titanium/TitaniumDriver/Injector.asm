.code

NormalRoutineNativeAssembly proc

	mov			qword ptr [rsp+18h], r8
	mov         qword ptr [rsp+10h], rdx  
	sub         rsp, 48h  
	mov         rax, qword ptr [rsp+50h]  
	mov         qword ptr [rsp+30h], rax  
	mov         rax, qword ptr [rsp+30h]  
	add         rax, 30h  
	mov         rcx, qword ptr [rsp+30h]  
	add         rcx, 20h  
	mov         rdx, qword ptr [rsp+30h]  
	mov         rdx, qword ptr [rdx+18h]  
	mov         qword ptr [rsp+38h], rdx  
	mov         r9, rax  
	mov         r8, rcx  
	xor         edx, edx  
	xor         ecx, ecx  
	mov         rax, qword ptr [rsp+38h]  
	call		rax
	mov         rax, qword ptr [rsp+30h]  
	mov         byte ptr [rax+38h], 1  
	add         rsp, 48h  
	ret

NormalRoutineNativeAssembly endp
end