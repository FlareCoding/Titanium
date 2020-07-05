.code

NormalRoutineNativeAssembly proc

	mov     qword ptr [rsp+24], r8
    mov     qword ptr [rsp+16], rdx
    mov     qword ptr [rsp+8], rcx
    sub     rsp, 56                            
    mov     rax, qword ptr [rsp+64]
    mov     qword ptr [rsp+32], rax
    mov     rax, qword ptr [rsp+32]
    add     rax, 56                             
    mov     rcx, qword ptr [rsp+32]
    add     rcx, 40                             
    mov     r9, rax
    mov     r8, rcx
    xor     edx, edx
    xor     ecx, ecx
    mov     rax, qword ptr [rsp+32]
    call    qword ptr [rax+24]
    mov     rax, qword ptr [rsp+32]
    mov     BYTE PTR [rax+64], 1
    add     rsp, 56                             
    ret     0

NormalRoutineNativeAssembly endp
end
