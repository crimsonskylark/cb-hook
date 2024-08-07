
; void stack_fix( DEVICE_OBJECT *device_obj, MOUSE_INPUT_DATA *mid_in, MOUSE_INPUT_DATA *mid_end, u32 *out )

EXTERNDEF resume_addr:QWORD

.data
resume_addr dq 0;

.code

stack_fix proc
	mov rax, rsp
	mov qword ptr [rax+8], rbx
	mov qword ptr [rax+10h], rsi
	mov qword ptr [rax+18h], rdi
	mov qword ptr [rax+20h], r9

	push rbp
	push r12
	push r13
	push r14
	push r15
	
	mov rbp, rsp
	sub rsp, 70h

	jmp [resume_addr]

stack_fix endp

end