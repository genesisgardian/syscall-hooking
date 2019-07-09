.text
.globl  my_stub_execve_hook
.type   my_stub_execve_hook, @function
my_stub_execve_hook:
    // store register
	pushq   %rbx
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %rax
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

	// call my execve
    call    my_execve
    test    %rax, %rax
    movq    %rax, %rbx

    // restore register
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rax
    pop     %rcx
    pop     %rdx
    pop     %rsi
    pop     %rdi

    jz      my_stub_execve_hook_done

// when return not 0
drop_invalidfile_execution:
    movq    %rbx, %rax
    pop     %rbx
    ret
    
// when return 0
my_stub_execve_hook_done:
    pop     %rbx
	// call origin execve
    jmp     *o_execve
