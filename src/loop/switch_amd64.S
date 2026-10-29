// elodin_fiber_switch(from_sp: **void, to_sp: *void)
//
// Saves the System V callee-saved registers (rbp, rbx, r12-r15) on the current
// stack, stores the stack pointer through `from_sp`, loads `to_sp`, restores the
// same registers from there and returns into whatever that stack last switched
// out of. rbx is also copied to rdi, which is how a fiber's first switch hands
// its entry point the argument: `fiber_prepare` puts it in the rbx slot and the
// entry's address where the return address is popped from.
//
// The x87 control word and MXCSR are not saved: nothing in this process changes
// them, so every fiber runs with the values the thread started with.
	.text
	.globl elodin_fiber_switch
	.type elodin_fiber_switch,@function
elodin_fiber_switch:
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	movq %rsp, (%rdi)
	movq %rsi, %rsp
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
	movq %rbx, %rdi
	ret
	.size elodin_fiber_switch, .-elodin_fiber_switch
	.section .note.GNU-stack,"",@progbits
