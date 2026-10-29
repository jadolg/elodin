// elodin_fiber_switch(from_sp: **void, to_sp: *void)
//
// Saves the AAPCS64 callee-saved registers (x19-x30, d8-d15) on the current
// stack, stores the stack pointer through `from_sp`, loads `to_sp`, restores the
// same registers from there and returns into whatever that stack last switched
// out of. x19 is also copied to x0, which is how a fiber's first switch hands
// its entry point the argument: `fiber_prepare` puts it in the x19 slot and the
// entry's address in the x30 slot.
	.text
	.globl elodin_fiber_switch
	.type elodin_fiber_switch,%function
	.p2align 2
elodin_fiber_switch:
	sub sp, sp, #160
	stp x19, x20, [sp, #0]
	stp x21, x22, [sp, #16]
	stp x23, x24, [sp, #32]
	stp x25, x26, [sp, #48]
	stp x27, x28, [sp, #64]
	stp x29, x30, [sp, #80]
	stp d8, d9, [sp, #96]
	stp d10, d11, [sp, #112]
	stp d12, d13, [sp, #128]
	stp d14, d15, [sp, #144]
	mov x9, sp
	str x9, [x0]
	mov sp, x1
	ldp x19, x20, [sp, #0]
	ldp x21, x22, [sp, #16]
	ldp x23, x24, [sp, #32]
	ldp x25, x26, [sp, #48]
	ldp x27, x28, [sp, #64]
	ldp x29, x30, [sp, #80]
	ldp d8, d9, [sp, #96]
	ldp d10, d11, [sp, #112]
	ldp d12, d13, [sp, #128]
	ldp d14, d15, [sp, #144]
	add sp, sp, #160
	mov x0, x19
	ret
	.size elodin_fiber_switch, .-elodin_fiber_switch
	.section .note.GNU-stack,"",%progbits
