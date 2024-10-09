//! This module contains the implementation of scalar multiplication using assembly language.

#[cfg(target_arch = "x86_64")]
use std::arch::asm;

///Implement Montgomery modular multiplication, result = result * 5
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn mont_mul_by5_asm(result: &mut [u64; 4]) {
    unsafe {
        asm!(
            "push %rdx",
            "push %rcx",
            "push %rbx",
            "push %rsi",
            "push %r15",

            "movq 0(%rdi), %rdx",
            "movq 8(%rdi), %rcx",
            "movq 16(%rdi), %rbx",
            "movq 24(%rdi), %rsi",

            "addq %rdx, %rdx",
            "adcq %rcx, %rcx",
            "adcq %rbx, %rbx",
            "adcq %rsi, %rsi",

            //reduce_macro  %rdx, %rcx, %rbx, %rsi, %rax, %r8, %r9, %r10
            "movq    %rdx, %rax",
            "movq    $0xffffffff00000001, %r15",
            "subq    %r15, %rdx",
            "movq    %rcx, %r8",
            "movq    $0x53bda402fffe5bfe, %r15",
            "sbbq    %r15, %rcx",
            "movq    %rbx, %r9",
            "movq    $0x3339d80809a1d805, %r15",
            "sbbq    %r15, %rbx",
            "movq    %rsi, %r10",
            "movq    $0x73eda753299d7d48, %r15",
            "sbbq    %r15, %rsi",
            "cmovc   %rax, %rdx",
            "cmovc   %r8, %rcx",
            "cmovc   %r9, %rbx",
            "cmovc   %r10, %rsi",

            "addq %rdx, %rdx",
            "adcq %rcx, %rcx",
            "adcq %rbx, %rbx",
            "adcq %rsi, %rsi",

            //reduce_macro %rdx, %rcx, %rbx, %rsi, %rax, %r8, %r9, %r10
            "movq    %rdx, %rax",
            "movq    $0xffffffff00000001, %r15",
            "subq    %r15, %rdx",
            "movq    %rcx, %r8",
            "movq    $0x53bda402fffe5bfe, %r15",
            "sbbq    %r15, %rcx",
            "movq    %rbx, %r9",
            "movq    $0x3339d80809a1d805, %r15",
            "sbbq    %r15, %rbx",
            "movq    %rsi, %r10",
            "movq    $0x73eda753299d7d48, %r15",
            "sbbq    %r15, %rsi",
            "cmovc   %rax, %rdx",
            "cmovc   %r8, %rcx",
            "cmovc   %r9, %rbx",
            "cmovc   %r10, %rsi",

            "addq 0(%rdi), %rdx",
            "adcq 8(%rdi), %rcx",
            "adcq 16(%rdi), %rbx",
            "adcq 24(%rdi), %rsi",

            //reduce_macro %rdx, %rcx, %rbx, %rsi, %rax, %r8, %r9, %r10
            "movq    %rdx, %rax",
            "movq    $0xffffffff00000001, %r15",
            "subq    %r15, %rdx",
            "movq    %rcx, %r8",
            "movq    $0x53bda402fffe5bfe, %r15",
            "sbbq    %r15, %rcx",
            "movq    %rbx, %r9",
            "movq    $0x3339d80809a1d805, %r15",
            "sbbq    %r15, %rbx",
            "movq    %rsi, %r10",
            "movq    $0x73eda753299d7d48, %r15",
            "sbbq    %r15, %rsi",
            "cmovc   %rax, %rdx",
            "cmovc   %r8, %rcx",
            "cmovc   %r9, %rbx",
            "cmovc   %r10, %rsi",

            "movq %rdx, 0(%rdi)",
            "movq %rcx, 8(%rdi)",
            "movq %rbx, 16(%rdi)",
            "movq %rsi, 24(%rdi)",

            "pop %r15",
            "pop %rsi",
            "pop %rbx",
            "pop %rcx",
            "pop %rdx",

            inout("rdi") result.as_mut_ptr() => _,
            out("rax") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,

            options(att_syntax),
            clobber_abi("C")
        );
    }
}

///Implement Montgomery modular multiplication, result = x * y
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn mont_mul_asm(result: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4]) {
    unsafe {
        asm!(
            "push %r15",
            "push %r14",
            "push %r13",
            "push %r12",
            "push %rbp",
            "push %rcx",
            "push %rbx",

            "movq 0(%rsi), %r12",
            "movq 8(%rsi), %r8",
            "movq 16(%rsi), %r9",
            "movq 24(%rsi), %r10",

            "movq %rdx, %r11",
            // clear the flags
            "xorq %rax, %rax",
            "movq 0(%r11), %rdx",

            // (A,t[0])  := x[0]*y[0] + A
            "mulxq %r12, %r14, %r13",

            // (A,t[1])  := x[1]*y[0] + A
            "mulxq %r8, %rax, %rcx",
            "adoxq %rax, %r13",

            // (A,t[2])  := x[2]*y[0] + A
            "mulxq %r9, %rax, %rbx",
            "adoxq %rax, %rcx",

            // (A,t[3])  := x[3]*y[0] + A
            "mulxq %r10, %rax, %rbp",
            "adoxq %rax, %rbx",

            // A += carries from ADCXQ and ADOXQ
            "movq $0, %rax",
            "adoxq %rax, %rbp",

            // m := t[0]*q'[0] mod W
            "movq $0xfffffffeffffffff, %rdx",
            "imulq %r14, %rdx",

            // clear the flags
            "xorq %rax, %rax",

            // C,_ := t[0] + m*q[0]
            "movq $0xffffffff00000001, %r15",
            "mulxq %r15, %rax, %rsi",
            "adcxq %r14, %rax",
            "movq %rsi, %r14",

            // (C,t[0]) := t[1] + m*q[1] + C
            "adcxq %r13, %r14",
            "movq $0x53bda402fffe5bfe, %r15",
            "mulxq %r15, %rax, %r13",
            "adoxq %rax, %r14",

            // (C,t[1]) := t[2] + m*q[2] + C
            "adcxq %rcx, %r13",
            "movq $0x3339d80809a1d805, %r15",
            "mulxq %r15, %rax, %rcx",
            "adoxq %rax, %r13",

            // (C,t[2]) := t[3] + m*q[3] + C
            "adcxq %rbx, %rcx",
            "movq $0x73eda753299d7d48, %r15",
            "mulxq %r15, %rax, %rbx",
            "adoxq %rax, %rcx",

            // t[3] = C + A
            "movq $0, %rax",
            "adcxq %rax, %rbx",
            "adoxq %rbp, %rbx",

            // clear the flags
            "xorq %rax, %rax",
            "movq 8(%r11), %rdx",

            // (A,t[0])  := t[0] + x[0]*y[1] + A
            "mulxq %r12, %rax, %rbp",
            "adoxq %rax, %r14",

            // (A,t[1])  := t[1] + x[1]*y[1] + A
            "adcxq %rbp, %r13",
            "mulxq %r8, %rax, %rbp",
            "adoxq %rax, %r13",

            // (A,t[2])  := t[2] + x[2]*y[1] + A
            "adcxq %rbp, %rcx",
            "mulxq %r9, %rax, %rbp",
            "adoxq %rax, %rcx",

            // (A,t[3])  := t[3] + x[3]*y[1] + A
            "adcxq %rbp, %rbx",
            "mulxq %r10, %rax, %rbp",
            "adoxq %rax, %rbx",

            // A += carries from ADCXQ and ADOXQ
            "movq $0, %rax",
            "adcxq %rax, %rbp",
            "adoxq %rax, %rbp",

            // m := t[0]*q'[0] mod W
            "movq $0xfffffffeffffffff, %rdx",
            "imulq %r14, %rdx",
            // clear the flags
            "xorq %rax, %rax",

            // C,_ := t[0] + m*q[0]
            "movq $0xffffffff00000001, %r15",
            "mulxq %r15, %rax, %rsi",
            "adcxq %r14, %rax",
            "movq %rsi, %r14",

            // (C,t[0]) := t[1] + m*q[1] + C
            "adcxq %r13, %r14",
            "movq $0x53bda402fffe5bfe, %r15",
            "mulxq %r15, %rax, %r13",
            "adoxq %rax, %r14",

            // (C,t[1]) := t[2] + m*q[2] + C
            "adcxq %rcx, %r13",
            "movq $0x3339d80809a1d805, %r15",
            "mulxq %r15, %rax, %rcx",
            "adoxq %rax, %r13",

            // (C,t[2]) := t[3] + m*q[3] + C
            "adcxq %rbx, %rcx",
            "movq $0x73eda753299d7d48, %r15",
            "mulxq %r15, %rax, %rbx",
            "adoxq %rax, %rcx",

            // t[3] = C + A
            "movq $0, %rax",
            "adcxq %rax, %rbx",
            "adoxq %rbp, %rbx",

            // clear the flags
            "xorq %rax, %rax",
            "movq 16(%r11), %rdx",

            // (A,t[0])  := t[0] + x[0]*y[2] + A
            "mulxq %r12, %rax, %rbp",
            "adoxq %rax, %r14",

            // (A,t[1])  := t[1] + x[1]*y[2] + A
            "adcxq %rbp, %r13",
            "mulxq %r8, %rax, %rbp",
            "adoxq %rax, %r13",

            // (A,t[2])  := t[2] + x[2]*y[2] + A
            "adcxq %rbp, %rcx",
            "mulxq %r9, %rax, %rbp",
            "adoxq %rax, %rcx",

            // (A,t[3])  := t[3] + x[3]*y[2] + A
            "adcxq %rbp, %rbx",
            "mulxq %r10, %rax, %rbp",
            "adoxq %rax, %rbx",

            // A += carries from ADCXQ and ADOXQ
            "movq  $0, %rax",
            "adcxq %rax, %rbp",
            "adoxq %rax, %rbp",

            // m := t[0]*q'[0] mod W
            "movq $0xfffffffeffffffff, %rdx",
            "imulq %r14, %rdx",

            // clear the flags
            "xorq %rax, %rax",

            // C,_ := t[0] + m*q[0]
            "movq $0xffffffff00000001, %r15",
            "mulxq %r15, %rax, %rsi",
            "adcxq %r14, %rax",
            "movq  %rsi, %r14",

            // (C,t[0]) := t[1] + m*q[1] + C
            "adcxq %r13, %r14",
            "movq $0x53bda402fffe5bfe, %r15",
            "mulxq %r15, %rax, %r13",
            "adoxq %rax, %r14",

            // (C,t[1]) := t[2] + m*q[2] + C
            "adcxq %rcx, %r13",
            "movq $0x3339d80809a1d805, %r15",
            "mulxq %r15, %rax, %rcx",
            "adoxq %rax, %r13",

            // (C,t[2]) := t[3] + m*q[3] + C
            "adcxq %rbx, %rcx",
            "movq $0x73eda753299d7d48, %r15",
            "mulxq %r15, %rax, %rbx",
            "adoxq %rax, %rcx",

            // t[3] = C + A
            "movq  $0, %rax",
            "adcxq %rax, %rbx",
            "adoxq %rbp, %rbx",

            // clear the flags
            "xorq %rax, %rax",
            "movq 24(%r11), %rdx",

            // (A,t[0])  := t[0] + x[0]*y[3] + A
            "mulxq %r12, %rax, %rbp",
            "adoxq %rax, %r14",

            // (A,t[1])  := t[1] + x[1]*y[3] + A
            "adcxq %rbp, %r13",
            "mulxq %r8, %rax, %rbp",
            "adoxq %rax, %r13",

            // (A,t[2])  := t[2] + x[2]*y[3] + A
            "adcxq %rbp, %rcx",
            "mulxq %r9, %rax, %rbp",
            "adoxq %rax, %rcx",

            // (A,t[3])  := t[3] + x[3]*y[3] + A
            "adcxq %rbp, %rbx",
            "mulxq %r10, %rax, %rbp",
            "adoxq %rax, %rbx",

            // A += carries from ADCXQ and ADOXQ
            "movq  $0, %rax",
            "adcxq %rax, %rbp",
            "adoxq %rax, %rbp",

            // m := t[0]*q'[0] mod W
            "movq $0xfffffffeffffffff, %rdx",
            "imulq %r14, %rdx",

            // clear the flags
            "xorq %rax, %rax",

            // C,_ := t[0] + m*q[0]
            "movq $0xffffffff00000001, %r15",
            "mulxq %r15, %rax, %rsi",
            "adcxq %r14, %rax",
            "movq  %rsi, %r14",

            // (C,t[0]) := t[1] + m*q[1] + C
            "adcxq %r13, %r14",
            "movq $0x53bda402fffe5bfe, %r15",
            "mulxq %r15, %rax, %r13",
            "adoxq %rax, %r14",

            // (C,t[1]) := t[2] + m*q[2] + C
            "adcxq %rcx, %r13",
            "movq $0x3339d80809a1d805, %r15",
            "mulxq %r15, %rax, %rcx",
            "adoxq %rax, %r13",

            // (C,t[2]) := t[3] + m*q[3] + C
            "adcxq %rbx, %rcx",
            "movq $0x73eda753299d7d48, %r15",
            "mulxq %r15, %rax, %rbx",
            "adoxq %rax, %rcx",

            // t[3] = C + A
            "movq  $0, %rax",
            "adcxq %rax, %rbx",
            "adoxq %rbp, %rbx",

            // reduce element(R14,R13,CX,BX) using temp registers (SI,R12,R11,DI)
            "movq    %r14, %rsi",
            "movq    $0xffffffff00000001, %r15",
            "subq    %r15, %r14",
            "movq    %r13, %r12",
            "movq    $0x53bda402fffe5bfe, %r15",
            "sbbq    %r15, %r13",
            "movq    %rcx, %r11",
            "movq    $0x3339d80809a1d805, %r15",
            "sbbq    %r15, %rcx",
            "movq    %rbx, %rax",
            "movq    $0x73eda753299d7d48, %r15",
            "sbbq    %r15, %rbx",
            "cmovc   %rsi, %r14",
            "cmovc   %r12, %r13",
            "cmovc   %r11, %rcx",
            "cmovc   %rax, %rbx",

            "movq   %r14, 0(%rdi)",
            "movq   %r13, 8(%rdi)",
            "movq   %rcx, 16(%rdi)",
            "movq   %rbx, 24(%rdi)",


            "pop %rbx",
            "pop %rcx",
            "pop %rbp",
            "pop %r12",
            "pop %r13",
            "pop %r14",
            "pop %r15",
            inout("rsi") x.as_ptr() => _,
            inout("rdx") y.as_ptr() => _,
            inout("rdi") result.as_mut_ptr() => _,
            out("rax") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,

            options(att_syntax),
            clobber_abi("C")
        );
    }
}
