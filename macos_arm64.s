// ===========================================================================
// macOS ARM64 (Apple Silicon) — Cryptographic Random Hex Generator
// ===========================================================================
//
// Usage: ./random [N]    (default: 32 bytes)
// Output: 2*N hex characters + newline
//
// Build:
//   as macos_arm64.s -o macos_arm64.o
//   ld -e _start -o random macos_arm64.o -lSystem -syslibroot $(xcrun --show-sdk-path)
//
// See linux_x86_64.asm for the most detailed comments on the algorithm.
//
// ARM64 syscall convention on macOS:
//   x16 = syscall number, x0–x5 = args, svc #0x80, return in x0
//
// ARM64 register overview:
//   x0–x7   = arguments / return values (caller-saved)
//   x9–x15  = temporary (caller-saved)
//   x16     = syscall number
//   x19–x28 = callee-saved (we use x19–x24 freely since _start never returns)
//   sp      = stack pointer (must be 16-byte aligned at ALL times)
//   w0–w30  = lower 32-bit halves of x0–x30
//
// ===========================================================================

.global _start
.p2align 2                     // Align to 4 bytes (ARM64 instruction size)

.equ SYS_EXIT,       1
.equ SYS_WRITE,      4
.equ SYS_GETENTROPY, 244      // Max 256 bytes per call

_start:
    // =================================================================
    // STEP 1: Parse command line argument (default: 32)
    // =================================================================
    // Stack at entry: [sp]=argc, [sp+8]=argv[0], [sp+16]=argv[1]
    mov w19, #32               // x19 = byte count N (default 32)

    ldr x0, [sp]              // x0 = argc
    cmp x0, #2
    b.lt .alloc                // No argument → use default

    ldr x1, [sp, #16]         // x1 = pointer to argv[1] string
    mov w0, #0                 // w0 = accumulator

.parse:
    ldrb w2, [x1], #1         // Load next char, post-increment pointer
    sub w2, w2, #'0'          // Convert ASCII to digit
    cmp w2, #9
    b.hi .parse_done           // Not a digit (unsigned > 9) → stop
    mov w3, #10
    mul w0, w0, w3             // accumulator *= 10
    add w0, w0, w2             // accumulator += digit
    b .parse

.parse_done:
    cmp w0, #0
    csel w19, w0, w19, ne     // x19 = (w0 != 0) ? w0 : default
                               // "csel" = Conditional Select (ARM64's cmov)

    // =================================================================
    // STEP 2: Allocate stack space: 3*N + 1, rounded up to 16
    // =================================================================
.alloc:
    add w0, w19, w19, lsl #1  // w0 = N + N*2 = 3*N
                               // "lsl #1" shifts the second operand left by 1 (×2)
                               // so w19 + (w19 << 1) = w19 + 2*w19 = 3*w19
    add w0, w0, #1             // w0 = 3*N + 1
    add w0, w0, #15            // Round up to 16-byte alignment
    and w0, w0, #-16
    sub sp, sp, x0             // Allocate on stack

    // =================================================================
    // STEP 3: Get random bytes (loop for > 256, getentropy limit)
    // =================================================================
    mov w20, w19               // w20 = remaining bytes
    mov x21, sp                // x21 = write position

.random_loop:
    mov w1, #256
    cmp w20, #256
    csel w1, w20, w1, lt      // chunk = min(remaining, 256)
    mov w22, w1                // Save chunk size

    mov x16, SYS_GETENTROPY
    mov x0, x21                // buffer
                               // x1 already set to chunk size
    svc #0x80

    add x21, x21, x22         // Advance write position
    sub w20, w20, w22          // Decrease remaining
    cbnz w20, .random_loop     // "Compare and Branch if Not Zero"

    // =================================================================
    // STEP 4: Convert bytes to hex
    // =================================================================
    mov x20, sp                // Read pointer (raw_bytes)
    add x21, sp, x19           // Write pointer (hex_out = sp + N)
    adrp x22, hex_table@PAGE
    add x22, x22, hex_table@PAGEOFF
    mov w23, w19               // Loop counter = N

.loop:
    ldrb w0, [x20], #1        // Load byte, post-increment

    lsr w1, w0, #4             // Upper nibble
    ldrb w1, [x22, x1]        // Look up hex char
    strb w1, [x21], #1        // Write, advance

    and w0, w0, #0x0F          // Lower nibble
    ldrb w0, [x22, x0]        // Look up hex char
    strb w0, [x21], #1        // Write, advance

    subs w23, w23, #1
    b.ne .loop

    // =================================================================
    // STEP 5: Write to stdout
    // =================================================================
    mov w0, #10
    strb w0, [x21]             // Append newline

    mov x16, SYS_WRITE
    mov x0, #1                 // stdout
    add x1, sp, x19            // buffer = hex_out (sp + N)
    add x2, x19, x19
    add x2, x2, #1             // count = 2*N + 1
    svc #0x80

    // =================================================================
    // STEP 6: Exit
    // =================================================================
    mov x16, SYS_EXIT
    mov x0, #0
    svc #0x80

.data
hex_table:
    .ascii "0123456789abcdef"
