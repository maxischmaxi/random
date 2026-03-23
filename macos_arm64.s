// ===========================================================================
// macOS ARM64 (Apple Silicon) — Cryptographic Random Hex Generator
// ===========================================================================
//
// Generates 32 random bytes and prints them as a 64-character hex string.
// Equivalent to: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
//
// Build:
//   as macos_arm64.s -o macos_arm64.o
//   ld -e _start -o random macos_arm64.o -lSystem -syslibroot $(xcrun --show-sdk-path)
//
// Key differences from x86_64 (see main.asm for the most detailed comments):
//   - CPU architecture: ARM64 (AArch64) instead of x86_64
//   - Completely different instruction set and register names
//   - Syscall convention: x16 = syscall number, x0–x5 = args, svc #0x80
//     (x86_64 uses rax for number and rdi/rsi/rdx for args with "syscall")
//   - No 0x2000000 prefix on syscall numbers (unlike macOS x86_64)
//   - Stack pointer must be 16-byte aligned at ALL times (not just at calls)
//   - ARM64 uses fixed-width 4-byte instructions (x86_64 is variable-length)
//
// ARM64 register overview:
//   x0–x7   = arguments and return values (caller-saved)
//   x8      = indirect result register
//   x9–x15  = temporary registers (caller-saved)
//   x16–x17 = intra-procedure scratch (used for syscall number on macOS)
//   x18     = platform register (reserved on macOS, do not use)
//   x19–x28 = callee-saved (preserved across function calls)
//   x29     = frame pointer (FP)
//   x30     = link register (LR, return address)
//   sp      = stack pointer (must always be 16-byte aligned)
//
//   w0–w30 are the lower 32-bit halves of x0–x30 (like eax is to rax on x86)
//
// ===========================================================================

.global _start
.p2align 2                     // Align to 4 bytes (2^2). ARM64 instructions are
                               // always exactly 4 bytes, and must be aligned to
                               // a 4-byte boundary. .p2align 2 ensures this.

// macOS ARM64 syscall numbers (no 0x2000000 prefix, unlike x86_64)
.equ SYS_EXIT,       1        // exit(int status)
.equ SYS_WRITE,      4        // write(int fd, void *buf, size_t count)
.equ SYS_GETENTROPY, 244      // getentropy(void *buf, size_t buflen)

// ===========================================================================
// Stack layout after "sub sp, sp, #112":
//
//   Address          Contents              Size
//   ────────────     ──────────────        ─────
//   sp + 0           raw_bytes             32 bytes (random data from kernel)
//   sp + 32          hex_out               64 bytes (hex characters)
//   sp + 96          newline ('\n')         1 byte
//   sp + 97..111     unused padding        15 bytes (for 16-byte alignment)
//                                          ───────
//                               Allocated: 112 bytes (= 97 rounded up to 16)
//
// ARM64 requires sp to be 16-byte aligned at all times. sub/add to sp must
// use multiples of 16, otherwise the CPU raises an alignment fault.
// ===========================================================================

_start:
    // =====================================================================
    // STEP 1: Reserve stack space
    // =====================================================================
    sub sp, sp, #112           // Reserve 112 bytes (97 needed, 16-byte aligned).
                               // On ARM64, "sub" subtracts: sp = sp - 112.
                               // The # prefix marks an immediate (literal) value.

    // =====================================================================
    // STEP 2: Get 32 random bytes from the kernel
    // =====================================================================
    // ARM64 macOS syscall convention:
    //   x16 = syscall number (NOT x0 or rax like on x86_64)
    //   x0  = 1st argument
    //   x1  = 2nd argument
    //   x2  = 3rd argument (and so on up to x5)
    //   svc #0x80 triggers the syscall (like "syscall" on x86_64)
    //   Return value in x0. On error, carry flag is set.
    // -----------------------------------------------------------------
    mov x16, SYS_GETENTROPY    // Syscall number → x16 (not x0!)
    mov x0, sp                 // 1st arg: buffer = sp (raw_bytes)
    mov x1, #32                // 2nd arg: 32 bytes
    svc #0x80                  // Supervisor Call: triggers kernel syscall.
                               // "svc" = ARM's equivalent of x86's "syscall".
                               // #0x80 is the syscall trap number on macOS.

    // =====================================================================
    // STEP 3: Convert raw bytes to hex string
    // =====================================================================
    // We use callee-saved registers (x19–x22) for values that must survive
    // across the loop. Since _start never returns, we don't need to
    // save/restore them — there's no caller to return to.
    // -----------------------------------------------------------------
    mov x19, sp                // x19 = read pointer (raw_bytes at sp+0)
    add x20, sp, #32           // x20 = write pointer (hex_out at sp+32)
                               // "add" computes sp + 32 and stores in x20.
    adrp x21, hex_table@PAGE   // x21 = page-aligned base address of hex_table.
                               // "adrp" = Address of Register Page. Loads the 4 KB
                               // page address containing the label (PC-relative).
                               // Needed because hex_table is in .data (different
                               // section), and "adr" can't cross section boundaries.
    add x21, x21, hex_table@PAGEOFF // Add the page offset to get the exact address.
                               // @PAGE = which 4 KB page, @PAGEOFF = offset within
                               // that page. Together they form the full address.
    mov x22, #32               // x22 = loop counter (32 bytes to process)

.loop:
    // --- Load one byte ---
    ldrb w0, [x19], #1        // Load Byte: reads 1 byte from address [x19] into w0
                               // (zero-extended to 32 bits), then post-increments
                               // x19 by 1. The ", #1" is post-index addressing:
                               // first load from [x19], then x19 = x19 + 1.
                               // This combines "load" and "advance pointer" in one
                               // instruction — more efficient than separate ops.
                               // w0 is the 32-bit lower half of x0.

    // --- Upper nibble (bits 7–4) ---
    lsr w1, w0, #4             // Logical Shift Right: w1 = w0 >> 4.
                               // Moves the upper 4 bits to positions 3–0.
                               // Example: 0xB3 >> 4 = 0x0B = 11.
    ldrb w1, [x21, x1]        // Load byte from hex_table[w1].
                               // [x21, x1] = base + offset addressing.
                               // x21 = table base, x1 = index (0–15).
    strb w1, [x20], #1        // Store Byte: write hex char to [x20], post-increment.
                               // strb = Store Register Byte.

    // --- Lower nibble (bits 3–0) ---
    and w0, w0, #0x0F          // Bitwise AND: keep only lower 4 bits.
                               // Example: 0xB3 & 0x0F = 0x03 = 3.
    ldrb w0, [x21, x0]        // Look up hex_table[w0]
    strb w0, [x20], #1        // Write hex char, advance pointer

    // --- Loop control ---
    subs x22, x22, #1         // Subtract and Set flags: x22 = x22 - 1.
                               // "subs" (with 's') updates the condition flags
                               // (like "dec" on x86 sets the zero flag).
                               // On ARM64, you must explicitly use "subs" to
                               // set flags — plain "sub" does NOT set them.
    b.ne .loop                 // Branch if Not Equal (i.e., if x22 != 0).
                               // "b.ne" checks the zero flag set by "subs".
                               // Equivalent to x86's "jnz".

    // =====================================================================
    // STEP 4: Append newline and write to stdout
    // =====================================================================
    mov w0, #10                // ASCII 10 = newline
    strb w0, [x20]             // Write newline at current position (sp + 96)

    mov x16, SYS_WRITE         // Syscall: write
    mov x0, #1                 // 1st arg: fd = 1 (stdout)
    add x1, sp, #32            // 2nd arg: buffer = hex_out (sp + 32)
    mov x2, #65                // 3rd arg: 65 bytes (64 hex + newline)
    svc #0x80

    // =====================================================================
    // STEP 5: Exit
    // =====================================================================
    mov x16, SYS_EXIT          // Syscall: exit
    mov x0, #0                 // Exit code 0
    svc #0x80

// ========================== Constant Data ==================================
// .data section for the hex lookup table. On ARM64, data and code are in
// separate sections. The "adr" instruction above loads this address
// relative to the program counter.
// ==========================================================================
.data
hex_table:
    .ascii "0123456789abcdef"
