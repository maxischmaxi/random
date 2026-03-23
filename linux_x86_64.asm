; ============================================================================
; MINIMAL ELF BINARY: Cryptographic Random Hex Generator
; ============================================================================
;
; Generates 32 random bytes and prints them as a 64-character hex string.
; Equivalent to: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
;
; What makes this file special?
; -----------------------------
; Normally, you build an ELF binary in two steps:
;   1. nasm -f elf64 → produces a .o object file with sections
;   2. ld            → links the object file into an executable ELF binary
;
; The linker adds a lot of overhead: section headers, symbol tables,
; string tables, and most importantly page alignment (4096-byte boundaries
; between sections), which bloats the binary to ~9 KB even though the
; actual code is only ~130 bytes.
;
; Here we bypass the linker entirely and write the ELF header by hand.
; NASM in "flat binary" mode (-f bin) outputs bytes exactly as we define
; them — no additional wrapping. The result: ~245 bytes.
;
; Additionally, we use the stack as a buffer instead of a BSS section.
; This saves an entire program header segment and simplifies the binary.
;
; Build & Run:
;   make linux && ./random-linux-x86_64
;
; ============================================================================

; ----------------------------------------------------------------------------
; BITS 64 — We are writing 64-bit x86 code (also known as "x86_64" or "AMD64").
; Without this directive, NASM would default to 16-bit code
; (for historical reasons — NASM dates back to the DOS era).
; ----------------------------------------------------------------------------
BITS 64

; ----------------------------------------------------------------------------
; org 0x400000 — "Origin", the virtual start address in memory.
;
; When Linux loads our binary, it maps it to this address in the process's
; virtual memory space. 0x400000 (4 MB) is the default load address for
; statically linked x86_64 ELF executables on Linux.
;
; This directive tells NASM: "When calculating addresses (e.g. for labels),
; assume that byte 0 of the file is located at address 0x400000."
; Without org, _start would be at address 0x78 (offset in the file), but
; with org it becomes 0x400078 — the correct address at runtime.
; ----------------------------------------------------------------------------
org 0x400000


; ****************************************************************************
; *                        ELF HEADER (64 Bytes)                             *
; ****************************************************************************
;
; The ELF header is the first structure in every ELF file. It is always
; exactly 64 bytes (for 64-bit) and contains:
;   - Identification (magic number, architecture, endianness)
;   - File type (executable, shared library, etc.)
;   - Entry point (where code execution begins)
;   - Pointer to the program headers (load instructions for the kernel)
;
; Run "readelf -h main" to see these fields broken down.
;
; Reference: https://man7.org/linux/man-pages/man5/elf.5.html (Elf64_Ehdr)
; ****************************************************************************

ehdr:
    ; --- e_ident: 16 bytes identification ---

    db 0x7F, "ELF"            ; Bytes 0–3: "Magic number" — these 4 bytes appear at
                               ; the start of every ELF file. The kernel checks them
                               ; first and refuses to load the file if they're missing.
                               ; 0x7F is a non-printable character, followed by the
                               ; ASCII letters 'E', 'L', 'F'.

    db 2                       ; Byte 4: EI_CLASS = ELFCLASS64 (2 = 64-bit)
                               ; Determines whether addresses and offsets are 4 or 8
                               ; bytes wide. 1 = 32-bit, 2 = 64-bit.

    db 1                       ; Byte 5: EI_DATA = ELFDATA2LSB (1 = little-endian)
                               ; x86_64 is always little-endian: the least significant
                               ; byte is stored at the lowest address.
                               ; Example: 0x0001 is stored as bytes [01, 00].

    db 1                       ; Byte 6: EI_VERSION = EV_CURRENT (always 1)
                               ; The ELF specification only has version 1.

    db 0                       ; Byte 7: EI_OSABI = ELFOSABI_NONE (0 = System V / Linux)
                               ; Indicates which OS the binary is intended for.
                               ; 0 works on Linux, FreeBSD, and other
                               ; System V-compatible systems.

    dq 0                       ; Bytes 8–15: EI_ABIVERSION + padding (8 bytes, all 0)
                               ; Reserved and unused. dq = "define quad" = 8 bytes.

    ; --- Actual header fields start here ---

    dw 2                       ; Bytes 16–17: e_type = ET_EXEC (2 = executable file)
                               ; Other values: 1 = relocatable (.o), 3 = shared (.so)
                               ; dw = "define word" = 2 bytes.

    dw 0x3E                    ; Bytes 18–19: e_machine = EM_X86_64 (0x3E = 62)
                               ; Each CPU architecture has its own number.
                               ; ARM would be 0xB7, RISC-V would be 0xF3.

    dd 1                       ; Bytes 20–23: e_version = EV_CURRENT (1)
                               ; The version again, this time as a 4-byte value.
                               ; dd = "define double word" = 4 bytes.

    dq _start                  ; Bytes 24–31: e_entry = address of _start
                               ; THE most important value: this is where execution begins.
                               ; The kernel sets the instruction pointer (RIP) to this
                               ; address after loading the binary.
                               ; _start is calculated by NASM at assembly time:
                               ; 0x400000 (org) + offset of _start in the file.

    dq phdr - ehdr             ; Bytes 32–39: e_phoff = offset to program headers
                               ; Tells the kernel where in the file the program headers
                               ; begin. phdr - ehdr = 64 (right after the ELF header).

    dq 0                       ; Bytes 40–47: e_shoff = 0 (no section header table)
                               ; Section headers are only needed by tools like objdump,
                               ; nm, or gdb — not by the kernel for loading.
                               ; By omitting them, we save hundreds of bytes.

    dd 0                       ; Bytes 48–51: e_flags = 0
                               ; Processor-specific flags. Always 0 for x86_64.

    dw ehdr_size               ; Bytes 52–53: e_ehsize = 64
                               ; Size of this ELF header. Always 64 for 64-bit ELF.

    dw phdr_size               ; Bytes 54–55: e_phentsize = 56
                               ; Size of a single program header in bytes.

    dw 1                       ; Bytes 56–57: e_phnum = 1
                               ; Number of program headers. We only have one!
                               ; A normal binary has several (code, data, BSS...).

    dw 0                       ; Bytes 58–59: e_shentsize = 0 (no section headers)
    dw 0                       ; Bytes 60–61: e_shnum = 0 (no section headers)
    dw 0                       ; Bytes 62–63: e_shstrndx = 0 (no string table index)

ehdr_size equ $ - ehdr         ; $ = current position. ehdr_size = 64 bytes.


; ****************************************************************************
; *                     PROGRAM HEADER (56 Bytes)                            *
; ****************************************************************************
;
; Program headers are the load instructions for the kernel. Each program
; header describes a "segment" — a contiguous memory region that the kernel
; should load from the file into RAM.
;
; Normally there are multiple segments:
;   - Code segment  (r-x): read + execute only
;   - Data segment  (rw-): read + write
;   - BSS segment   (rw-): like data, but not in the file (zero-filled)
;
; We pack everything into ONE segment with all permissions (rwx). This is
; insecure for production code (code should not be writable), but perfect
; for a minimal demo — it saves 2 × 56 = 112 bytes of program headers.
;
; Reference: https://man7.org/linux/man-pages/man5/elf.5.html (Elf64_Phdr)
; ****************************************************************************

phdr:
    dd 1                       ; Bytes 0–3: p_type = PT_LOAD (1)
                               ; PT_LOAD means: "Load this segment into memory."
                               ; Other types: PT_DYNAMIC (for shared libs), PT_NOTE, etc.

    dd 7                       ; Bytes 4–7: p_flags = PF_R | PF_W | PF_X (7 = rwx)
                               ; Permissions for this memory region:
                               ;   Bit 0 (1) = PF_X = executable
                               ;   Bit 1 (2) = PF_W = writable
                               ;   Bit 2 (4) = PF_R = readable
                               ;   4 + 2 + 1 = 7 = all permissions

    dq 0                       ; Bytes 8–15: p_offset = 0
                               ; From which byte in the file to start reading.
                               ; 0 = from the beginning (including the ELF header itself).

    dq ehdr                    ; Bytes 16–23: p_vaddr = 0x400000
                               ; The virtual address where the kernel maps this segment
                               ; in process memory. ehdr = 0x400000 (because of org).

    dq ehdr                    ; Bytes 24–31: p_paddr = 0x400000
                               ; Physical address — completely ignored by Linux.
                               ; Only relevant for bare-metal systems without an MMU.

    dq file_size               ; Bytes 32–39: p_filesz = size of the file
                               ; How many bytes to load from the file.
                               ; Everything: headers + code + hex_table.

    dq file_size               ; Bytes 40–47: p_memsz = size in memory
                               ; If p_memsz > p_filesz, the kernel fills the rest
                               ; with zeros (this is how BSS works). In our case both
                               ; are equal because we use the stack instead of BSS.

    dq 0x1000                  ; Bytes 48–55: p_align = 4096 (0x1000)
                               ; The segment must start at a 4096-byte boundary (page)
                               ; in memory. This is a requirement of the x86_64 Memory
                               ; Management Unit (MMU), which manages memory in 4 KB pages.

phdr_size equ $ - phdr         ; = 56 bytes


; ****************************************************************************
; *                           PROGRAM CODE                                   *
; ****************************************************************************
;
; From here on is the actual executable code. The kernel jumps here after
; loading the binary (because e_entry points to _start).
;
; Instead of BSS memory (which would require an extra segment), we use the
; stack. The stack is a memory region that the kernel automatically sets up
; for every process. It grows from high to low addresses.
;
; Stack layout after "sub rsp, 97":
;
;   Address          Contents            Size
;   ────────────     ──────────────      ─────
;   rsp + 0          raw_bytes           32 bytes (random data from kernel)
;   rsp + 32         hex_out             64 bytes (hex characters as ASCII)
;   rsp + 96         newline ('\n')       1 byte
;                                        ───────
;                                Total:  97 bytes
;
; ****************************************************************************

_start:
    ; ====================================================================
    ; STEP 1: Reserve space on the stack
    ; ====================================================================
    sub rsp, 97                ; Move RSP (Stack Pointer) 97 bytes downward.
                               ; "sub" = subtract. Since the stack grows downward,
                               ; subtracting reserves space.
                               ; The region rsp+0 through rsp+96 now belongs to us.

    ; ====================================================================
    ; STEP 2: Get 32 cryptographically secure random bytes from the kernel
    ; ====================================================================
    ;
    ; Linux syscall convention for x86_64:
    ;   rax = syscall number (which kernel function to call)
    ;   rdi = 1st argument
    ;   rsi = 2nd argument
    ;   rdx = 3rd argument
    ;   r10 = 4th argument  (not used here)
    ;   r8  = 5th argument  (not used here)
    ;   r9  = 6th argument  (not used here)
    ;   → return value is placed in rax
    ;
    ; Syscall: getrandom(buf, buflen, flags)
    ;   - Provides cryptographically secure random numbers directly from the kernel
    ;   - Like reading /dev/urandom, but without file I/O (faster, simpler)
    ;   - The same entropy source that OpenSSL/Node.js use
    ; --------------------------------------------------------------------
    mov eax, 318               ; Syscall number 318 = getrandom
                               ; We write to eax (32-bit) instead of rax (64-bit).
                               ; On x86_64, writing to a 32-bit register automatically
                               ; zeroes the upper 32 bits. This saves 1 byte of machine
                               ; code (no REX prefix needed).

    mov rdi, rsp               ; 1st arg: pointer to the buffer = rsp (raw_bytes)
                               ; This must be rdi (64-bit) because addresses on
                               ; x86_64 are always 64 bits wide.

    mov esi, 32                ; 2nd arg: number of bytes = 32 (256 bits of randomness)
                               ; Again a 32-bit register (esi) to save 1 byte.

    xor edx, edx              ; 3rd arg: flags = 0 (like /dev/urandom)
                               ; "xor x, x" is the fastest way to zero a register:
                               ; every bit XOR'd with itself = 0.
                               ; Produces only 2 bytes of machine code, while
                               ; "mov edx, 0" requires 5 bytes.
                               ; Flag 0 = non-blocking, uses the urandom pool.

    syscall                    ; Context switch into the kernel. The kernel:
                               ;   1. Reads 32 bytes from the entropy pool
                               ;   2. Writes them to the address in rdi (= rsp)
                               ;   3. Returns the number of bytes written in rax
                               ; Execution continues here afterwards.

    ; ====================================================================
    ; STEP 3: Convert raw bytes to hex string
    ; ====================================================================
    ;
    ; Core principle of hex conversion:
    ;
    ; A byte has 8 bits, i.e. 2 "nibbles" (half-bytes) of 4 bits each.
    ; Each nibble has a value of 0–15, which corresponds exactly to one
    ; hex digit (0–9, a–f). We split each byte into its two nibbles and
    ; look up the corresponding ASCII characters in a table.
    ;
    ; Example: byte 0xB3 (decimal 179, binary 10110011)
    ;
    ;   Upper nibble:  10110011 >> 4 = 00001011 = 11 (decimal)
    ;                  hex_table[11] = 'b'
    ;
    ;   Lower nibble:  10110011 & 0x0F = 00000011 = 3 (decimal)
    ;                  hex_table[3]  = '3'
    ;
    ;   Result: "b3"
    ;
    ; Register assignments for the loop:
    ;   rsi = read pointer  (walks through raw_bytes)
    ;   rdi = write pointer (walks through hex_out)
    ;   rbx = base address of hex_table (stays constant)
    ;   ecx = loop counter  (32 → 0)
    ; --------------------------------------------------------------------
    mov rsi, rsp               ; rsi = read pointer, points to raw_bytes (rsp + 0)

    lea rdi, [rsp + 32]        ; rdi = write pointer, points to hex_out (rsp + 32)
                               ; lea = "Load Effective Address": computes the address
                               ; rsp + 32 without reading the memory at that address.
                               ; Unlike "mov rdi, [rsp+32]" (which reads the VALUE),
                               ; lea loads the ADDRESS itself.

    lea rbx, [rel hex_table]   ; rbx = address of the lookup table "0123456789abcdef"
                               ; [rel hex_table] = RIP-relative addressing.
                               ; The assembler calculates the distance between this
                               ; instruction and hex_table and encodes it as an offset.
                               ; "rel" is needed because we're in flat binary mode
                               ; (no "default rel" directive).

    mov ecx, 32                ; ecx = 32 bytes to process (loop counter)

.loop:
    ; --- Load one raw byte from the source ---
    movzx eax, byte [rsi]     ; Reads exactly 1 byte from the address in rsi.
                               ; "movzx" = Move with Zero-Extend:
                               ;   - Reads 1 byte (8 bits)
                               ;   - Extends it to 32 bits by filling the upper
                               ;     24 bits with zeros
                               ;   - Stores the result in eax
                               ; Why not just "mov al, [rsi]"? Because the upper
                               ; bits of rax would remain undefined, which could
                               ; produce wrong results with the later "and eax, 0x0F".
                               ; movzx guarantees clean upper bits.
                               ; "byte" is a size hint for NASM (read 1 byte).

    ; --- Extract upper nibble (bits 7–4) ---
    mov edx, eax              ; Copy the byte into edx, because we still need eax
                               ; for the lower nibble and are about to shift destructively.

    shr edx, 4                ; Shift Right by 4 positions:
                               ; Moves all bits 4 places to the right.
                               ; The upper 4 bits land at positions 3–0,
                               ; the lower 4 bits fall off (are discarded).
                               ; Example: 0xB3 = 10110011
                               ;   shr 4 → 00001011 = 0x0B = 11
                               ; Result: a value 0–15 = index into hex_table.

    mov dl, [rbx + rdx]       ; Look up in the table:
                               ; rbx = base address of hex_table ("0123456789abcdef")
                               ; rdx = index (0–15)
                               ; rbx + rdx = address of the hex character
                               ; dl = the byte read (lower byte of rdx)
                               ; Example: rbx + 11 → hex_table[11] = 'b' (ASCII 0x62)

    mov [rdi], dl              ; Write the hex character to the current write position
                               ; in the output buffer on the stack.

    inc rdi                    ; Advance write pointer by 1 byte (next position).
                               ; inc = increment = add 1. Shorter than "add rdi, 1".

    ; --- Extract lower nibble (bits 3–0) ---
    and eax, 0x0F              ; Bitwise AND with 0x0F = 00001111:
                               ; Clears the upper 4 bits, keeps the lower 4.
                               ; Example: 0xB3 = 10110011
                               ;   and 0x0F → 00000011 = 0x03 = 3
                               ; Result: index 0–15 for hex_table.

    mov al, [rbx + rax]       ; hex_table[3] = '3' (ASCII 0x33)
                               ; al = lower byte of rax (the result character)

    mov [rdi], al              ; Write hex character to the output buffer.
    inc rdi                    ; Advance write pointer.

    ; --- Loop control ---
    inc rsi                    ; Advance read pointer to the next raw byte.

    dec ecx                    ; Decrement loop counter by 1.
                               ; dec = decrement = subtract 1.
                               ; Automatically sets the Zero Flag (ZF) in RFLAGS
                               ; when the result is 0.

    jnz .loop                  ; "Jump if Not Zero": jump back to .loop as long
                               ; as ZF = 0 (i.e. ecx != 0).
                               ; After 32 iterations, ecx = 0, ZF = 1, and the
                               ; jump is NOT taken → falls through to below.
                               ; The dot before ".loop" makes it a local label
                               ; (visible only within the enclosing global label).

    ; ====================================================================
    ; STEP 4: Append newline and write the result to stdout
    ; ====================================================================
    mov byte [rdi], 10         ; ASCII 10 = Line Feed ('\n'). After the loop, rdi
                               ; points to rsp + 96 (position 64 in the hex_out buffer).
                               ; "byte" tells NASM we only want to write 1 byte
                               ; (needed because [rdi] alone doesn't determine the size).

    ; Syscall: write(fd, buf, count)
    ;   - Writes count bytes from buf to the file descriptor fd
    ;   - fd 1 = stdout = standard output (the terminal)
    mov eax, 1                 ; Syscall number 1 = write
    mov edi, 1                 ; 1st arg: fd = 1 (stdout)
    lea rsi, [rsp + 32]        ; 2nd arg: pointer to hex_out (rsp + 32)
    mov edx, 65                ; 3rd arg: 65 bytes (64 hex characters + 1 newline)
    syscall                    ; Kernel writes the string to the terminal.
                               ; Returns in rax: number of bytes written (or error).

    ; ====================================================================
    ; STEP 5: Exit the program cleanly
    ; ====================================================================
    ; Without this syscall, the CPU would simply interpret the next bytes
    ; in memory as instructions (here: hex_table = "0123456789abcdef").
    ; Since that's not valid code → segmentation fault or undefined behavior.
    ; exit() returns control to the kernel, which cleans up the process
    ; (frees memory, closes file descriptors, etc.).
    ;
    ; Syscall: exit(status)
    ;   - Terminates the process with the given exit code
    ;   - Exit code 0 = success (convention)
    ;   - This syscall NEVER returns
    mov eax, 60                ; Syscall number 60 = exit
    xor edi, edi               ; 1st arg: exit code = 0 (xor edi,edi → edi = 0)
    syscall                    ; Process is terminated. Everything after is unreachable.


; ****************************************************************************
; *                         CONSTANT DATA                                    *
; ****************************************************************************
;
; These 16 bytes are the only data in the entire file.
; They form the hex lookup table: index 0 → '0', index 10 → 'a', etc.
;
; Since we're in flat binary mode, these bytes sit directly after the last
; syscall opcode in the file — no section overhead, no padding.
; ****************************************************************************

hex_table: db "0123456789abcdef"

; file_size calculates the total file size at assembly time:
; $ = current position (end of file), ehdr = start of file.
; We use this value above in the program header (p_filesz / p_memsz),
; so the kernel knows how many bytes to load.
file_size equ $ - ehdr
