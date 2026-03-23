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
; Usage: ./random [N]
;   N = number of random bytes to generate (default: 32)
;   Output: 2*N hex characters + newline
;
; At _start, the kernel has placed the following on the stack:
;
;   [rsp]      = argc        (number of arguments, including program name)
;   [rsp+8]    = argv[0]     (pointer to program name string, e.g. "./random")
;   [rsp+16]   = argv[1]     (pointer to first argument string, if argc >= 2)
;   [rsp+24]   = argv[2]     (or NULL terminator if argc == 2)
;   ...
;
; After parsing the argument and allocating the buffer, the stack layout is:
;
;   rsp + 0         .. rsp + N-1        = raw_bytes  (N random bytes)
;   rsp + N         .. rsp + 3*N-1      = hex_out    (2*N hex characters)
;   rsp + 3*N                           = newline    (1 byte)
;
; r12d holds N throughout the program (callee-saved, survives syscalls).
;
; ****************************************************************************

_start:
    ; ====================================================================
    ; STEP 1: Parse command line argument (or use default)
    ; ====================================================================
    ;
    ; We read argc from [rsp]. If argc >= 2, argv[1] exists and we parse
    ; it as a decimal integer. Otherwise we default to 32 bytes.
    ;
    ; The parsing loop implements a simple atoi: for each ASCII digit
    ; character ('0'–'9'), multiply the accumulator by 10 and add the
    ; digit value. Stop at the first non-digit character or end of string.
    ; --------------------------------------------------------------------
    mov r12d, 32               ; r12d = default byte count (32)

    cmp qword [rsp], 2        ; argc >= 2? (argc is a 64-bit value on the stack)
    jl .alloc                  ; No argument provided → skip parsing, use default

    mov rsi, [rsp+16]         ; rsi = pointer to argv[1] (the argument string)
    xor eax, eax              ; eax = accumulator for parsed number, starts at 0

.parse:
    movzx ecx, byte [rsi]    ; Load next ASCII character from the string
    sub ecx, '0'              ; Convert ASCII to digit: '0'→0, '1'→1, ..., '9'→9
                               ; If the character was below '0', ecx underflows
                               ; to a large number (unsigned), caught by cmp below.
    cmp ecx, 9                ; Is it a valid digit (0–9)?
    ja .parse_done             ; "Jump if Above" (unsigned): if ecx > 9, it's not
                               ; a digit → stop parsing. This also catches negative
                               ; values from the sub (they wrap to large unsigned).
    imul eax, eax, 10         ; accumulator *= 10 (shift decimal place left)
                               ; "imul" with 3 operands: dest = src1 * src2
    add eax, ecx              ; accumulator += current digit
    inc rsi                    ; Advance to next character
    jmp .parse                 ; Continue parsing loop

.parse_done:
    test eax, eax             ; Did we parse a valid number? (eax == 0 means no
                               ; digits were found, e.g. "./random abc")
    cmovnz r12d, eax          ; If non-zero, use parsed value; otherwise keep default.
                               ; "cmovnz" = Conditional Move if Not Zero. Avoids a
                               ; branch: r12d = (eax != 0) ? eax : r12d.

    ; ====================================================================
    ; STEP 2: Allocate stack space for buffers
    ; ====================================================================
    ;
    ; We need: N bytes (raw) + 2*N bytes (hex) + 1 byte (newline) = 3*N + 1
    ; Round up to 16-byte alignment (required by ABI for stack operations).
    ; --------------------------------------------------------------------
.alloc:
    lea eax, [r12 + r12*2 + 1] ; eax = 3*N + 1. LEA can compute this in one
                               ; instruction using base + index*scale + displacement.
                               ; r12 is the base, r12*2 is the index with scale 2,
                               ; +1 is the displacement. Total: r12 + 2*r12 + 1 = 3*r12 + 1.
    add eax, 15               ; Round up to next multiple of 16:
    and eax, -16               ; -16 in binary is ...11110000, so AND clears the
                               ; lower 4 bits, rounding down to the nearest 16.
                               ; Combined with the +15 above, this rounds UP.
    sub rsp, rax               ; Allocate the aligned buffer space on the stack.

    ; ====================================================================
    ; STEP 3: Get N cryptographically secure random bytes from the kernel
    ; ====================================================================
    ;
    ; Linux syscall convention for x86_64:
    ;   rax = syscall number, rdi/rsi/rdx = arguments, rax = return value
    ;
    ; getrandom() may return fewer bytes than requested (partial read),
    ; so we loop until all N bytes have been written.
    ; --------------------------------------------------------------------
    mov r13d, r12d             ; r13d = remaining bytes to generate
    mov r14, rsp               ; r14 = current write position in raw_bytes buffer

.random_loop:
    mov eax, 318               ; Syscall 318 = getrandom
    mov rdi, r14               ; 1st arg: buffer = current write position
    mov esi, r13d              ; 2nd arg: count = remaining bytes
    xor edx, edx              ; 3rd arg: flags = 0 (non-blocking, urandom pool)
    syscall                    ; Returns number of bytes actually written in rax
    add r14, rax               ; Advance write position by bytes written
    sub r13d, eax              ; Decrease remaining count
    jnz .random_loop           ; If remaining > 0, request more bytes

    ; ====================================================================
    ; STEP 4: Convert raw bytes to hex string
    ; ====================================================================
    ;
    ; Each byte is split into two 4-bit nibbles and converted to a hex
    ; character via the lookup table. See earlier comments in this file
    ; for a detailed explanation of the nibble extraction technique.
    ;
    ; Register assignments:
    ;   rsi = read pointer  (raw_bytes at rsp + 0)
    ;   rdi = write pointer (hex_out at rsp + N)
    ;   rbx = base address of hex_table
    ;   ecx = loop counter (N → 0)
    ; --------------------------------------------------------------------
    mov rsi, rsp               ; Read pointer → start of raw_bytes
    lea rdi, [rsp + r12]      ; Write pointer → hex_out starts at rsp + N
    lea rbx, [rel hex_table]   ; Lookup table address (RIP-relative)
    mov ecx, r12d              ; Loop counter = N

.loop:
    movzx eax, byte [rsi]     ; Load one raw byte, zero-extended to 32 bits

    mov edx, eax              ; Copy for upper nibble extraction
    shr edx, 4                ; Upper nibble: shift right 4 → index 0–15
    mov dl, [rbx + rdx]       ; Look up hex character
    mov [rdi], dl              ; Write to output buffer
    inc rdi

    and eax, 0x0F              ; Lower nibble: mask to index 0–15
    mov al, [rbx + rax]       ; Look up hex character
    mov [rdi], al              ; Write to output buffer
    inc rdi

    inc rsi                    ; Next input byte
    dec ecx
    jnz .loop                  ; Repeat for all N bytes

    ; ====================================================================
    ; STEP 5: Append newline and write the result to stdout
    ; ====================================================================
    mov byte [rdi], 10         ; Append newline (ASCII 10 = '\n')

    mov eax, 1                 ; Syscall 1 = write
    mov edi, 1                 ; 1st arg: fd = 1 (stdout)
    lea rsi, [rsp + r12]      ; 2nd arg: buffer = hex_out (at rsp + N)
    lea edx, [r12 + r12 + 1]  ; 3rd arg: count = 2*N + 1 (hex chars + newline)
    syscall

    ; ====================================================================
    ; STEP 6: Exit the program cleanly
    ; ====================================================================
    mov eax, 60                ; Syscall 60 = exit
    xor edi, edi               ; Exit code 0
    syscall


; ****************************************************************************
; *                         CONSTANT DATA                                    *
; ****************************************************************************

hex_table: db "0123456789abcdef"

file_size equ $ - ehdr
