; ============================================================================
; macOS x86_64 — Cryptographic Random Hex Generator
; ============================================================================
;
; Generates 32 random bytes and prints them as a 64-character hex string.
; Equivalent to: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
;
; Build:
;   nasm -f macho64 macos_x86_64.asm -o macos_x86_64.o
;   ld -e _start -o random macos_x86_64.o -lSystem -syslibroot $(xcrun --show-sdk-path)
;
; Key differences from Linux (see main.asm for the most detailed comments):
;   - Executable format: Mach-O instead of ELF
;   - Syscall numbers: prefixed with 0x2000000 (BSD syscall class on macOS)
;     Linux uses raw numbers (e.g. write = 1), macOS uses 0x2000000 + number
;   - Random source: getentropy (syscall 244) instead of getrandom (318)
;   - Linking: requires -lSystem on modern macOS (even for raw syscalls)
;
; Register convention is the same as Linux (System V AMD64 ABI):
;   rax = syscall number, rdi/rsi/rdx/r10/r8/r9 = args, rax = return value
;
; ============================================================================

default rel
bits 64

; ---------------------------------------------------------------------------
; macOS syscall numbers
; On macOS x86_64, syscall numbers are encoded as: 0x2000000 + unix_number
; The 0x2000000 prefix identifies the BSD/Unix syscall class (class 2).
; Other classes: Mach traps (class 1), machine-dependent (class 3).
; ---------------------------------------------------------------------------
SYS_EXIT        equ 0x2000001  ; exit(int status)
SYS_WRITE       equ 0x2000004  ; write(int fd, void *buf, size_t count)
SYS_GETENTROPY  equ 0x20000F4  ; getentropy(void *buf, size_t buflen)
                               ; 0x20000F4 = 0x2000000 + 244
                               ; getentropy provides cryptographically secure
                               ; random bytes, same entropy source as /dev/urandom.
                               ; Available since macOS 10.12 (Sierra, 2016).
                               ; Limited to 256 bytes per call.

section .data
    hex_table: db "0123456789abcdef"

section .text
    global _start

; ---------------------------------------------------------------------------
; Stack layout (same as Linux version):
;   rsp +  0 .. +31 = raw_bytes  (32 bytes of random data)
;   rsp + 32 .. +96 = hex_out    (64 hex chars + 1 newline)
; ---------------------------------------------------------------------------
_start:
    sub rsp, 97                ; Reserve 97 bytes on the stack

    ; --- Get 32 random bytes from the kernel ---
    mov eax, SYS_GETENTROPY   ; Note: upper 32 bits of rax are NOT auto-zeroed
                               ; here because 0x20000F4 > 32 bits? No — 0x20000F4
                               ; is 0x020000F4 which fits in 32 bits (536871156).
                               ; But to be safe, we use eax since the value fits.
                               ; Actually, 0x20000F4 = 33554676 which is < 2^32, so
                               ; writing to eax works correctly (zeroes upper 32 bits).
    mov rdi, rsp               ; 1st arg: buffer address
    mov esi, 32                ; 2nd arg: 32 bytes
    syscall                    ; Returns 0 on success, -1 on error

    ; --- Convert bytes to hex (identical to Linux version) ---
    mov rsi, rsp               ; Read pointer → raw_bytes
    lea rdi, [rsp + 32]        ; Write pointer → hex_out
    lea rbx, [rel hex_table]   ; Lookup table base address
    mov ecx, 32                ; Loop counter

.loop:
    movzx eax, byte [rsi]     ; Load one raw byte, zero-extended to 32 bits

    mov edx, eax              ; Copy for upper nibble extraction
    shr edx, 4                ; Shift right 4 → upper nibble (0–15)
    mov dl, [rbx + rdx]       ; Look up hex character
    mov [rdi], dl              ; Write to output buffer
    inc rdi

    and eax, 0x0F              ; Mask lower nibble (0–15)
    mov al, [rbx + rax]       ; Look up hex character
    mov [rdi], al              ; Write to output buffer
    inc rdi

    inc rsi                    ; Next input byte
    dec ecx
    jnz .loop                  ; Repeat for all 32 bytes

    mov byte [rdi], 10         ; Append newline (ASCII 10)

    ; --- Write hex string to stdout ---
    mov eax, SYS_WRITE
    mov edi, 1                 ; fd = stdout
    lea rsi, [rsp + 32]        ; Buffer = hex_out
    mov edx, 65                ; 64 hex chars + 1 newline
    syscall

    ; --- Exit ---
    mov eax, SYS_EXIT
    xor edi, edi               ; Exit code 0
    syscall
