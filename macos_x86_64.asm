; ============================================================================
; macOS x86_64 — Cryptographic Random Hex Generator
; ============================================================================
;
; Usage: ./random [N]    (default: 32 bytes)
; Output: 2*N hex characters + newline
;
; Build:
;   nasm -f macho64 macos_x86_64.asm -o macos_x86_64.o
;   ld -arch x86_64 -platform_version macos 13.0 13.0 -e _start -o random \
;      macos_x86_64.o -lSystem -syslibroot $(xcrun --show-sdk-path)
;
; Key differences from Linux (see linux_x86_64.asm for the most detailed comments):
;   - Syscall numbers prefixed with 0x2000000 (BSD syscall class on macOS)
;   - Random source: getentropy (syscall 244, max 256 bytes per call)
;   - Linking requires -lSystem on modern macOS
;
; ============================================================================

default rel
bits 64

SYS_EXIT        equ 0x2000001
SYS_WRITE       equ 0x2000004
SYS_GETENTROPY  equ 0x20000F4  ; getentropy(buf, buflen) — max 256 bytes per call

section .data
    hex_table: db "0123456789abcdef"

section .text
    global _start

_start:
    ; --- Parse command line argument (default: 32) ---
    ; Stack at entry: [rsp]=argc, [rsp+8]=argv[0], [rsp+16]=argv[1]
    mov r12d, 32               ; Default byte count
    cmp qword [rsp], 2
    jl .alloc
    mov rsi, [rsp+16]         ; argv[1]
    xor eax, eax
.parse:
    movzx ecx, byte [rsi]
    sub ecx, '0'
    cmp ecx, 9
    ja .parse_done
    imul eax, eax, 10
    add eax, ecx
    inc rsi
    jmp .parse
.parse_done:
    test eax, eax
    cmovnz r12d, eax

    ; --- Allocate stack: N + 2*N + 1 bytes, 16-byte aligned ---
.alloc:
    lea eax, [r12 + r12*2 + 1]
    add eax, 15
    and eax, -16
    sub rsp, rax

    ; --- Get random bytes (loop for > 256 bytes, getentropy limit) ---
    mov r13d, r12d             ; Remaining bytes
    mov r14, rsp               ; Write position
.random_loop:
    mov r15d, 256
    cmp r13d, 256
    cmovl r15d, r13d           ; Chunk = min(remaining, 256)
    mov eax, SYS_GETENTROPY
    mov rdi, r14
    mov esi, r15d
    syscall
    add r14, r15               ; Advance by chunk size
    sub r13d, r15d
    jnz .random_loop

    ; --- Convert bytes to hex ---
    mov rsi, rsp
    lea rdi, [rsp + r12]
    lea rbx, [rel hex_table]
    mov ecx, r12d
.loop:
    movzx eax, byte [rsi]
    mov edx, eax
    shr edx, 4
    mov dl, [rbx + rdx]
    mov [rdi], dl
    inc rdi
    and eax, 0x0F
    mov al, [rbx + rax]
    mov [rdi], al
    inc rdi
    inc rsi
    dec ecx
    jnz .loop

    ; --- Write to stdout ---
    mov byte [rdi], 10
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rsp + r12]
    lea edx, [r12 + r12 + 1]
    syscall

    ; --- Exit ---
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
