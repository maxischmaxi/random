; ============================================================================
; Windows x86_64 — Cryptographic Random Hex Generator
; ============================================================================
;
; Usage: random.exe [N]    (default: 32 bytes)
; Output: 2*N hex characters + newline
;
; Build:
;   nasm -f win64 windows_x86_64.asm -o windows_x86_64.obj
;   link /nodefaultlib /subsystem:console /entry:_start /out:random.exe ^
;        windows_x86_64.obj kernel32.lib bcrypt.lib
;
; Key differences from Linux/macOS (see linux_x86_64.asm for detailed comments):
;   - No raw syscalls (Windows syscall numbers are unstable between versions)
;   - Must call DLL functions: BCryptGenRandom, GetStdHandle, WriteFile, ExitProcess
;   - Calling convention: rcx, rdx, r8, r9 (not rdi, rsi, rdx, rcx like Linux)
;   - 32 bytes "shadow space" required on the stack before every CALL
;   - Command line obtained via GetCommandLineA (no argc/argv at entry)
;
; ============================================================================

default rel
bits 64

; --- DLL imports ---
extern GetCommandLineA         ; LPSTR GetCommandLineA(void)
extern BCryptGenRandom         ; NTSTATUS BCryptGenRandom(handle, buf, len, flags)
extern GetStdHandle            ; HANDLE GetStdHandle(DWORD nStdHandle)
extern WriteFile               ; BOOL WriteFile(handle, buf, count, &written, overlapped)
extern ExitProcess             ; void ExitProcess(UINT exitCode)

STD_OUTPUT_HANDLE              equ -11
BCRYPT_USE_SYSTEM_PREFERRED_RNG equ 2

section .data
    hex_table: db "0123456789abcdef"

section .text
    global _start

_start:
    ; =====================================================================
    ; STEP 1: Parse command line argument (default: 32)
    ; =====================================================================
    ;
    ; On Windows, the entry point does NOT receive argc/argv on the stack.
    ; Instead, we must call GetCommandLineA to get the raw command line
    ; string (e.g. "random.exe 64"), then parse it ourselves.
    ;
    ; Windows x64 calling convention requires 32 bytes of "shadow space"
    ; reserved on the stack before every CALL, even for 0-argument functions.
    ; RSP must be 16-byte aligned before CALL.
    ; -----------------------------------------------------------------
    sub rsp, 48                ; 32 shadow + 8 for 5th arg + 8 padding (alignment)

    mov r12d, 32               ; Default byte count

    call GetCommandLineA       ; Returns pointer to command line string in rax
    mov rsi, rax               ; rsi = "random.exe 64" (or just "random.exe")

    ; Skip the program name (may be quoted: "C:\path\random.exe" 64)
    cmp byte [rsi], '"'
    jne .scan_space
    inc rsi                    ; Skip opening quote
.find_quote:
    cmp byte [rsi], 0
    je .alloc                  ; End of string → no argument
    cmp byte [rsi], '"'
    je .after_name
    inc rsi
    jmp .find_quote
.after_name:
    inc rsi                    ; Skip closing quote
    jmp .skip_ws
.scan_space:
    cmp byte [rsi], 0
    je .alloc
    cmp byte [rsi], ' '
    je .skip_ws
    inc rsi
    jmp .scan_space
.skip_ws:
    cmp byte [rsi], ' '
    jne .have_arg
    inc rsi
    jmp .skip_ws

.have_arg:
    cmp byte [rsi], 0
    je .alloc                  ; No argument after program name

    ; Parse decimal number from argument
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

    ; =====================================================================
    ; STEP 2: Allocate stack space for buffers
    ; =====================================================================
    ; Layout: [rsp+0..47] = shadow+args, [rsp+48..] = buffer
    ; Buffer: N raw + 2*N hex + 1 newline + 4 written_count = 3*N + 5
    ; -----------------------------------------------------------------
.alloc:
    lea eax, [r12 + r12*2 + 5] ; 3*N + 5 (extra 4 for written DWORD)
    add eax, 15
    and eax, -16
    sub rsp, rax
    ; rsp + 0 = buffer start (raw_bytes, hex_out, newline, written)
    ; We keep the shadow space from the first sub rsp, 48 ABOVE this buffer.
    ; But wait — we need shadow space at [rsp] for future calls.
    ; Let me restructure: put buffer below, shadow above.

    ; Actually, let's use a simpler layout:
    ; Save buffer base in r15, and before each call ensure [rsp] has shadow space.
    ; Since we already subtracted 48 + buffer_size, the total stack is large enough.
    ; The shadow space for calls is at [rsp + buffer_aligned_size].
    ; But this is tricky. Simpler: add 48 to the allocation so shadow is always at rsp.
    ; Undo and redo:
    add rsp, rax               ; Undo buffer allocation
    add rsp, 48                ; Undo shadow allocation
    ; Now RSP is back to entry value. Compute total:
    lea eax, [r12 + r12*2 + 5]
    add eax, 15
    and eax, -16
    mov r15d, eax              ; r15d = aligned buffer size
    add eax, 48                ; + shadow space + 5th arg + padding
    sub rsp, rax               ; Allocate everything at once

    ; Stack layout:
    ;   [rsp + 0..31]              = shadow space for API calls
    ;   [rsp + 32..39]             = 5th arg slot for WriteFile
    ;   [rsp + 40..47]             = padding
    ;   [rsp + 48 .. 48+N-1]      = raw_bytes
    ;   [rsp + 48+N .. 48+3*N-1]  = hex_out
    ;   [rsp + 48+3*N]            = newline
    ;   [rsp + 48+3*N+1 .. +4]   = written (DWORD)

    ; =====================================================================
    ; STEP 3: Generate random bytes
    ; =====================================================================
    xor ecx, ecx              ; 1st arg: hAlgorithm = NULL
    lea rdx, [rsp + 48]        ; 2nd arg: buffer
    mov r8d, r12d              ; 3rd arg: N bytes
    mov r9d, BCRYPT_USE_SYSTEM_PREFERRED_RNG
    call BCryptGenRandom

    ; =====================================================================
    ; STEP 4: Convert bytes to hex
    ; =====================================================================
    lea rsi, [rsp + 48]        ; Read pointer = raw_bytes
    lea rdi, [rsp + 48]
    add rdi, r12               ; Write pointer = hex_out (rsp + 48 + N)
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

    mov byte [rdi], 10         ; Newline

    ; =====================================================================
    ; STEP 5: Write to stdout
    ; =====================================================================
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle          ; Returns handle in rax

    mov rcx, rax               ; 1st arg: handle
    lea rdx, [rsp + 48]
    add rdx, r12               ; 2nd arg: buffer = hex_out
    lea r8d, [r12 + r12 + 1]  ; 3rd arg: count = 2*N + 1
    lea r9, [rsp + 40]        ; 4th arg: &written (reuse padding area at rsp+40)
    mov qword [rsp+32], 0     ; 5th arg: lpOverlapped = NULL
    call WriteFile

    ; =====================================================================
    ; STEP 6: Exit
    ; =====================================================================
    xor ecx, ecx
    call ExitProcess
