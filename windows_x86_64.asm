; ============================================================================
; Windows x86_64 — Cryptographic Random Hex Generator
; ============================================================================
;
; Generates 32 random bytes and prints them as a 64-character hex string.
; Equivalent to: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
;
; Build:
;   nasm -f win64 windows_x86_64.asm -o windows_x86_64.obj
;   link /nodefaultlib /subsystem:console /entry:_start /out:random.exe ^
;        windows_x86_64.obj kernel32.lib bcrypt.lib
;
; Key differences from Linux/macOS (see main.asm for the most detailed comments):
;
;   - Executable format: PE (Portable Executable) instead of ELF or Mach-O
;
;   - No raw syscalls: Windows syscall numbers change between OS versions
;     and are NOT a stable API. All programs MUST call DLL functions instead.
;     This is fundamentally different from Linux/macOS where syscall numbers
;     are part of the stable kernel ABI.
;
;   - Calling convention: Windows x64 uses a DIFFERENT convention than Linux:
;       Windows: rcx, rdx, r8, r9 (then stack) — "Microsoft x64"
;       Linux:   rdi, rsi, rdx, rcx, r8, r9    — "System V AMD64 ABI"
;     Also, Windows requires 32 bytes of "shadow space" on the stack before
;     every CALL, even if the function has fewer than 4 arguments.
;
;   - Random source: BCryptGenRandom from bcrypt.dll (Windows CNG API)
;     instead of getrandom/getentropy syscalls.
;
;   - Console output: WriteFile from kernel32.dll via GetStdHandle,
;     instead of the write syscall.
;
;   - Linking: requires import libraries (kernel32.lib, bcrypt.lib) that
;     tell the linker how to find functions in the corresponding DLLs.
;
; ============================================================================

default rel
bits 64

; ---------------------------------------------------------------------------
; External function declarations (imported from Windows DLLs at runtime)
;
; "extern" tells NASM these symbols are defined elsewhere. The linker resolves
; them from the import libraries (kernel32.lib, bcrypt.lib), which point to
; the actual DLL functions loaded at runtime.
; ---------------------------------------------------------------------------

; kernel32.dll — core Windows API
extern GetStdHandle            ; HANDLE GetStdHandle(DWORD nStdHandle)
                               ; Returns a handle to stdout/stdin/stderr.
                               ; STD_OUTPUT_HANDLE = -11.

extern WriteFile               ; BOOL WriteFile(HANDLE, LPCVOID, DWORD,
                               ;                LPDWORD, LPOVERLAPPED)
                               ; Writes data to a file or pipe. Works with
                               ; both console output and piped redirection
                               ; (unlike WriteConsoleA which only works for consoles).

extern ExitProcess             ; void ExitProcess(UINT uExitCode)
                               ; Terminates the process. On Windows, you can't
                               ; just "return" from the entry point — you must
                               ; explicitly call ExitProcess.

; bcrypt.dll — Windows Cryptography: Next Generation (CNG)
extern BCryptGenRandom         ; NTSTATUS BCryptGenRandom(
                               ;   BCRYPT_ALG_HANDLE hAlgorithm,  // NULL with flag 2
                               ;   PUCHAR pbBuffer,               // output buffer
                               ;   ULONG cbBuffer,                // number of bytes
                               ;   ULONG dwFlags                  // flags
                               ; )
                               ; With BCRYPT_USE_SYSTEM_PREFERRED_RNG (flag 2),
                               ; hAlgorithm can be NULL — the system picks the
                               ; best available random number generator.
                               ; Returns 0 (STATUS_SUCCESS) on success.

; ---------------------------------------------------------------------------
; Constants
; ---------------------------------------------------------------------------
STD_OUTPUT_HANDLE              equ -11
BCRYPT_USE_SYSTEM_PREFERRED_RNG equ 2

; ---------------------------------------------------------------------------
; Data sections
; ---------------------------------------------------------------------------
section .data
    hex_table: db "0123456789abcdef"

section .bss
    raw_bytes: resb 32         ; 32 random bytes from BCryptGenRandom
    hex_out:   resb 65         ; 64 hex characters + 1 newline
    written:   resd 1          ; DWORD for WriteFile's "bytes written" output

; ---------------------------------------------------------------------------
; Code
; ---------------------------------------------------------------------------
section .text
    global _start

; ===========================================================================
; Windows x64 Calling Convention ("Microsoft x64"):
;
;   Arguments:    rcx, rdx, r8, r9 (first 4), then stack (5th, 6th, ...)
;   Return value: rax
;   Caller-saved: rax, rcx, rdx, r8, r9, r10, r11 (volatile)
;   Callee-saved: rbx, rsi, rdi, rbp, r12–r15 (non-volatile)
;
;   Shadow space: The caller MUST reserve 32 bytes on the stack before every
;   CALL, even if the function has fewer than 4 arguments. This "shadow space"
;   (also called "home space") is used by the callee to spill register args
;   if needed. Forgetting this causes crashes.
;
;   Stack alignment: RSP must be 16-byte aligned before the CALL instruction.
;   At process entry, RSP is 16-byte aligned.
;
; Stack layout after "sub rsp, 48":
;
;   RSP + 0..31  = shadow space (32 bytes, used by callees)
;   RSP + 32..39 = 5th argument slot for WriteFile (lpOverlapped)
;   RSP + 40..47 = padding for 16-byte alignment
;
; ===========================================================================
_start:
    sub rsp, 48                ; Reserve stack space: 32 shadow + 8 arg + 8 pad.
                               ; 48 % 16 = 0, so RSP stays 16-byte aligned.

    ; =====================================================================
    ; STEP 1: Generate 32 cryptographically secure random bytes
    ; =====================================================================
    ; BCryptGenRandom(NULL, raw_bytes, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    ;
    ; With flag BCRYPT_USE_SYSTEM_PREFERRED_RNG (2), we can pass NULL as the
    ; algorithm handle — Windows picks the best available CSPRNG.
    ; This is the recommended way to generate random bytes on Windows.
    ; -----------------------------------------------------------------
    xor ecx, ecx              ; 1st arg: hAlgorithm = NULL
    lea rdx, [rel raw_bytes]   ; 2nd arg: output buffer
    mov r8d, 32                ; 3rd arg: 32 bytes
    mov r9d, BCRYPT_USE_SYSTEM_PREFERRED_RNG  ; 4th arg: flags = 2
    call BCryptGenRandom       ; Returns STATUS_SUCCESS (0) on success

    ; =====================================================================
    ; STEP 2: Convert raw bytes to hex string
    ; =====================================================================
    ; Same algorithm as Linux/macOS. Note: on Windows, rsi, rdi, and rbx
    ; are callee-saved (non-volatile), so API calls preserve them.
    ; We use them freely between calls.
    ; -----------------------------------------------------------------
    lea rsi, [rel raw_bytes]   ; Read pointer
    lea rdi, [rel hex_out]     ; Write pointer
    lea rbx, [rel hex_table]   ; Lookup table
    mov ecx, 32                ; Counter

.loop:
    movzx eax, byte [rsi]     ; Load one byte, zero-extended

    mov edx, eax              ; Copy for upper nibble
    shr edx, 4                ; Upper nibble → index 0–15
    mov dl, [rbx + rdx]       ; Look up hex character
    mov [rdi], dl              ; Write to output
    inc rdi

    and eax, 0x0F              ; Lower nibble → index 0–15
    mov al, [rbx + rax]       ; Look up hex character
    mov [rdi], al              ; Write to output
    inc rdi

    inc rsi                    ; Next input byte
    dec ecx
    jnz .loop

    mov byte [rdi], 10         ; Append newline (ASCII 10)

    ; =====================================================================
    ; STEP 3: Get stdout handle and write hex string
    ; =====================================================================
    ; Windows doesn't have file descriptor numbers like Linux/macOS (where
    ; stdout = fd 1). Instead, you must ask the kernel for a HANDLE to
    ; stdout using GetStdHandle.
    ; -----------------------------------------------------------------
    mov ecx, STD_OUTPUT_HANDLE ; 1st arg: nStdHandle = -11 (stdout)
    call GetStdHandle          ; Returns HANDLE in rax

    ; WriteFile(hFile, lpBuffer, nBytesToWrite, lpBytesWritten, lpOverlapped)
    mov rcx, rax               ; 1st arg: file handle (from GetStdHandle)
    lea rdx, [rel hex_out]     ; 2nd arg: buffer to write
    mov r8d, 65                ; 3rd arg: 65 bytes (64 hex + newline)
    lea r9, [rel written]      ; 4th arg: pointer to receive bytes written count
    mov qword [rsp+32], 0     ; 5th arg: lpOverlapped = NULL (on stack, after
                               ; shadow space). 5th+ args go on the stack at
                               ; [rsp+32], [rsp+40], etc.
    call WriteFile

    ; =====================================================================
    ; STEP 4: Exit process
    ; =====================================================================
    ; On Windows, simply "returning" from the entry point doesn't cleanly
    ; exit — you must call ExitProcess to properly terminate.
    ; -----------------------------------------------------------------
    xor ecx, ecx              ; 1st arg: exit code = 0
    call ExitProcess           ; Terminates the process (never returns)
