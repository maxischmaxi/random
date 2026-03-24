# random

A tiny x86_64 / ARM64 binary that generates 32 cryptographically secure random bytes and prints them as a hex string. Equivalent to `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` — but ~40x faster and without any runtime dependencies.

Supports Linux, macOS (Intel & Apple Silicon), and Windows.

## Install

**Linux / macOS (auto-detects OS and architecture):**

```bash
curl -fsSL "https://github.com/maxischmaxi/random/releases/latest/download/random-$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')-$(uname -m)" -o ~/.local/bin/random && chmod +x ~/.local/bin/random
```

> Make sure `~/.local/bin` is in your `PATH`.

**Windows (PowerShell):**

```powershell
New-Item -Force -ItemType Directory "$env:USERPROFILE\.local\bin" | Out-Null; Invoke-WebRequest -Uri "https://github.com/maxischmaxi/random/releases/latest/download/random-windows-x86_64.exe" -OutFile "$env:USERPROFILE\.local\bin\random.exe"
```

> Add `%USERPROFILE%\.local\bin` to your `PATH` environment variable.

## Usage

```bash
random        # 32 bytes → 64 hex characters (default)
random 8      # 8 bytes → 16 hex characters
random 64     # 64 bytes → 128 hex characters
random 256    # 256 bytes → 512 hex characters
```

The optional argument specifies the number of random bytes to generate. Each byte produces 2 hex characters. If omitted, it defaults to 32 bytes (256 bits).

## Build from source

Requires [NASM](https://nasm.us/) (`sudo pacman -S nasm` / `sudo apt install nasm` / `brew install nasm`).

```bash
make linux        # Linux x86_64
make macos-intel  # macOS x86_64 (Intel)
make macos-arm    # macOS ARM64 (Apple Silicon)
make windows      # Windows x86_64 (requires MSVC link.exe)
```

## How it works

Each platform uses raw syscalls (Linux/macOS) or native OS APIs (Windows) to generate 32 cryptographically secure random bytes. Each byte is split into two 4-bit nibbles and converted to hex via a 16-byte lookup table.

| Platform          | Random source         | Executable format | Binary size |
|-------------------|-----------------------|-------------------|-------------|
| Linux x86_64      | `getrandom` syscall   | ELF (hand-crafted)| 310 bytes   |
| macOS x86_64      | `getentropy` syscall  | Mach-O            | 8.4 KB      |
| macOS ARM64       | `getentropy` syscall  | Mach-O            | 32.8 KB     |
| Windows x86_64    | `BCryptGenRandom` API | PE                | 3 KB        |

The Linux version uses a hand-crafted ELF header (no linker needed), resulting in a 310-byte binary. See `linux_x86_64.asm` for detailed comments on every instruction.

## Performance

Benchmark: generating 32 random bytes as hex, averaged over 1000 (assembly) / 100 (Node.js) runs on Linux x86_64.

|                  | `random`        | Bun              | Node.js          |
|------------------|-----------------|------------------|------------------|
| **Time per run** | ~0.3 ms         | ~9.7 ms          | ~12.9 ms         |
| **Speedup**      | **~45x faster** | ~1.3x faster     | 1x               |
| **Binary size**  | 310 bytes       | ~100 MB runtime  | ~124 MB runtime  |
| **Dependencies** | none            | Bun              | Node.js          |

All three use the same kernel entropy source (`getrandom`). The difference comes from JS runtime startup overhead (V8/JavaScriptCore, JIT compiler, garbage collector).

Commands used:
```bash
./random                                                                  # assembly
bun -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # bun 1.3.9
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"  # node v24.11.0
```

## Files

| File                  | Description                                       |
|-----------------------|---------------------------------------------------|
| `linux_x86_64.asm`    | Linux x86_64 — hand-crafted ELF, detailed comments |
| `macos_x86_64.asm`    | macOS Intel — NASM + Mach-O                       |
| `macos_arm64.s`       | macOS Apple Silicon — ARM64 assembly               |
| `windows_x86_64.asm`  | Windows — NASM + PE, uses Win32 API                |
| `main.js`             | Node.js equivalent for performance comparison      |
| `Makefile`            | Build configuration for all platforms              |
