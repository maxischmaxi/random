# random

A 245-byte x86_64 Linux binary that generates 32 cryptographically secure random bytes and prints them as a hex string. Equivalent to `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` — but ~40x faster and without any runtime dependencies.

## Install

```bash
curl -fsSL https://github.com/maxischmaxi/random/releases/latest/download/random -o ~/.local/bin/random && chmod +x ~/.local/bin/random
```

> Make sure `~/.local/bin` is in your `PATH`.

## Build from source

Requires [NASM](https://nasm.us/) (`sudo pacman -S nasm` / `sudo apt install nasm`).

```bash
make        # builds the 'random' binary
./random    # prints 64 hex characters
```

## How it works

The binary is a hand-crafted ELF executable — no linker, no libc, no runtime. It uses two Linux syscalls directly:

1. **`getrandom`** (syscall 318) — fetches 32 cryptographically secure bytes from the kernel
2. **`write`** (syscall 1) — outputs the bytes as a 64-character hex string to stdout

Each byte is split into two 4-bit nibbles and converted to hex via a 16-byte lookup table. See `main.asm` for detailed comments on every instruction.

## Files

| File       | Description                                      |
|------------|--------------------------------------------------|
| `main.asm` | x86_64 assembly source with hand-crafted ELF header |
| `main.js`  | Node.js equivalent for performance comparison    |
| `Makefile` | Build configuration                              |
