# Symbol of Hope — Write Up (215 solves)

## 0) What this challenge is trying to “hide”

This challenge hides the flag in two layers:

1. **UPX packing**: the provided binary is compressed/packed, so static tools (strings/disassembly) show very little useful code.
2. **Obfuscated checker logic**: after unpacking, the program doesn’t compare your input to the flag directly. Instead it:
   - takes your 42‑character input,
   - runs it through **4200 tiny transformations** (functions `f_0` … `f_4199`),
   - then compares the transformed bytes to a hardcoded 42‑byte array called `expected`.

The “challenge” is to reverse those transformations to recover the original input that would produce `expected` — i.e., the flag.

The clue in the description (“symbol of hope”) points toward **symbolic / automated reasoning** instead of manually reversing thousands of operations.

---

## 1) Files

Only one file is provided:

- `checker` — the flag checker binary.

---

## 2) Quick recon (first commands you should run)

```bash
file checker
strings -n 4 checker | head
```

You should notice:

- It’s an `ELF 64-bit` Linux executable.
- `strings` includes `UPX!` → very strong hint it’s **UPX packed**.

UPX is a common packer in CTFs: it compresses the program and adds a small “unpacker stub” that restores the original code at runtime.

---

## 3) Unpack the binary (remove UPX)

### Option A: If you already have UPX installed

```bash
upx -d -o checker.unpacked checker
```

### Option B: If you don’t have UPX installed

Download a UPX release from GitHub, extract it, and run its `upx` binary. (That’s what was done in this solve.)

After unpacking, confirm:

```bash
file checker.unpacked
```

In this challenge, `checker.unpacked` becomes **not stripped**, meaning it keeps symbols like `main`, `expected`, and `f_0`… which makes reversing much easier.

---

## 4) Understand what the program does (high level)

Disassemble `main`:

```bash
objdump -d -Mintel --disassemble=main checker.unpacked
```

What you’ll see (in plain English):

1. Read a line from stdin (`fgets`).
2. Remove newline using `strcspn`.
3. Require the input length to be exactly **42**.
4. Copy those 42 bytes into a local buffer.
5. Call `f_0(buffer)` which starts a long chain.

So your input must be exactly 42 characters (not counting the newline).

---

## 5) Find the final check and the target bytes

Look at the last function in the chain:

```bash
objdump -d -Mintel --disassemble=f_4200 checker.unpacked
```

`f_4200` does:

- `memcmp(buf, expected, 0x2a)` (0x2a = 42)
- prints `Yes` if equal, otherwise `No`.

The bytes named `expected` live in `.rodata`:

```bash
objdump -s -j .rodata checker.unpacked | head -n 80
```

So the program is basically:

> “Transform your 42 bytes → compare against a fixed 42‑byte array.”

---

## 6) What are `f_0` … `f_4199` doing?

Use `nm` to see there are thousands of functions:

```bash
nm -n checker.unpacked | rg '^.* f_[0-9]+$' | head
```

If you disassemble a few, you’ll notice a pattern:

- each `f_i` modifies **one byte** at some index like `buf[0x13]` or `buf[0x22]`
- the modification is a simple invertible operation, e.g.:
  - XOR with a constant
  - NOT (`~x`)
  - NEG (`-x`)
  - add/sub a constant
  - rotate bits (ROL/ROR)
  - swap high/low nibbles (like `0xAB -> 0xBA`)
  - multiply by a constant (mod 256)
- then it calls the next function (`call f_{i+1}`)

This is “death by a thousand cuts”: nothing is hard individually, but manually reversing 4200 steps is painful.

---

## 7) Key observation (the big shortcut)

Even though there are 4200 steps, **each step only touches one byte** and uses an invertible 8‑bit operation.

That means:

- For each function `f_i`, the transformation on that one byte is a **permutation** of values 0..255.
- A permutation always has an inverse.

So we can solve it by working backwards:

1. Start from the 42 bytes in `expected` (this is the “final transformed” buffer).
2. For `i = 4199 ... 0`:
   - find which index `f_i` modifies (e.g., byte 0x13)
   - apply the inverse transformation for `f_i` to that one byte
3. After all inverses, the buffer becomes the original input → the flag.

---

## 8) Automated solution (step-by-step)

This repo includes a solver script:

- `solve.py`

What it does:

1. Opens `checker.unpacked` as an ELF and reads:
   - `.text` (code)
   - `.rodata` (contains `expected`)
   - symbols (`f_0`…`f_4200`, `rol8`, `ror8`, `expected`)
2. Disassembles each function `f_i` with Capstone.
3. For each `f_i`:
   - extracts which byte index is being modified (0..41)
   - emulates the small instruction sequence for **all 256 input byte values**
   - records the mapping `in_byte -> out_byte`
   - inverts it to get `out_byte -> in_byte`
4. Starts from `expected` and applies the inverses in reverse order.
5. Prints the recovered 42‑byte string.

Run it:

```bash
python3 solve.py
```

---

## 9) Validate the result

Take the printed flag and test it:

```bash
printf 'FLAG_HERE\n' | ./checker
```

If it prints `Yes`, you’re done.

---

## 10) Flag

The recovered flag is:

`uoftctf{5ymb0l1c_3x3cu710n_15_v3ry_u53ful}`

