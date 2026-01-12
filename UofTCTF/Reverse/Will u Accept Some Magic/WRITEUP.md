# Will u Accept Some Magic? — Write up (117 solves)

## Goal

The challenge is a Kotlin program compiled to WebAssembly (WASM). It asks for a password, and the flag is:

`uoftctf{<password>}`

Our job is to reverse the WASM and recover the password.

---

## What this challenge is trying to “hide” (what it’s testing)

This challenge is mostly about **Kotlin/Wasm GC** and how it changes the usual reversing workflow:

- **“Where did my heap go?”**  
  Kotlin/Wasm (with the GC proposal) can store objects (Strings, arrays, class instances) in a **GC-managed heap**, not in linear memory. That means classic “scan linear memory for strings / heap structures” doesn’t work well.

- **Tooling trap**  
  Many common tools (like older `wabt` / `wasm2wat`) fail to disassemble modules using new proposals (GC types, exceptions). You need a tool that understands modern WASM features.

- **Noise / misdirection**  
  The binary contains a huge Kotlin runtime + lots of exception strings and “validation engine” names to make it look complicated. The real check is simpler than it looks.

---

## Files provided

- `program.wasm` — the actual challenge binary (WASI WebAssembly module).
- `runner.mjs` — a Node.js runner (WASI preview1). The comment says Node v22+.

---

## Step-by-step solution

### 1) Identify what you’re dealing with

```bash
ls -la
file program.wasm
```

You should see it’s a WebAssembly module.

If you try a classic disassembler like `wasm2wat` from `wabt`, it will likely fail because this module uses newer proposals (GC/exceptions).

### 2) Convert WASM → WAT using a modern tool

Use `wasm-tools` (it supports GC/exceptions well).

If you already have it installed:

```bash
wasm-tools print program.wasm > program.wat
```

If you don’t have it, you can download a prebuilt release from:
https://github.com/bytecodealliance/wasm-tools/releases

Now we have a readable text version `program.wat`.

### 3) Find the entrypoint

Search exports:

```bash
rg -n "\\(export" program.wat
```

In this challenge, you’ll see only:

- `memory`
- `_initialize`

That means `_initialize` is the “main” function that runs when the module starts under WASI.

### 4) Confirm it’s a password checker

There are embedded prompt strings like `Enter password:` and outputs like `Password: CORRECT!`.

Quick ways to find them:

```bash
strings -a -n 6 program.wasm | rg -n "Enter password|CORRECT|INCORRECT"
```

Note: Kotlin strings are often UTF-16, so you may also want:

```bash
strings -el program.wasm | rg -n "Enter password|CORRECT|INCORRECT"
```

In the WAT you can also directly see these strings in a data segment near the end.

### 5) Find the required password length

Inside `_initialize` there is a length check:

```wat
i32.const 30
...
i32.ne
if
  ;; throws/prints length_check_failed
end
```

So the password length must be **30 characters**.

### 6) Understand the real trick: “Processors” per position

The code builds a list/array of “processors”:

- `ProcessorA`
- `ProcessorB`
- `ProcessorC`
- …
- `ProcessorZ`
- `ProcessorAA`
- `ProcessorBB`
- `ProcessorCC`
- `ProcessorDD`

That is exactly **30 processors** (A..Z = 26, plus AA/BB/CC/DD = 4).

Each processor is a tiny object with a vtable (virtual method table). In `program.wat` you can see these vtables as globals like:

```wat
(global (;134;) (ref 27) ... ref.func 139 ref.func 140 ref.func 141 ref.func 142 struct.new 27)  ;; ProcessorA vtable
(global (;184;) (ref 27) ... ref.func 143 ref.func 144 ref.func 145 ref.func 146 struct.new 27)  ;; ProcessorB vtable
...
```

The important part: each vtable points to a “get expected character” function (type 9 in this module), and those functions are trivial:

```wat
(func (;139;) (type 9) (param (ref null 5)) (result i32)
  i32.const 48
)
```

That `i32.const` is an ASCII/Unicode codepoint. `48` = `'0'`.

The validation later compares the input character with this constant and throws exceptions if it doesn’t match.

So despite the scary “validation engine”, the password is basically:

> For position 0 use ProcessorA’s constant, position 1 use ProcessorB’s constant, …, position 29 use ProcessorDD’s constant.

### 7) Extract the password (easy automated method)

Because the data is right in the WAT, the easiest way is to parse it and pull out:

1. The processor vtables in order (A, B, C, …, DD)
2. The function index each vtable uses for its “get” method
3. The `i32.const` inside that function

This repo includes a ready script: `extract_password.py`. Run:

```bash
python3 extract_password.py
```

If you want to understand what it does (or retype it yourself), here is the full script:

```python
import re
from pathlib import Path

wat = Path("program.wat").read_text()

# vtable globals for ProcessorA..ProcessorDD:
# ProcessorA is global 134, then ProcessorB..ProcessorDD are globals 184..212.
order_vtables = [134] + list(range(184, 213))

# Extract: global index -> "get" function index
vtable_pat = re.compile(
    r"\(global \(;(?P<g>\d+);\) \(ref 27\) ref\.null none "
    r"ref\.func 55 ref\.func (?P<get>\d+) ref\.func \d+ ref\.func \d+ ref\.func \d+ struct\.new 27\)"
)
vtable_get = {int(m.group("g")): int(m.group("get")) for m in vtable_pat.finditer(wat)}

# Extract: function index -> constant returned (the expected character codepoint)
func_pat = re.compile(
    r"\(func \(;(?P<f>\d+);\) \(type 9\) \(param \(ref null 5\)\) \(result i32\)\s*\n"
    r"\s*i32\.const (?P<c>-?\d+)\s*\n\s*\)"
)
func_const = {int(m.group("f")): int(m.group("c")) for m in func_pat.finditer(wat)}

password = "".join(chr(func_const[vtable_get[g]]) for g in order_vtables)
print(password)
```

It prints the password:

`0QGFCBREENDFDONZRC39BDS3DMEH3E`

### 8) Verify by running the program

If you have Node.js v22+ (as hinted by `runner.mjs`):

```bash
echo '0QGFCBREENDFDONZRC39BDS3DMEH3E' | node runner.mjs
```

Expected output includes:

`Password: CORRECT!`

### 9) Final flag

Wrap the password:

`uoftctf{0QGFCBREENDFDONZRC39BDS3DMEH3E}`

---

## Why this works (short explanation)

- The program pretends to do complex “validation” with many processors, exceptions, and state updates.
- But the decisive check is simply: **each processor hardcodes the expected character as an `i32.const`**.
- Kotlin/Wasm GC + lots of runtime strings are there to distract you and make simple string extraction misleading.
