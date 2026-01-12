# Baby (Obfuscated) Flag Checker — Write up (359 solves)

## Overview
This challenge gives you a single Python script, `baby.py`. When you run it, it prints a banner, asks for a flag, then tells you whether you got it right.

The “reverse” part is that the script is heavily obfuscated, so reading the checker directly is painful. The hint says you don’t need to fully deobfuscate it — that’s exactly what we’ll do.

## What the challenge is trying to hide (what it’s testing)
Under all the noise, the program is basically a **flag checker**:
- It checks the **length** of your input.
- Then it checks **several slices** (substrings) of your input against **expected strings**.
- If every slice matches, it prints success.

The obfuscation is meant to hide:
- **Constants**: you see things like `G0g0sQu1D_116510(12775, 3349)` instead of a literal number. (That function is just XOR.)
- **Strings**: prompts and messages are built from lists of integers XORed with a key, instead of appearing as `"Enter the flag:"` in plaintext.
- **Control flow**: instead of readable `if/elif/for`, it uses giant `while True` state machines where a “state” integer is XORed into different values to decide what happens next.
- **Comparison logic**: even when it checks a substring, it wraps both sides in extra functions so it’s harder to spot “this slice must equal that constant”.

In short: it’s challenging you to **avoid getting lost in the obfuscation**, and instead find a clean leverage point to extract the flag.

## Key observation (the leverage point)
If you search for where your input (`g0go`) is used, you’ll find many checks that look like:

```
if g0G0SQuid(g0go[start:end], key) == g0G0SQuid(expected, key):
    ...
```

This is important:
- `g0G0SQuid` is a deterministic transformation (in this file, it’s basically “reverse or don’t reverse” depending on `key`).
- The *same* transformation is applied to both sides with the *same* `key`.

So the condition is equivalent to:

```
g0go[start:end] == expected
```

That means we don’t need to understand `key` or the transform at all. We just need to learn:
1) `start`, 2) `end`, and 3) `expected`.

And Python conveniently keeps those values in local variables while the program is running.

## Step-by-step solve (beginner friendly)

### 1) Run the script once
From the challenge folder:

```
python3 baby.py
```

Enter anything and you’ll see it reject it.

### 2) Determine the required length
There’s a length check at `baby.py:197`:

```
if len(g0go) == <very obfuscated expression>:
```

You can evaluate that expression by importing the module and calling the same helper functions (without running the whole program).

One quick way (this is exactly what was used to solve it):

```py
import baby

length = baby.G0G0SQU1D(
    baby.gOg0sQuId(
        baby.g0GOsquiD(baby.G0g0sQu1D_116510(12775, 3349), baby.G0g0sQu1D_116510(15888, 6848)),
        baby.g0GOsquiD(baby.G0g0sQu1D_116510(13850, 8363), baby.G0g0sQu1D_116510(5053, 3980)),
    ),
    baby.gOg0sQuId(
        baby.g0GOsquiD(baby.G0g0sQu1D_116510(1034, 5173), baby.G0g0sQu1D_116510(12571, 8408)),
        baby.g0GOsquiD(baby.G0g0sQu1D_116510(2118, 5430), baby.G0g0sQu1D_116510(1969, 2517)),
    ),
)
print(length)
```

Result:
- The flag length must be **74**.

### 3) Find where substring checks happen
Search the file for uses of `g0go[` (your input being sliced). For example:
- `baby.py:474` has a check of the form `g0go[start:end]` wrapped inside `g0G0SQuid(...) == g0G0SQuid(...)`.

There are more checks later in the file; they’re nested (one check only runs if previous checks passed).

### 4) Solve by tracing (no deobfuscation required)
We’ll do dynamic analysis:
- Feed the program a 74-character placeholder string.
- Attach a tracer (`sys.settrace`) that runs on every executed line.
- When we hit a line that contains `if g0G0SQuid(g0go[...`, we grab:
  - the `start` and `end` slice indices from the current frame’s locals
  - the `expected` string variable name (also from that line), then its value from locals
- If our current candidate substring doesn’t match the expected string, we “patch” the candidate and restart.

After a few iterations, every slice matches, and the candidate becomes the full flag.

### 5) Reproducible solver script (copy/paste)
Run this from the same folder as `baby.py`:

```py
import builtins
import contextlib
import io
import linecache
import re
import sys

import baby

FLAG_LEN = 74
candidate = ["A"] * FLAG_LEN


class FoundMismatch(Exception):
    pass


slice_re = re.compile(r"g0go\\[(\\w+):(\\w+)\\]")
expected_re = re.compile(r"==\\s*g0G0SQuid\\((\\w+),")

for _ in range(1, 500):
    current = "".join(candidate)
    mismatch = [None]

    def fake_input(prompt=""):
        return current

    def tracer(frame, event, arg):
        if event != "line":
            return tracer

        filename = frame.f_code.co_filename
        if not filename.endswith("baby.py"):
            return tracer

        line = linecache.getline(filename, frame.f_lineno)
        if "if g0G0SQuid(g0go[" not in line:
            return tracer

        m_slice = slice_re.search(line)
        m_exp = expected_re.search(line)
        if not (m_slice and m_exp):
            return tracer

        start_var, end_var = m_slice.group(1), m_slice.group(2)
        expected_var = m_exp.group(1)

        start = frame.f_locals.get(start_var)
        end = frame.f_locals.get(end_var)
        expected = frame.f_locals.get(expected_var)

        if not isinstance(start, int) or not isinstance(end, int) or not isinstance(expected, str):
            return tracer

        if current[start:end] != expected:
            mismatch[0] = (start, end, expected)
            raise FoundMismatch

        return tracer

    old_input = builtins.input
    old_trace = sys.gettrace()
    builtins.input = fake_input
    sys.settrace(tracer)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            baby.gog0sQu1D()
    except FoundMismatch:
        pass
    finally:
        sys.settrace(old_trace)
        builtins.input = old_input

    if mismatch[0] is None:
        break

    start, end, expected = mismatch[0]
    candidate[start:end] = list(expected)

print("".join(candidate))
```

When you run it, it prints the recovered flag.

### 6) Verify
Run the original program and paste the printed string:

```
python3 baby.py
```

It prints: `You got the flag!`

## Flag
`uoftctf{d1d_y0u_m0nk3Y_p4TcH_d3BuG_r3v_0r_0n3_sh07_th15_w17h_4n_1LM_XD???}`

