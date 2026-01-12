# Guess The Number — Write up (189 solves)
> “Guess my super secret number”
>
> Remote: `nc 35.231.13.90 5000`

## What the challenge is trying to hide / challenge you with
The server picks a secret random number `x` (up to ~100 bits) and then:

1. Lets you ask **50 yes/no questions** about `x`, by submitting an “expression”.
2. After 50 questions, you must **guess `x` exactly** to get the flag.

Normally, a yes/no question only gives **1 bit** of information. Since `x` is ~100 bits, you’d expect to need around **100** yes/no questions (e.g., binary search with `x < mid`) to recover it. The challenge only gives **50**, so it looks impossible.

The “hidden trick” is that the server leaks extra information through **timing** (how long it takes to answer), so we can effectively get **2 bits per query** instead of 1.

## Provided server logic (important parts)
From `chall.py`:

- `x = random.randint(0, 1<<100)`
- You can send 50 inputs. Each input is parsed with `ast.literal_eval`, so it must be a Python literal like:
  - an `int` / `bool`
  - a string `'x'`
  - a dict like `{'op': '+', 'arg1': ..., 'arg2': ...}`
- The server evaluates the expression with a custom recursive evaluator and prints:
  - `Yes!` if `bool(evaluate(expression, x))` is true
  - `No!` otherwise
- After 50 expressions, it asks `Guess the number:` and compares your guess to `x`.

### Supported operations
The evaluator supports:
- Boolean: `and`, `or`, `not`
- Comparisons: `<`, `<=`, `>`, `>=`
- Arithmetic: `+`, `-`, `*`, `/` (this is **integer** division `//`), `**`, `%`

## The bug/vulnerability: timing side-channel via short-circuiting
Look at how `and`/`or` are implemented:

```py
case "and":
    return evaluate(arg1, x) and evaluate(arg2, x)
case "or":
    return evaluate(arg1, x) or evaluate(arg2, x)
```

In Python, `and`/`or` **short-circuit**:
- `A and B`: if `A` is false, Python **never evaluates** `B`.
- `A or B`: if `A` is true, Python **never evaluates** `B`.

So if we put something **very expensive** (slow) in `B`, then:
- When the condition is met, the server becomes **slow**.
- Otherwise, it stays **fast**.

Even though the server only prints `Yes!/No!`, the **response time** leaks another bit.

## Strategy: get 2 bits of `x` per query
We have 50 queries, so we can target **100 bits** total by extracting **2 bits per query**.

For query `i` (0 to 49), we will recover bits `(2*i)` and `(2*i+1)`:

1. Let `shift = 2*i`.
2. Define:
   - `v = (x // 2**shift) % 4`
   - This isolates two bits of `x` as a value `v ∈ {0,1,2,3}`:
     - `v = b0 + 2*b1`, where:
       - `b0` is the lower bit (bit `shift`)
       - `b1` is the upper bit (bit `shift+1`)

### Bit 0 (printed output)
`b0 = v % 2`

That’s a clean 0/1 value; if we make the whole expression evaluate to that, then:
- `Yes!` means `b0 = 1`
- `No!` means `b0 = 0`

### Bit 1 (timing)
`b1 = (v >= 2)`

That’s a boolean. We want to trigger an expensive computation **only if** `b1` is true.

We use this trick:

`(v >= 2) and ((2**HEAVY_EXP) and 0)`

Why it works:
- If `(v >= 2)` is false, the `and` short-circuits: the expensive part is skipped → **fast**.
- If `(v >= 2)` is true, it must evaluate `((2**HEAVY_EXP) and 0)`:
  - `2**HEAVY_EXP` is a huge nonzero integer → truthy
  - `truthy and 0` returns `0`
  - This forces the big exponentiation to actually run, costing time.

Crucially, this timing-leak term always evaluates to something falsy (`False` or `0`), so we can add it without changing the printed bit:

Final idea:

```
expr = (v % 2) + ((v >= 2) and ((2**HEAVY_EXP) and 0))
```

No matter what, `expr` is either `0` or `1` (so printed output still gives `b0`), but the runtime differs depending on `b1`.

## Step-by-step solve (newbie friendly)

### 1) Pick a “heavy” operation
We need a big computation that’s:
- Noticeably slower than normal
- Still safe under the jail limits and time limit

`2 ** 25_000_000` worked well (big enough time gap, still within memory/time).

### 2) Connect and send 50 expressions
For each `i = 0..49`:
- Compute `shift = 2*i`
- Send the expression (as a Python literal dict) to the server
- Measure how long it took to get the response line
- Record:
  - Printed `Yes!/No!` → bit `2*i`
  - Time “fast/slow” → bit `2*i+1`

### 3) Turn timings into 0/1
Because networks are noisy, timings aren’t perfectly constant.

Instead of hard-coding a threshold, we can compute it automatically:
- Sort all 50 durations
- Find the **largest gap** between two neighboring sorted durations
- Put the threshold in the middle of that gap

This works well when the data is “two clusters” (fast vs slow).

### 4) Reconstruct `x`
After collecting 100 bits:

`x = sum(bits[k] * 2**k for k in range(100))`

### 5) Send the guess and read the flag
After 50 expressions, the server prompts `Guess the number:`.
Send the reconstructed `x`.

## Full exploit script (Python)
Save as `solve.py` locally (or just run it as-is):

```py
#!/usr/bin/env python3
import socket
import time

HOST = "35.231.13.90"
PORT = 5000

# Chosen so the heavy path is clearly slower, but still finishes within time/memory.
HEAVY_EXP = 25_000_000


class Tube:
    def __init__(self, sock: socket.socket):
        self.s = sock
        self.buf = b""

    def _recv(self, n=4096) -> bytes:
        data = self.s.recv(n)
        if not data:
            raise EOFError
        return data

    def recvuntil(self, token: bytes, timeout=60) -> bytes:
        self.s.settimeout(timeout)
        while token not in self.buf:
            self.buf += self._recv(4096)
        idx = self.buf.index(token) + len(token)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def recvline(self, timeout=60) -> bytes:
        return self.recvuntil(b"\n", timeout=timeout)

    def sendline(self, s: str) -> None:
        self.s.sendall(s.encode() + b"\n")


def build_expr(bitpair_index: int) -> dict:
    shift = 2 * bitpair_index

    # v = (x // 2**shift) % 4
    v = {
        "op": "%",
        "arg1": {
            "op": "/",
            "arg1": "x",
            "arg2": 2**shift,
        },
        "arg2": 4,
    }

    # b0 = v % 2
    b0 = {"op": "%", "arg1": v, "arg2": 2}

    # b1 = (v >= 2)
    b1 = {"op": ">=", "arg1": v, "arg2": 2}

    heavy = {"op": "**", "arg1": 2, "arg2": HEAVY_EXP}

    # Force 'heavy' to be evaluated only when b1 is true,
    # but return a falsy value (0) so it doesn't change the final boolean.
    heavy_and_0 = {"op": "and", "arg1": heavy, "arg2": 0}
    timing_term = {"op": "and", "arg1": b1, "arg2": heavy_and_0}

    # expr = b0 + timing_term
    return {"op": "+", "arg1": b0, "arg2": timing_term}


def threshold_largest_gap(durations):
    s = sorted(durations)
    best_gap = -1.0
    best_mid = None
    for a, b in zip(s, s[1:]):
        gap = b - a
        if gap > best_gap:
            best_gap = gap
            best_mid = (a + b) / 2
    return best_mid


def main():
    sock = socket.create_connection((HOST, PORT), timeout=5)
    t = Tube(sock)

    lsb_bits = [0] * 50
    durations = [0.0] * 50

    for i in range(50):
        t.recvuntil(b": ", timeout=60)  # "Input your expression (...): "
        expr = build_expr(i)

        start = time.perf_counter()
        t.sendline(repr(expr))
        line = t.recvline(timeout=300).decode(errors="replace").strip()
        dt = time.perf_counter() - start

        lsb_bits[i] = 1 if line == "Yes!" else 0
        durations[i] = dt

    thr = threshold_largest_gap(durations)

    bits = [0] * 100
    for i in range(50):
        bits[2 * i] = lsb_bits[i]
        bits[2 * i + 1] = 1 if durations[i] > thr else 0

    x = 0
    for k, b in enumerate(bits):
        x |= (b << k)

    t.recvuntil(b": ", timeout=60)  # "Guess the number: "
    t.sendline(str(x))

    out = b""
    sock.settimeout(2)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
    except Exception:
        pass

    print(out.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

Run it:

```bash
python3 solve.py
```

## Flag
`uoftctf{h0w_did_y0u_gu3ss_7h3_numb3r}`

## Notes / common pitfalls
- The input must be a valid Python literal (because the server uses `ast.literal_eval`), so make sure you send dictionaries like `{'op': ..., 'arg1': ..., 'arg2': ...}`.
- The `/` operator in this challenge is **integer division**.
- If your network is especially noisy, increase `HEAVY_EXP` a bit so the “slow” cluster is more separated from the “fast” cluster.
