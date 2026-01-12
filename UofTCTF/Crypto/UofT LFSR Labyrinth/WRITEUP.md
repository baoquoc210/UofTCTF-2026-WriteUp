# LFSR Labyrinth — Write Up (283 solves)

## What the challenge is “hiding”

Everything about the cipher is public (the “blueprint”): the 48‑bit LFSR taps, the nonlinear filter function, the HKDF info string, and the fact the flag is encrypted with ChaCha20‑Poly1305.

The *only* secret is the **initial 48‑bit internal state** of the LFSR.  
If you recover that state, you can derive the same key and decrypt the flag.

The “80 bits of trace” is the giveaway: you’re handed 80 output bits of the stream cipher, which leak enough information to solve for the hidden state.

## Files in the challenge

- `challenge.json`: all public parameters + the leaked 80 keystream bits + `nonce` and `ct`
- `filter_cipher.py`: implements the 48‑bit LFSR + nonlinear filter (WG‑style ANF)
- `crypto.py`: derives a key from the recovered state and decrypts with ChaCha20‑Poly1305

## How the stream cipher works (high level)

### 1) The LFSR (Linear Feedback Shift Register)

An LFSR has a state of `L` bits. Each clock:

1. It outputs a bit derived from some taps of the current state (here: via a nonlinear filter).
2. It computes a **feedback bit** as XOR of some tapped state bits.
3. It shifts and inserts the feedback bit into the state.

From `challenge.json`:

- `L = 48`
- feedback taps: `[0, 1, 2, 3, 47]`

From `filter_cipher.py` (important indexing detail):

- `state[0]` is the **newest** bit
- after clocking: `state = [feedback] + state[:-1]`

So the update rule is:

- `state[t+1][0] = state[t][0] XOR state[t][1] XOR state[t][2] XOR state[t][3] XOR state[t][47]`
- `state[t+1][i] = state[t][i-1]` for `i = 1..47`

### 2) The nonlinear filter (WG‑flavoured ANF)

The keystream bit isn’t a simple linear tap. Instead it uses 7 tapped bits from the LFSR:

- filter taps: `[0, 4, 7, 11, 16, 22, 29]`

Call those 7 bits:

```
x0 = state[t][0]
x1 = state[t][4]
x2 = state[t][7]
x3 = state[t][11]
x4 = state[t][16]
x5 = state[t][22]
x6 = state[t][29]
```

Then the output bit `z[t]` is computed using an **ANF** (algebraic normal form), which is just a polynomial over GF(2):

- “multiplication” is AND
- “addition” is XOR

Each term like `(1,2,3)` means `x1 AND x2 AND x3`.  
All term results are XORed together to produce `z[t]`.

This list of monomials is in `filter_cipher.py` as `WG_ANF_TERMS` and is repeated in `challenge.json` as `filter_terms`.

## Why this is solvable (the cryptanalysis idea)

Brute forcing the secret 48‑bit state would be ~`2^48`, which is too big.

But we are given 80 keystream bits. Each keystream bit gives one equation that the secret state must satisfy. Because we know exactly how the internal state shifts each time, we can write **constraints** linking:

- the unknown initial state `state[0][0..47]`
- the unknown states at later times `state[1]`, `state[2]`, …
- the known output bits `keystream[0..79]`

Even though the filter is nonlinear, the state is only 48 bits and the trace is 80 bits, so an SMT/SAT solver (like Z3) can solve it quickly.

## Step‑by‑step solution

### Step 1: Read parameters and leaked data

From `challenge.json` you get:

- LFSR size `L`
- `feedback_taps`
- `filter_taps`
- ANF monomials `filter_terms`
- leaked `keystream` (80 bits)
- `nonce` and ciphertext `ct` for ChaCha20‑Poly1305

### Step 2: Create boolean variables for the unknown state bits

Create boolean variables:

- `s[t][i]` for time `t = 0..80` and bit position `i = 0..47`

These represent the entire LFSR state at each clock step.

### Step 3: Add LFSR transition constraints

For each time `t = 0..79`, constrain:

- feedback `fb[t] = XOR(s[t][idx] for idx in feedback_taps)`
- `s[t+1][0] == fb[t]`
- `s[t+1][i] == s[t][i-1]` for `i = 1..47`

This ensures `s[t]` evolves exactly like the provided cipher.

### Step 4: Add output (filter) constraints

For each time `t = 0..79`:

1. select the 7 tap variables: `x0..x6` from `s[t][filter_taps[*]]`
2. compute the ANF output as XOR of AND‑monomials
3. assert it equals the leaked `keystream[t]`

### Step 5: Ask Z3 to solve, then extract the initial state

If Z3 returns `sat`, you can read `s[0][0..47]` from the model; that’s the hidden 48‑bit secret.

### Step 6: Verify and decrypt

1. Re-run the provided `NLFFilterCipher` using the recovered state and confirm it reproduces the 80 leaked keystream bits.
2. Use `crypto.decrypt(nonce, ct, state_bits)` to get the plaintext flag.

ChaCha20‑Poly1305 includes an authentication tag, so if you recovered the wrong state, decryption will fail with an exception.

## Reproducible solver script

Save this as `solve.py` in this folder (or run it directly with `python3 -`).

```python
import json
from z3 import Solver, Bool, BoolVal, Xor, And, sat

from filter_cipher import NLFFilterCipher
from crypto import decrypt


def anf_output(tap_bits, terms):
    acc = BoolVal(False)
    for mon in terms:
        prod = BoolVal(True)
        for idx in mon:
            prod = And(prod, tap_bits[idx])
        acc = Xor(acc, prod)
    return acc


def main():
    with open("challenge.json", "r") as f:
        chal = json.load(f)

    L = chal["L"]
    feedback_taps = chal["feedback_taps"]
    filter_taps = chal["filter_taps"]
    terms = [tuple(t) for t in chal["filter_terms"]]
    keystream = chal["keystream"]

    T = len(keystream)  # 80

    s = Solver()
    state = [[Bool(f"s_{t}_{i}") for i in range(L)] for t in range(T + 1)]

    for t in range(T):
        # Output constraint: z[t] == leaked keystream[t]
        tap_bits = [state[t][i] for i in filter_taps]  # 7 variables
        zt = anf_output(tap_bits, terms)
        s.add(zt == BoolVal(bool(keystream[t])))

        # LFSR transition constraints
        fb = BoolVal(False)
        for idx in feedback_taps:
            fb = Xor(fb, state[t][idx])
        s.add(state[t + 1][0] == fb)
        for i in range(1, L):
            s.add(state[t + 1][i] == state[t][i - 1])

    if s.check() != sat:
        raise SystemExit("No solution found (unexpected).")

    m = s.model()
    state0 = [1 if m.evaluate(state[0][i], model_completion=True) else 0 for i in range(L)]

    # Verify keystream matches
    cipher = NLFFilterCipher(feedback_taps, filter_taps, state0)
    assert cipher.keystream(T) == keystream

    # Decrypt flag
    nonce = bytes.fromhex(chal["nonce"])
    ct = bytes.fromhex(chal["ct"])
    flag = decrypt(nonce, ct, state0)
    print(flag.decode())


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve.py
```

## Flag

`uoftctf{l33ky_lfsr_w17h_n0n_l1n34r_fl4v0rrrr}`

