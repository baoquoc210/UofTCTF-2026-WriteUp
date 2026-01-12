# Orca — Write up (179 solves)

Challenge description: “Orcas eat squids :(”

Remote: `nc 34.186.247.84 5000`

Flag: `uoftctf{l37_17_b3_kn0wn_th4t_th3_0r4c13_h45_5p0k3N_ac9ae43a889d2461fa7039201b6a1a75}`

## What is this challenge “hiding”?

The server is hiding the flag by:

- Encrypting `your_input || flag` with **AES-ECB** (block cipher mode, 16-byte blocks).
- Adding a **random prefix** (`p`) before your input every query (but with a fixed length for the whole connection).
- Shuffling the ciphertext blocks with a secret **permutation** `q`.
- Only giving you **one ciphertext block** per query (you choose the output index).

This looks like it should break the classic “ECB byte-at-a-time” attack, because:

- The random prefix scrambles alignment.
- The permutation hides block positions.
- You can’t see the whole ciphertext at once.

But ECB has a fatal property: **each 16-byte block is encrypted independently**. If we can (1) force alignment and (2) learn which “output index” corresponds to which “real block”, then we can still recover the flag byte-by-byte.

## Background (newbie-friendly)

### AES and blocks

AES is a **block cipher**: it encrypts data in fixed-size chunks (blocks). For AES the block size is always **16 bytes**, no matter if the key is 128/192/256 bits.

So any plaintext is split like:

```
P0 | P1 | P2 | ...
```

where each `Pi` is 16 bytes.

### ECB mode (why it’s weak)

ECB mode encrypts each block *independently*:

```
Ci = AES_k(Pi)
```

That means:

- Same plaintext block → same ciphertext block (for a fixed key).
- There is no IV and no “chaining” between blocks.

This “same in, same out” property is exactly what we abuse.

### PKCS#7 padding (why there are 65 blocks)

AES needs a multiple of 16 bytes. PKCS#7 padding appends `N` bytes, each with value `N`.

Example: if you need 3 bytes of padding, you append `03 03 03`.

In this challenge the server always builds `m` to be exactly 1024 bytes long, which is already a multiple of 16, so PKCS#7 adds a **full extra block** of 16 bytes of value `0x10`. That’s why the ciphertext has:

```
1024 bytes / 16 = 64 blocks
+ 1 extra padding block
= 65 blocks total (idx 0..64)
```

## Understanding the server

From `src/server.py`:

- AES key `k` is random once per process and reused for all queries.
- Prefix length `pl` is fixed once per process: `pl = random_byte % 97`, so `0..96`.
- Your input `u` is at most 256 bytes.
- Plaintext is built as:

```
m = p || u || FLAG
```

Then `m` is either truncated to 1024 bytes or padded out to 1024 bytes with random bytes. After that, PKCS#7 padding is applied and AES-ECB encrypts it.

Finally:

- The ciphertext is split into 16-byte blocks.
- Blocks are permuted with a fixed secret permutation `q`.
- The server returns `out[idx]` (one 16-byte block), base64-encoded.

### The oracle interface

Each line you send is:

```
<idx>:<hex bytes>
```

Example: `0:414141` sends `u = b"AAA"`.

`idx` must be in `0..64` (there are 65 blocks total).

## Key observations

### 1) ECB leaks equality

If two plaintext blocks are identical, their ciphertext blocks are identical:

```
AES_ECB(block) is deterministic for a fixed key
```

So if we can place many identical 16-byte plaintext blocks somewhere, the server’s output (even after permutation) will contain repeated 16-byte ciphertext blocks.

Important detail: the server shuffles blocks, but a shuffle does not destroy equality — if you had 8 identical blocks before the shuffle, you still have 8 identical blocks after the shuffle.

### 2) The prefix length is random, but constant

The prefix bytes change every query, but `pl` (the number of bytes) stays the same for the whole run.

That means we can “fix” alignment once we learn `pl mod 16`.

### 3) The permutation is fixed

Even though blocks are shuffled, the shuffle is the same for every query.

So we can learn a mapping:

```
real_block_number -> output_idx_to_request
```

## Step-by-step solution

### Step 0 — Confirm parameters

- AES block size is 16 bytes.
- Total blocks returned: `65` (because 1024 bytes plus a full PKCS#7 padding block).

### Step 1 — Find the alignment padding (learn `pl mod 16`)

We want the start of our “controlled blocks” to land exactly on a 16-byte boundary.

Let `t` be how many padding bytes we prepend to our input. We need:

```
(pl + t) % 16 == 0
```

We can find `t` by brute forcing `t = 0..15`:

1. Build an input that contains **8 identical full blocks**, e.g. `b"Z" * (16*8)`.
2. Prepend `b"P" * t`.
3. Fill the rest up to 256 bytes with unique data (to avoid accidental repeats).
4. Query **all 65 indices** and count how many times each ciphertext block repeats.

When the 8 identical plaintext blocks are aligned, you will see a ciphertext block repeated **exactly 8 times** in the multiset of returned blocks. That `t` is the correct alignment padding.

Why? Because misalignment causes those `"Z"` bytes to straddle block boundaries, and then the 16-byte blocks are no longer identical.

At this point you can think of it as:

```
p (random, length pl) + P...P (length t) ends exactly on a block boundary
```

### Step 2 — Learn which output index corresponds to which controlled block (undo the permutation)

Now that we can align, create a payload consisting of `m` distinct full blocks:

```
block_0 = 0x00 repeated 16 times
block_1 = 0x01 repeated 16 times
...
block_{m-1}
```

Send:

```
u = b"P"*t + block_0||block_1||...||block_{m-1}
```

Because the prefix bytes are random each query, some output indices will change every time (blocks that include the random prefix). We ignore those by finding “stable indices”:

- Query each index twice with the same input.
- If the returned block is identical both times, that index is stable for this input.

These “stable” indices include (at least) the ciphertext blocks that come entirely from our controlled blocks, because those plaintext blocks are the same every time.

To map a particular controlled block `i`:

- Change only that block (e.g. replace `block_i` with a totally different 16 bytes).
- Query all stable indices once.
- Exactly one stable index will change: that index is where `block_i` ends up after the server’s permutation.

This gives `block_to_outidx[i]`.

### Step 3 — Byte-at-a-time ECB recovery of the flag

After alignment, the plaintext looks like:

```
[random prefix ...][alignment bytes P...P][your controlled bytes][FLAG...]
                                   ^ block boundary starts here
```

Now we do the classic ECB oracle trick, but we request the right output index using the mapping from Step 2.

To recover flag byte `j`:

1. Let `k = j // 16` (which 16-byte block of the flag we are currently in).
2. Let `pad2 = 15 - (j % 16)` so the unknown byte lands at the end of a block.
3. Query the target ciphertext block for:

```
u_target = b"P"*t + b"A"*pad2
```

Request output index `block_to_outidx[k]` and store that 16-byte ciphertext as `C_target`.

4. Build a dictionary by trying all candidate bytes `b`:

```
u_try = b"P"*t + b"A"*pad2 + known_flag_prefix + bytes([b])
```

Request the same output index. When the ciphertext equals `C_target`, the guessed byte is correct.

Repeat until you see the closing `}` of the flag.

### Step 4 — Practical tips (so it doesn’t take forever)

- The service prints a prompt (`> `) after every query. If you send one line, wait, send one line, wait… it’s slow.
- You can speed it up a lot by **batching**: send many `idx:hex` lines in one `sendall()`, then read the same number of responses back.
- In the solver, we first try printable ASCII for each byte (fast), and only fall back to all 256 byte values if needed.

## Solver

An automated solver is in `solve.py`.

Run:

```bash
python3 solve.py
```
