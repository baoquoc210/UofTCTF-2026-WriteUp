# Gambler's Fallacy  — Write up (405 solves)

## What the challenge is trying to hide (challenge us with)

This looks like a “provably fair” dice site (inspired by primedice):

- The server generates a secret `server_seed`.
- You choose a `client_seed`.
- A `nonce` increments each roll.
- A hash/HMAC combines these into a roll.

The game *pretends* the roll is cryptographically unpredictable, so you’d think the only way to win is “gambling” (streaks, luck, *gambler’s fallacy*, etc.).

The real hidden weakness is that the “secret” `server_seed` is:

1) generated with Python’s `random` (Mersenne Twister, MT19937), **not** a cryptographic RNG, and  
2) **printed to you after every roll** (`Server-Seed: ...`), leaking the RNG output.

MT19937 can be fully reconstructed from 624 observed 32‑bit outputs. Once reconstructed, you can predict all future `server_seed` values and therefore predict/control future rolls.

## Source code walkthrough (important parts)

From `chall.py`:

- Each roll does:
  - `self.server_seed = random.getrandbits(32)`  ← **MT19937 output**
  - `sig = hmac.new(str(self.server_seed), f"{client_seed}-{nonce}", sha256).hexdigest()`
  - Pull 5‑hex‑digit chunks from `sig` to build `lucky`
  - `roll = round((lucky % 10000) * 0.01)`  → an integer-ish value in `[0..99]`
- After every game the server prints:
  - `Nonce`, `Client-Seed`, and **`Server-Seed`**

So the server gives you exactly what you need to clone its RNG.

## Key idea: clone MT19937 from leaked outputs

Python’s `random` uses MT19937. It has an internal state of **624 32-bit words**.

Each call to `getrandbits(32)` produces a **tempered** version of one internal state word.
“Untempering” reverses the tempering function, recovering the raw state word.

Once you collect 624 consecutive `server_seed` values:

1) Untemper each output to recover the 624 internal state words.
2) Build a local `random.Random()` and set its state to match the server.
3) Now you can predict the next `server_seed` values exactly.

## Step-by-step solution (newbie friendly)

### Step 0: Connect and observe

Connect:

```bash
nc 34.162.20.138 5000
```

You start with `$800`. The shop sells the flag for `$10000`, so you must grow your balance.

### Step 1: Farm 624 leaked `Server-Seed` values

Use option `b) gamble`, then choose:

- Wager: `1` (minimum is `balance/800`, so initially it’s 1)
- Number of games: `624`
- Greed: `98` (high chance to win, low-risk)

Each line looks like:

```
Game 00000: Roll: 60, Reward: ..., Nonce: 0, Client-Seed: ..., Server-Seed: 3677090077
```

Record all 624 `Server-Seed` integers in order.

### Step 2: Reconstruct the server RNG state (untwist / untemper)

Implement MT untempering:

- MT tempering is a sequence of XOR + shifts + masks.
- You reverse them in reverse order to recover the original 32-bit state word.

After untempering all 624 outputs, you now have the full MT state.

### Step 3: Predict the next `server_seed` and sanity-check

With your local clone, compute:

```python
next_seed = predictor.getrandbits(32)
```

Place a single cheap bet (1 game) and confirm the server prints the same `Server-Seed`.
If it matches, your clone is synced.

### Step 4: Use the prediction to force a huge win

Now you can predict the *next* `server_seed` before betting.

Because the roll is computed as:

```
roll = f(server_seed, client_seed, nonce)
```

and you’re allowed to choose `client_seed`, you can brute-force a `client_seed` that makes the next roll very small (e.g. `<= 2`).

Why this matters:

- The payout multiplier is `(100-1)/greed = 99/greed`.
- Smaller `greed` → bigger multiplier.
- If you can guarantee `roll <= 2`, you can set `greed = 2` and win ~49.5× your wager.

So:

1) Predict upcoming `server_seed`.
2) Search for a `client_seed` giving a tiny roll at the upcoming `nonce`.
3) Set that `client_seed` (menu option `c`).
4) Bet your full balance with `greed = 2`.

Your balance jumps far beyond `$10000`.

### Step 5: Buy the flag

Use option `a) view shop` then `a) buy flag`.

## Automated solve script

This folder includes `solve.py`, which does the full exploit end-to-end:

- Collects 624 `Server-Seed` values
- Untempers them and clones MT19937
- Predicts the next `server_seed` and verifies sync
- Brute-forces a `client_seed` to get a low roll
- Bets all-in and buys the flag

Run:

```bash
python3 solve.py
```

If you don’t have pwntools installed, install it with:

```bash
python3 -m pip install pwntools
```

## Why this is a crypto challenge (lessons learned)

- **MT19937 is not cryptographically secure**: observing enough outputs lets you predict all future outputs.
- **Never use non-crypto RNG for secrets** (keys, seeds, tokens).
- **Never leak your secret**: printing `Server-Seed` defeats the whole point of “provably fair”.
- Even if you use strong primitives (HMAC-SHA256), using them with predictable/leaked keys breaks security.

