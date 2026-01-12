# Rotor Cipher — Write up (72 solves)

## 0) What is this challenge trying to hide?

The organizers “destroyed the rotors”, meaning the secret parts are missing:

- `RX`, `RY`, `RZ`: the **rotor wirings** (each is a permutation of A–Z)
- `Ref`: the **reflector wiring** (an involution: swaps letters in pairs, and in this challenge it also has fixed points)

The log (`rotor_cipher.log`) gives you many plaintext/ciphertext examples under many “daily” configurations. The goal is to use those examples to **reconstruct the missing permutations**.

The flag format is defined in `rotor_cipher.py`:

`uoftctf{<RX>_<RY>_<RZ>_<reflector_pairs>}`

(Notches are ignored in the flag.)

---

## 1) What you are given

- `rotor_cipher.py`: the exact encryption algorithm (this is your “spec”).
- `rotor_cipher.log`: output of the *real* rotors:
  - 10 days
  - each day chooses:
    - a rotor order (a permutation of X/Y/Z)
    - a plugboard (6 swaps)
    - a 3-letter starting setting
  - then encrypts 100 random 6-letter messages, **resetting the machine for every message**.

That reset is the key: it lets us treat each character position (0..5) as a fixed substitution for that day.

---

## 2) How the cipher works (from `rotor_cipher.py`)

### 2.0 Tiny glossary (terms used below)

- **Permutation**: a one-to-one mapping of the alphabet (each letter maps to exactly one letter).
- **Involution**: a permutation that is its own inverse. It is made of swaps (A↔B) plus possible fixed points (C→C).
- **Conjugation**: “same wiring, relabeled letters”. `g ∘ p ∘ g^{-1}` has the same cycle structure as `p`.
- **26-cycle**: a permutation that is one big cycle visiting all 26 letters exactly once.

### 2.1 Components

- Alphabet: A..Z (we’ll use numbers 0..25 for math).
- Plugboard `P`: swaps 6 pairs, everything else maps to itself.
  - Important: `P` is an **involution**, meaning `P(P(x)) = x`.
- 3 rotors in some order:
  - Each rotor has a base wiring permutation `p` (“at position 0”).
    - If a rotor wiring string starts with `M...`, that means `A→M`; the next char means `B→...`, etc.
  - Each rotor also has a position `pos` that changes its effective mapping.
  - Each rotor has a notch (affects stepping), but notches do **not** appear in the flag.
- Reflector `Ref`: also an involution.

### 2.2 One character of encryption

For each character, the machine:

1. Steps the rotors (fast rotor always steps; stepping may “carry” to the next rotor depending on notch).
2. Applies plugboard `P`.
3. Passes forward through the 3 rotors.
4. Applies reflector `Ref`.
5. Passes backward through the inverses of the 3 rotors.
6. Applies plugboard `P` again.

Because of the “forward → reflector → backward” structure, encryption equals decryption.

---

## 3) Step-by-step solve

### Step 1 — Strip the plugboard

For any fixed rotor state, the full mapping is:

`ct = P( E( P(pt) ) )`

Where `E` is the “core” mapping made by rotors+reflector+inverse-rotors (no plugboard).

So if we define:

- `u = P(pt_letter)`
- `v = P(ct_letter)`

Then we get a direct equation:

`E(u) = v`

The log gives 100 messages per day, each 6 letters long. Because the machine is reset for each message, **position 0 always uses the same rotor state**, position 1 uses the next state, etc.

So for each day `d` and each position `s in {0..5}`:

- collect all pairs `(u, v)` from the log at that position
- this builds the full substitution table for `E_{d,s}`

With 100 random messages, almost every letter appears at each position, so `E_{d,s}` becomes (almost always) fully known.

### Step 2 — Use the involution property

The core mapping `E` must be an involution because:

- Plugboard is an involution
- Reflector is an involution
- Forward rotors then inverse rotors cancel structurally

So for every day/step:

`E(E(x)) = x`

This lets you:

- sanity-check the recovered table
- fill in missing letters (in this log, 3 steps were missing exactly 1 letter)

In this challenge, every fully recovered `E_{d,s}` has **exactly 2 fixed points** (letters where `E(x)=x`). That’s a strong hint:

- Conjugation preserves “how many fixed points a permutation has”.
- Each `E` is basically a conjugate of the reflector.
- Therefore the reflector itself must also have **2 fixed points** (this is unusual vs. classic Enigma reflectors, which have none).

### Step 3 — Normalize away the fast-rotor position

This is the trick that makes the recovery easy.

Let `S` be the Caesar shift permutation: `S(i) = i+1 (mod 26)`.

In `rotor_cipher.py`, a rotor with wiring `p` at position `pos` acts like:

`rotor_pos = S^{-pos} ∘ p ∘ S^{pos}`

If you bundle the middle+slow rotors and reflector into a single permutation `K` (constant as long as only the fast rotor moves), then:

`E_pos = rotor_pos^{-1} ∘ K ∘ rotor_pos`

Define a “normalized” permutation:

`F_pos = S^{pos} ∘ E_pos ∘ S^{-pos}`

Then you can derive:

`F_{pos+1} = G ∘ F_pos ∘ G^{-1}`

Where:

`G = p^{-1} ∘ S ∘ p`

Important facts:

- `G` depends **only** on the fast rotor wiring `p`.
- `G` is always a **single 26-cycle**, because it’s a conjugate of `S`.

In practice:

- compute each `E_{d,s}` from the log (Step 1)
- compute `pos_fast` for that position:
  - the machine steps before encrypting a character, so `pos_fast = setting_fast + (s+1)`
- build `F_{d,s} = S^{pos_fast} ∘ E_{d,s} ∘ S^{-pos_fast}`
- for transitions within the same day:
  - most of the time: `F_{d,s+1} = G ∘ F_{d,s} ∘ G^{-1}`

If a carry happens (middle rotor steps), that single transition breaks. With 6-letter messages there can be **at most one** such bad transition per day.

### Step 4 — Solve for each rotor’s `G`

For a given rotor (say `X`), look at all days where `X` is the fast rotor and collect equations:

`G ∘ A ∘ G^{-1} = B`

Where `A = F_{d,s}` and `B = F_{d,s+1}`.

Because `A` and `B` are involutions with 2 fixed points, you can heavily restrict what `G` is allowed to do:

- If `x` is fixed by `A`, then `G(x)` must be fixed by `B`.
- If `x` is not fixed by `A`, then `G(x)` can’t be fixed by `B`.

Using the fixed/not-fixed pattern across many equations gives tiny candidate sets for each letter, and a small backtracking solver recovers the unique 26-cycle `G` for each rotor.

### Step 5 — Convert `G` into the rotor wiring `p` (up to a shift)

Since `G = p^{-1} S p`, `p` is basically “the relabeling that turns the 26-cycle `G` into the plain shift cycle”.

Build a canonical `p0` by walking the cycle of `G` starting from 0:

- set `p0[0] = 0`
- `p0[G(0)] = 1`
- `p0[G(G(0))] = 2`
- …

This recovers `p` except for one remaining ambiguity:

- You can add a constant `t` to every output (`p_t(i) = p0(i)+t mod 26`)
- and `G` stays the same.

So each rotor has 26 candidates.

### Step 6 — Brute-force the last 26³ shifts + recover the reflector

Now we brute-force the remaining shifts `(tX, tY, tZ)` (only `26^3 = 17576` cases):

1. Pick one known day/step, build the forward stack `A` for that rotor order and positions.
2. Compute reflector from:
   - `E = A^{-1} Ref A`  ⇒  `Ref = A E A^{-1}`
3. Check that:
   - `Ref` is an involution
   - it has 2 fixed points
4. Verify that the same `Ref` works for **all** days/steps.

Only one shift triple works.

---

## 4) Final recovered secret wirings

Rotor wirings (as A→… strings):

- `RX = MTFXEOVHCRJYUQGBSLPKANIDZW`
- `RY = EWJPHLXIGCNAZOMDRKFUYSVQTB`
- `RZ = AGLVFZDCOSYHNTBKPQJWRIUEXM`

Reflector pairs (fixed points are not shown in the flag):

`AM BQ CP DO EW FZ HU IV KY LX NR ST`

Reflector fixed points: `G` and `J`.

---

## 5) Flag

`uoftctf{MTFXEOVHCRJYUQGBSLPKANIDZW_EWJPHLXIGCNAZOMDRKFUYSVQTB_AGLVFZDCOSYHNTBKPQJWRIUEXM_AM_BQ_CP_DO_EW_FZ_HU_IV_KY_LX_NR_ST}`

---

## 6) (Optional) How to verify locally

The easiest sanity check is: re-run the encryption for every log line and ensure it matches.

- Use the included solver/verifier: `python3 solve_rotor_cipher_fast.py --verify`.
- Use the same `RotorCipher` class from `rotor_cipher.py`.
- For each day line, read rotor order, plugboard, and setting; for each message, encrypt and compare ciphertext.
