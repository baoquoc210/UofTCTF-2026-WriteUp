# MAT247 — Write up (194 solves)

## 1) Challenge recap (what you’re given)

You’re given:
- `chall.py` (generator) and `output.txt` (the “ciphertext”).
- A prime field `GF(p)` and a fixed `12×12` matrix `A` over `GF(p)`.

The generator converts the flag to bits and prints one `12×12` matrix per bit:

- If the bit is `0`, it prints `gen_commuting_matrix(A)` (some matrix `S` such that `SA = AS`).
- If the bit is `1`, it prints a random power `A^k`.

So `output.txt` is a sequence of 368 matrices, each encoding one flag bit.

## 2) What is this challenge trying to hide?

The challenge tries to make “commuting with `A`” look like a weak/ambiguous condition:

> “If `S` commutes with `A`, maybe `S` could be almost anything, so it’s hard to tell it apart from `A^k`.”

The trick is that this is *false* when `A` is **cyclic** (has a cyclic vector). In that case, **every** matrix commuting with `A` is actually a **polynomial in `A`**. That turns the problem into algebra inside a (finite) field, where we can distinguish:
- “general polynomial in `A`” (bit `0`) vs
- “monomial `A^k`” (bit `1`)

That is exactly what the prompt theorem is telling you.

## 3) Key theorem (the prompt) and why it matters

### Theorem (commutant of a cyclic operator)
Let `V` be a finite-dimensional vector space over a field `F`, `T: V → V` a linear operator.

If `V` admits a **T-cyclic vector** `v` (meaning `{v, Tv, T^2v, …, T^{n-1}v}` spans `V`, where `n = dim(V)`), and `S` is another operator such that `ST = TS`, then:

> There exists a polynomial `p(x) ∈ F[x]` such that `S = p(T)`.

(The prompt has a tiny typo; it means “for some polynomial **p**”, not “polynomial T”.)

### Proof (newbie-friendly)
Assume `v` is `T`-cyclic, so every vector in `V` is a linear combination of
`v, Tv, …, T^{n-1}v`.

1) Because `{v, Tv, …, T^{n-1}v}` spans `V`, we can write `Sv` in that spanning set:
   \[
   Sv = a_0 v + a_1 Tv + \cdots + a_{n-1}T^{n-1}v = p(T)v
   \]
   where `p(x) = a_0 + a_1 x + ··· + a_{n-1}x^{n-1}`.

2) Now take any vector `w ∈ V`. Since `v` is cyclic, `w` can be written as `w = q(T)v` for some polynomial `q`.

3) Use the commuting relation `ST = TS`. That implies `S` commutes with **every** polynomial in `T`:
   \[
   S q(T) = q(T) S
   \]

4) Apply `S` to `w`:
   \[
   Sw = S(q(T)v) = q(T)Sv = q(T)p(T)v = p(T)q(T)v = p(T)w
   \]

So `S` and `p(T)` agree on every `w ∈ V`, hence `S = p(T)`.

### Why this breaks the “encryption”

In this challenge:
- `T` is the matrix `A`
- `S` is whatever `gen_commuting_matrix(A)` returns

Because `A` is (by design) cyclic, **every** “commuting matrix” is actually `p(A)`.

So the two branches become:
- bit `0`: print a “random” `p(A)`
- bit `1`: print `A^k` (a very special `p(A)` where `p(x)=x^k`)

Now the goal is to distinguish “random polynomial” from “pure power”.

## 4) Turning this into arithmetic in GF(p^12)

Let `n = 12`.

If `A` is cyclic and its characteristic/minimal polynomial is irreducible of degree `n`, then the set
\[
F_p[A] = \{ p(A) : p(x) \in F_p[x] \}
\]
is not just a ring — it is a **field** isomorphic to `GF(p^n)`.

Concretely, this field can be represented as:
\[
GF(p^n) \cong F_p[x]/(m(x))
\]
where `m(x)` is the minimal polynomial of `A` (here it equals the characteristic polynomial, and it is irreducible).

Under this isomorphism:
- the matrix `A` corresponds to the field element `α = x (mod m(x))`
- any commuting matrix `p(A)` corresponds to the field element `p(α)`

## 5) How to read a printed matrix as a field element

This is the “translation to `GF(p^12)`” hinted by the flag.

### Step A: pick a cyclic vector v
We need a vector `v ∈ (GF(p))^12` such that:
\[
B = [v\ |\ Av\ |\ A^2v\ |\ \cdots\ |\ A^{11}v]
\]
is invertible (i.e., has nonzero determinant mod `p`). Then `{v, Av, …, A^{11}v}` is a basis.

In practice: try random `v` until `B` is invertible.

### Step B: compute coordinates of Mv in that basis
Take one printed matrix `M`.

Because `M` commutes with `A`, we know `M = p(A)` for some polynomial `p`.

Compute `w = Mv`. Since `{v, Av, …, A^{11}v}` is a basis, there is a unique coefficient vector
\[
c = (c_0,\dots,c_{11})
\]
such that:
\[
w = c_0 v + c_1 Av + \cdots + c_{11}A^{11}v
\]

In matrix form: `w = B c`, so `c = B^{-1} w (mod p)`.

That coefficient vector `c` is exactly the field element `p(α)` written in the basis `{1, α, α^2, …, α^{11}}`.

## 6) Distinguishing bit 0 vs bit 1

Now every printed matrix gives you a field element `c ∈ GF(p^12)`.

- If the hidden bit is `1`: `M = A^k`, so `c = α^k`.
  That means `c` lies in the cyclic subgroup `<α>` of `GF(p^12)^*`.

- If the hidden bit is `0`: `M = p(A)` for a “random” polynomial `p`, so `c = p(α)` is (essentially) a random field element.
  A random nonzero element lands in `<α>` with probability `1 / [GF(p^12)^* : <α>]`.

### Membership test
Let `ord(α)` be the multiplicative order of `α` in `GF(p^12)^*`.

Then:
\[
c \in \langle \alpha \rangle \iff c^{ord(\alpha)} = 1
\]
(and `c ≠ 0`; but `0^{ord(α)} ≠ 1` anyway).

For this challenge’s `A`, `α` is not primitive: the index is
\[
[GF(p^{12})^* : \langle \alpha \rangle] = 1224 = 2^3 \cdot 3^2 \cdot 17
\]
so
\[
ord(\alpha) = \frac{p^{12}-1}{1224}.
\]

That makes `<α>` only `1/1224` of the nonzero field elements, so the “random polynomial” case almost never looks like a power.

## 7) Step-by-step solve summary

1. Read `p` and `A` from `chall.py`.
2. Compute the characteristic polynomial `m(x)` of `A` modulo `p` (it’s irreducible of degree 12 here).
3. Implement field arithmetic in `GF(p^12) ≅ F_p[x]/(m(x))` using 12 coefficients.
4. Find a cyclic vector `v` by checking when `B = [v|Av|…|A^11v]` is invertible mod `p`; compute `B^{-1}`.
5. For each printed matrix `M` in `output.txt`:
   - Compute `w = Mv`.
   - Compute `c = B^{-1} w` (the coefficients in the cyclic basis).
   - Output bit `1` if `c^{(p^12-1)/1224} == 1`, else bit `0`.
6. Convert the recovered bitstring to bytes: that’s the flag.

## 8) Solver (reproducible)

Run:

```bash
python3 solve.py
```

## 9) Flag

`uoftctf{jus7_4_s1mple_tr4nslation_t0_GF(p^12)}`

