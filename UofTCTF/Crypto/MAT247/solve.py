#!/usr/bin/env python3
import re
import random

import sympy as sp
from sympy.polys.matrices import DomainMatrix


P = 202184226278391025014930169562408816719
N = 12
INDEX_ALPHA = 1224


def parse_A():
    text = open("chall.py", "r", encoding="utf-8").read()
    start = text.index("A = GF([") + len("A = GF([")
    end = text.index("])\n\nFLAG")
    nums = list(map(int, re.findall(r"-?\d+", text[start:end])))
    if len(nums) != N * N:
        raise ValueError("Unexpected A size")
    return [nums[i * N : (i + 1) * N] for i in range(N)]


def charpoly_mod_p(A):
    dm = DomainMatrix(A, (N, N), sp.GF(P))
    coeffs_high = [int(c) % P for c in dm.charpoly()]
    mod_low = [coeffs_high[N - i] for i in range(N + 1)]
    if mod_low[-1] != 1:
        raise ValueError("Expected monic modulus")
    return mod_low


def mat_vec_mul(M, v):
    out = [0] * N
    for i in range(N):
        s = 0
        Mi = M[i]
        for j in range(N):
            s += Mi[j] * v[j]
        out[i] = s % P
    return out


def find_cyclic_vector(A):
    rng = random.Random(0)
    while True:
        v = [rng.randrange(P) for _ in range(N)]
        if all(x == 0 for x in v):
            continue
        cols = [v]
        for _ in range(1, N):
            cols.append(mat_vec_mul(A, cols[-1]))
        B_rows = [[cols[j][i] for j in range(N)] for i in range(N)]
        B = sp.Matrix(B_rows)
        try:
            B_inv = B.inv_mod(P)
        except ValueError:
            continue
        B_inv_rows = [
            [int(B_inv[i, j]) % P for j in range(N)]
            for i in range(N)
        ]
        return v, B_inv_rows


def fe_mul_builder(mod_low):
    mod_c = mod_low[:N]

    def fe_mul(a, b):
        prod = [0] * (2 * N - 1)
        for i, ai in enumerate(a):
            if ai:
                for j, bj in enumerate(b):
                    if bj:
                        prod[i + j] += ai * bj
        for d in range(2 * N - 2, N - 1, -1):
            t = prod[d]
            if t:
                base = d - N
                for i, c in enumerate(mod_c):
                    prod[base + i] -= t * c
        return [x % P for x in prod[:N]]

    return fe_mul


def fe_pow_window_builder(fe_mul, window_bits=4):
    one = [1] + [0] * (N - 1)

    def fe_pow(a, e):
        if e == 0:
            return one
        table = [None] * (1 << (window_bits - 1))
        table[0] = a
        a2 = fe_mul(a, a)
        for i in range(1, len(table)):
            table[i] = fe_mul(table[i - 1], a2)

        res = one
        i = e.bit_length() - 1
        while i >= 0:
            if ((e >> i) & 1) == 0:
                res = fe_mul(res, res)
                i -= 1
                continue
            j = max(i - window_bits + 1, 0)
            while ((e >> j) & 1) == 0:
                j += 1
            for _ in range(i - j + 1):
                res = fe_mul(res, res)
            window_val = (e >> j) & ((1 << (i - j + 1)) - 1)
            res = fe_mul(res, table[(window_val - 1) // 2])
            i = j - 1
        return res

    return fe_pow, one


def decode():
    A = parse_A()
    mod_low = charpoly_mod_p(A)
    fe_mul = fe_mul_builder(mod_low)
    fe_pow, fe_one = fe_pow_window_builder(fe_mul)

    v, B_inv_rows = find_cyclic_vector(A)

    order_alpha = (P ** N - 1) // INDEX_ALPHA

    nums = list(map(int, re.findall(r"-?\d+", open("output.txt", "r", encoding="utf-8").read())))
    if len(nums) % (N * N) != 0:
        raise ValueError("output.txt length is not a multiple of 12x12 matrices")

    bits = []
    it = iter(nums)
    for _ in range(len(nums) // (N * N)):
        w = []
        for _ in range(N):
            dot = 0
            for j in range(N):
                dot += next(it) * v[j]
            w.append(dot % P)

        c = [sum(B_inv_rows[i][j] * w[j] for j in range(N)) % P for i in range(N)]
        bits.append("1" if fe_pow(c, order_alpha) == fe_one else "0")

    bitstr = "".join(bits)
    out = int(bitstr, 2).to_bytes(len(bits) // 8, "big")
    return out


if __name__ == "__main__":
    print(decode())

