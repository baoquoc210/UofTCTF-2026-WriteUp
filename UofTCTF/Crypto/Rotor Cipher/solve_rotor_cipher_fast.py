#!/usr/bin/env python3
"""
Fast (non-SMT) solver for the UofTCTF "Rotor Cipher" challenge.

It recovers:
  - rotor wirings RX/RY/RZ (strings)
  - reflector wiring Ref (pairs; with 2 fixed points in this challenge)
and prints the flag in the format required by rotor_cipher.py.

This is the method described in WRITEUP.md:
  1) Strip the plugboard to recover per-step core permutations E_{day,step}.
  2) Normalize away the fast-rotor position to get conjugacy equations.
  3) Solve for each rotor’s 26-cycle conjugator G.
  4) Convert G -> rotor wiring up to a 26-way output shift.
  5) Brute-force the remaining 26^3 shifts, derive the reflector, and verify all steps.
"""

from __future__ import annotations

import argparse
import re
import string
from dataclasses import dataclass
from itertools import product
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


ALPHA = string.ascii_uppercase
N = 26


def idx(c: str) -> int:
    return ord(c) - ord("A")


def chr_(i: int) -> str:
    return ALPHA[i % N]


def perm_comp(p: Sequence[int], q: Sequence[int]) -> List[int]:
    # p ∘ q (apply q then p)
    return [p[i] for i in q]


def perm_inv(p: Sequence[int]) -> List[int]:
    inv = [0] * N
    for i, v in enumerate(p):
        inv[v] = i
    return inv


def shift_perm(k: int) -> List[int]:
    return [(i + k) % N for i in range(N)]


def perm_conj(p: Sequence[int], g: Sequence[int]) -> List[int]:
    # g ∘ p ∘ g^{-1}
    invg = perm_inv(g)
    return perm_comp(perm_comp(g, p), invg)


def perm_conj_by_shift(p: Sequence[int], k: int) -> List[int]:
    return perm_conj(p, shift_perm(k))


def is_involution(p: Sequence[int]) -> bool:
    return all(p[p[i]] == i for i in range(N))


def fixed_points(p: Sequence[int]) -> List[int]:
    return [i for i in range(N) if p[i] == i]


def is_single_26_cycle(p: Sequence[int]) -> bool:
    seen = [False] * N
    cur = 0
    for _ in range(N):
        if seen[cur]:
            return False
        seen[cur] = True
        cur = p[cur]
    return cur == 0 and all(seen)


def parse_plugboard(pb_str: str) -> Dict[str, str]:
    pairs = re.findall(r"\('([A-Z])', '([A-Z])'\)", pb_str)
    mapping = {c: c for c in ALPHA}
    for a, b in pairs:
        mapping[a] = b
        mapping[b] = a
    return mapping


@dataclass(frozen=True)
class Day:
    rotor_order: Tuple[str, str, str]
    plugboard: Dict[str, str]
    setting: Tuple[str, str, str]
    messages: List[Tuple[str, str]]  # (msg, ct)


def parse_log(path: str) -> Tuple[str, str, Dict[int, Day]]:
    lines = open(path, "r", encoding="utf-8").read().splitlines()

    sample_plaintext = ""
    sample_ciphertext = ""
    days: Dict[int, Day] = {}
    cur_day: Optional[int] = None

    for line in lines:
        if line.startswith("Sample Plaintext:"):
            sample_plaintext = line.split(":", 1)[1].strip()
        elif line.startswith("Sample Ciphertext:"):
            sample_ciphertext = line.split(":", 1)[1].strip()

        m = re.match(
            r"^(\d+): rotor: \[(.*?)\], plugboard: \[(.*?)\] setting: \[(.*?)\]$",
            line,
        )
        if m:
            d = int(m.group(1))
            rotor_order = tuple(s.strip().strip("'") for s in m.group(2).split(","))
            plugboard = parse_plugboard(m.group(3))
            setting = tuple(s.strip().strip("'") for s in m.group(4).split(","))
            days[d] = Day(
                rotor_order=rotor_order,
                plugboard=plugboard,
                setting=setting,
                messages=[],
            )
            cur_day = d
            continue

        m = re.match(r"^\s*\d+:\s+msg:\s+([A-Z]{6})\s+ct:\s+([A-Z]{6})$", line)
        if m and cur_day is not None:
            days[cur_day].messages.append((m.group(1), m.group(2)))

    if len(days) != 10:
        raise ValueError(f"Expected 10 days, got {len(days)}")
    if not sample_plaintext or not sample_ciphertext:
        raise ValueError("Missing sample plaintext/ciphertext in log")
    return sample_plaintext, sample_ciphertext, days


def build_core_permutations(days: Dict[int, Day]) -> Dict[int, List[List[int]]]:
    """
    Returns E[d][step][i] = output index for input index i, after stripping plugboard.

    From the implementation:
      ct = P( E( P(pt) ) )
    so for each observed pt->ct letter:
      u = P(pt), v = P(ct)  =>  E(u) = v.
    """
    cores: Dict[int, List[List[int]]] = {}
    for d, info in days.items():
        maps: List[Dict[str, str]] = [dict() for _ in range(6)]
        for msg, ct in info.messages:
            for step, (p, c) in enumerate(zip(msg, ct)):
                u = info.plugboard[p]
                v = info.plugboard[c]
                existing = maps[step].get(u)
                if existing is not None and existing != v:
                    raise ValueError(f"inconsistent mapping on day {d} step {step}")
                maps[step][u] = v

        # Close under involution (E must satisfy E(E(x))=x).
        for step in range(6):
            m = maps[step]
            changed = True
            while changed:
                changed = False
                for a, b in list(m.items()):
                    if b in m and m[b] != a:
                        raise ValueError(f"not an involution on day {d} step {step}")
                    if b not in m:
                        m[b] = a
                        changed = True

            # In this log, 3 steps are missing exactly 1 letter; it must be a fixed point.
            missing = [c for c in ALPHA if c not in m]
            if missing:
                if len(missing) != 1:
                    raise ValueError(f"unexpected missing count on day {d} step {step}: {missing}")
                m[missing[0]] = missing[0]

            if sum(1 for c in ALPHA if m[c] == c) != 2:
                raise ValueError(f"expected exactly 2 fixed points on day {d} step {step}")

        cores[d] = [[idx(maps[step][c]) for c in ALPHA] for step in range(6)]
    return cores


def rotor_positions_fast_only(setting_fast: str) -> List[int]:
    """
    For the 6 characters in a message: rotors step before encryption, so the fast rotor position
    used at step s is setting_fast + (s+1).
    """
    start = idx(setting_fast)
    return [(start + s + 1) % N for s in range(6)]


def build_normalized_F(cores: Dict[int, List[List[int]]], days: Dict[int, Day]) -> Dict[int, List[List[int]]]:
    """
    F_{d,s} = S^{pos_fast} ∘ E_{d,s} ∘ S^{-pos_fast}.
    """
    F: Dict[int, List[List[int]]] = {}
    for d, info in days.items():
        pos_fast = rotor_positions_fast_only(info.setting[0])
        F[d] = [perm_conj_by_shift(cores[d][s], pos_fast[s]) for s in range(6)]
    return F


def solve_G_from_equations(eqs: List[Tuple[List[int], List[int]]]) -> Optional[List[int]]:
    """
    Solve for G in equations:  G ∘ A ∘ G^{-1} = B  (for all (A,B)).
    We additionally require G to be a single 26-cycle.

    This uses:
      - fixed-point signature filtering to make tiny domains
      - propagation via G(A(x)) = B(G(x))
      - backtracking to fill remaining choices
    """
    if not eqs:
        return None

    As = [A for A, _ in eqs]
    Bs = [B for _, B in eqs]

    m = len(eqs)
    sigA = [tuple(1 if As[i][x] == x else 0 for i in range(m)) for x in range(N)]
    sigB = [tuple(1 if Bs[i][y] == y else 0 for i in range(m)) for y in range(N)]

    sig_to_ys: Dict[Tuple[int, ...], List[int]] = {}
    for y, sig in enumerate(sigB):
        sig_to_ys.setdefault(sig, []).append(y)

    domains: List[List[int]] = []
    for x in range(N):
        dom = list(sig_to_ys.get(sigA[x], []))
        if not dom:
            return None
        domains.append(dom)

    g: List[Optional[int]] = [None] * N
    inv: List[Optional[int]] = [None] * N

    def trail_push_domain(trail, x: int, removed: Iterable[int]) -> None:
        for y in removed:
            trail.append(("dom", x, y))

    def assign(x: int, y: int, trail, queue) -> bool:
        if y not in domains[x]:
            return False
        if g[x] is not None:
            return g[x] == y
        if inv[y] is not None:
            return inv[y] == x

        g[x] = y
        inv[y] = x
        trail.append(("assign", x, y))

        removed = [yy for yy in domains[x] if yy != y]
        domains[x] = [y]
        trail_push_domain(trail, x, removed)

        queue.append(x)
        return True

    def remove_candidate(x: int, y: int, trail, queue) -> bool:
        if g[x] is not None:
            return g[x] != y
        if y in domains[x]:
            domains[x].remove(y)
            trail.append(("dom", x, y))
            if not domains[x]:
                return False
            if len(domains[x]) == 1:
                yy = domains[x][0]
                if not assign(x, yy, trail, queue):
                    return False
        return True

    def propagate(queue, trail) -> bool:
        while queue:
            x = queue.pop()
            y = g[x]
            if y is None:
                continue

            # Injective: once g[x]=y, remove y from all other domains.
            for xx in range(N):
                if xx != x and g[xx] is None:
                    if not remove_candidate(xx, y, trail, queue):
                        return False

            # Equation propagation: g[A(x)] must equal B(g[x]).
            for A, B in eqs:
                x2 = A[x]
                y2 = B[y]
                if g[x2] is None:
                    if not assign(x2, y2, trail, queue):
                        return False
                else:
                    if g[x2] != y2:
                        return False

        return True

    # Initial forced assignments from singleton domains.
    init_trail = []
    init_queue = []
    for x in range(N):
        if len(domains[x]) == 1:
            if not assign(x, domains[x][0], init_trail, init_queue):
                return None
    if not propagate(init_queue, init_trail):
        return None

    def choose_unassigned() -> Optional[int]:
        best_x = None
        best_len = 10**9
        for x in range(N):
            if g[x] is None:
                l = len(domains[x])
                if l < best_len:
                    best_len = l
                    best_x = x
        return best_x

    def undo(trail) -> None:
        for act in reversed(trail):
            if act[0] == "assign":
                _, x, y = act
                g[x] = None
                inv[y] = None
            else:
                _, x, y = act
                domains[x].append(y)

    result: Optional[List[int]] = None

    def backtrack() -> None:
        nonlocal result
        if result is not None:
            return
        x = choose_unassigned()
        if x is None:
            candidate = [v if v is not None else 0 for v in g]
            if is_single_26_cycle(candidate):
                result = candidate
            return

        for y in list(domains[x]):
            trail = []
            queue = []
            if not assign(x, y, trail, queue):
                undo(trail)
                continue
            if propagate(queue, trail):
                backtrack()
            undo(trail)
            if result is not None:
                return

    backtrack()
    return result


def solve_best_G(
    eqs_with_meta: List[Tuple[List[int], List[int], Tuple[int, int]]]
) -> Tuple[List[int], Dict[int, Optional[int]]]:
    """
    Some day has a carry (middle rotor steps), which breaks exactly one transition within that day.
    We search over excluding at most one transition per day, solve for G, and pick the solution
    that satisfies the most total transitions.

    Returns:
      - G (a 26-cycle)
      - excluded transition per day: {day: step_index or None}
    """
    by_day: Dict[int, List[Tuple[List[int], List[int], Tuple[int, int]]]] = {}
    for A, B, meta in eqs_with_meta:
        d, _s = meta
        by_day.setdefault(d, []).append((A, B, meta))

    days = sorted(by_day.keys())
    choices: List[List[Optional[int]]] = []
    for d in days:
        # None means exclude nothing, otherwise exclude that transition step s (0..4).
        opts: List[Optional[int]] = [None] + [meta[1] for _A, _B, meta in by_day[d]]
        choices.append(opts)

    best_G: Optional[List[int]] = None
    best_excl: Optional[Dict[int, Optional[int]]] = None
    best_sat = -1

    def sat_count(G: Sequence[int]) -> int:
        invG = perm_inv(G)
        count = 0
        for A, B, _meta in eqs_with_meta:
            if perm_comp(perm_comp(G, A), invG) == B:
                count += 1
        return count

    for excl_steps in product(*choices):
        subset: List[Tuple[List[int], List[int]]] = []
        for d, excl in zip(days, excl_steps):
            for A, B, meta in by_day[d]:
                if excl is not None and meta[1] == excl:
                    continue
                subset.append((A, B))

        G = solve_G_from_equations(subset)
        if G is None:
            continue

        sat = sat_count(G)
        if sat > best_sat:
            best_sat = sat
            best_G = G
            best_excl = dict(zip(days, excl_steps))
            if sat == len(eqs_with_meta):
                break

    if best_G is None or best_excl is None:
        raise ValueError("Could not solve for a consistent 26-cycle G")
    return best_G, best_excl


def rotor_base_from_G(G: Sequence[int]) -> List[int]:
    """
    Build p0 such that p0(G^k(0)) = k.
    This ensures p0 ∘ G ∘ p0^{-1} == shift_perm(1).
    """
    p0: List[Optional[int]] = [None] * N
    cur = 0
    for k in range(N):
        if p0[cur] is not None:
            raise ValueError("G is not a single 26-cycle (unexpected)")
        p0[cur] = k
        cur = G[cur]
    if cur != 0:
        raise ValueError("G is not a single 26-cycle (unexpected)")
    return [v if v is not None else 0 for v in p0]


def rotor_at(p: Sequence[int], pos: int) -> List[int]:
    # rotor_pos = S^{-pos} ∘ p ∘ S^{pos}
    return [(p[(i + pos) % N] - pos) % N for i in range(N)]


def A_from_state(
    rotor_cache: Dict[Tuple[str, int, int], List[int]],
    order: Sequence[str],
    shifts: Dict[str, int],
    pos0: int,
    pos1: int,
    pos2: int,
) -> List[int]:
    r0 = rotor_cache[(order[0], shifts[order[0]], pos0)]
    r1 = rotor_cache[(order[1], shifts[order[1]], pos1)]
    r2 = rotor_cache[(order[2], shifts[order[2]], pos2)]
    return perm_comp(r2, perm_comp(r1, r0))


def reflector_from_state(A: Sequence[int], E: Sequence[int]) -> List[int]:
    # Ref = A ∘ E ∘ A^{-1}
    invA = perm_inv(A)
    return perm_comp(A, perm_comp(E, invA))


def compute_carry_info(
    F: Dict[int, List[List[int]]], days: Dict[int, Day], Gs: Dict[str, List[int]]
) -> Tuple[Dict[int, Optional[int]], Dict[str, int]]:
    """
    Returns:
      - carry_step[day] = step index (0..5) where middle rotor steps, or None
        (carry_step is the step whose transition from previous step breaks)
      - notches[rotor] = notch index recovered for rotors that carried within 6 steps
    """
    carry_step: Dict[int, Optional[int]] = {}
    notches: Dict[str, int] = {}

    for d, info in days.items():
        fast = info.rotor_order[0]
        G = Gs[fast]
        invG = perm_inv(G)
        bad = []
        for s in range(5):
            A = F[d][s]
            B = F[d][s + 1]
            if perm_comp(perm_comp(G, A), invG) != B:
                bad.append(s)
        if not bad:
            carry_step[d] = None
            continue
        if len(bad) != 1:
            raise ValueError(f"unexpected: day {d} has multiple bad transitions: {bad}")

        cs = bad[0] + 1  # carry happens at step cs (0..5)
        carry_step[d] = cs

        # carry at step cs means: before rotating that character, fast rotor pos == notch.
        # Before rotation at step t, pos == setting_fast + t.
        notch = (idx(info.setting[0]) + cs) % N
        if fast in notches and notches[fast] != notch:
            raise ValueError(f"inconsistent notch for rotor {fast}: {notches[fast]} vs {notch}")
        notches[fast] = notch

    return carry_step, notches


def day_position_options(
    info: Day, carry_step: Optional[int], notches: Dict[str, int]
) -> List[List[Tuple[int, int, int]]]:
    """
    Returns a list of possible position traces for this day.
    Each trace is a list of 6 tuples: (pos0,pos1,pos2) used at each step.
    """
    start0 = idx(info.setting[0])
    start1 = idx(info.setting[1])
    start2 = idx(info.setting[2])

    pos0_list = [(start0 + s + 1) % N for s in range(6)]

    if carry_step is None:
        return [[(pos0_list[s], start1, start2) for s in range(6)]]

    middle = info.rotor_order[1]
    slow_rotates_known: Optional[bool] = None
    if middle in notches:
        slow_rotates_known = start1 == notches[middle]

    options: List[List[Tuple[int, int, int]]] = []
    for slow_rotates in ([slow_rotates_known] if slow_rotates_known is not None else [False, True]):
        trace: List[Tuple[int, int, int]] = []
        for s in range(6):
            pos1 = start1 + (1 if s >= carry_step else 0)
            pos2 = start2 + (1 if (slow_rotates and s >= carry_step) else 0)
            trace.append((pos0_list[s], pos1 % N, pos2 % N))
        options.append(trace)

    return options


def format_ref_pairs(ref: Sequence[int]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for i, j in enumerate(ref):
        if i < j:
            pairs.append((chr_(i), chr_(j)))
    pairs.sort()
    return pairs


def plugboard_pairs_from_mapping(mapping: Dict[str, str]) -> List[Tuple[str, str]]:
    seen = set()
    pairs = []
    for a in ALPHA:
        b = mapping[a]
        if a == b or a in seen or b in seen:
            continue
        seen.add(a)
        seen.add(b)
        pairs.append((min(a, b), max(a, b)))
    pairs.sort()
    return pairs


def verify_full_log(
    rotors: Dict[str, Tuple[str, str]],
    ref_pairs: List[Tuple[str, str]],
    days: Dict[int, Day],
) -> Tuple[bool, Optional[str]]:
    from rotor_cipher import RotorCipher

    for d, info in days.items():
        plug_pairs = plugboard_pairs_from_mapping(info.plugboard)
        rotor_list = [rotors[r] for r in info.rotor_order]
        for msg, ct in info.messages:
            cipher = RotorCipher(ref_pairs, rotor_list, plug_pairs, list(info.setting))
            calc = cipher.encrypt(msg)
            if calc != ct:
                return False, f"day {d}: {msg} -> {calc} (expected {ct})"
    return True, None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="rotor_cipher.log")
    ap.add_argument("--verify", action="store_true", help="Verify against the full log using RotorCipher.")
    args = ap.parse_args()

    sample_plaintext, sample_ciphertext, days = parse_log(args.log)
    cores = build_core_permutations(days)
    F = build_normalized_F(cores, days)

    # Build conjugacy equations per rotor (when that rotor is the fast rotor).
    eqs_by_rotor: Dict[str, List[Tuple[List[int], List[int], Tuple[int, int]]]] = {"X": [], "Y": [], "Z": []}
    for d, info in days.items():
        fast = info.rotor_order[0]
        for s in range(5):
            eqs_by_rotor[fast].append((F[d][s], F[d][s + 1], (d, s)))

    # Solve G for each rotor.
    Gs: Dict[str, List[int]] = {}
    excluded: Dict[str, Dict[int, Optional[int]]] = {}
    for r in ("X", "Y", "Z"):
        G, excl = solve_best_G(eqs_by_rotor[r])
        Gs[r] = G
        excluded[r] = excl

    # Detect carry steps and recover notches for rotors that carry within 6 steps.
    carry_step, notches = compute_carry_info(F, days, Gs)

    # Convert each G to a canonical base wiring p0, then generate 26 output-shift variants.
    p0 = {r: rotor_base_from_G(Gs[r]) for r in ("X", "Y", "Z")}
    p_variants = {
        r: [[(p0[r][i] + t) % N for i in range(N)] for t in range(N)] for r in ("X", "Y", "Z")
    }

    # Build per-day position options (handles the rare carry/slow-rotates ambiguity).
    pos_options: Dict[int, List[List[Tuple[int, int, int]]]] = {}
    for d, info in days.items():
        pos_options[d] = day_position_options(info, carry_step[d], notches)

    # Precompute rotor permutations for all needed positions.
    needed_positions: Dict[str, set] = {"X": set(), "Y": set(), "Z": set()}
    for d, info in days.items():
        for trace in pos_options[d]:
            for pos0, pos1, pos2 in trace:
                needed_positions[info.rotor_order[0]].add(pos0)
                needed_positions[info.rotor_order[1]].add(pos1)
                needed_positions[info.rotor_order[2]].add(pos2)

    rotor_cache: Dict[Tuple[str, int, int], List[int]] = {}
    for r in ("X", "Y", "Z"):
        for t in range(N):
            p = p_variants[r][t]
            for pos in needed_positions[r]:
                rotor_cache[(r, t, pos)] = rotor_at(p, pos)

    # Choose a reference state to derive the reflector (pick day 0 step 0; it has no carry).
    ref_day = 0
    ref_step = 0
    ref_trace = pos_options[ref_day][0]  # should exist and be unique for day 0 here
    ref_pos0, ref_pos1, ref_pos2 = ref_trace[ref_step]
    ref_order = days[ref_day].rotor_order
    ref_E = cores[ref_day][ref_step]

    solution = None
    for tX in range(N):
        for tY in range(N):
            for tZ in range(N):
                shifts = {"X": tX, "Y": tY, "Z": tZ}

                A = A_from_state(
                    rotor_cache,
                    ref_order,
                    shifts,
                    ref_pos0,
                    ref_pos1,
                    ref_pos2,
                )
                ref = reflector_from_state(A, ref_E)
                if not is_involution(ref):
                    continue
                if len(fixed_points(ref)) != 2:
                    continue

                # Verify: for each day, at least one position-trace option must match all 6 steps.
                ok = True
                for d, info in days.items():
                    day_ok = False
                    for trace in pos_options[d]:
                        for step in range(6):
                            pos0, pos1, pos2 = trace[step]
                            A2 = A_from_state(
                                rotor_cache,
                                info.rotor_order,
                                shifts,
                                pos0,
                                pos1,
                                pos2,
                            )
                            invA2 = perm_inv(A2)
                            E_pred = perm_comp(invA2, perm_comp(ref, A2))
                            if E_pred != cores[d][step]:
                                break
                        else:
                            day_ok = True
                            break
                    if not day_ok:
                        ok = False
                        break

                if ok:
                    solution = (tX, tY, tZ, ref)
                    break
            if solution is not None:
                break
        if solution is not None:
            break

    if solution is None:
        raise SystemExit("No solution found (unexpected).")

    tX, tY, tZ, ref = solution
    RX = ("".join(chr_(v) for v in p_variants["X"][tX]), chr_(notches.get("X", 0)))
    # The log is only 6 characters per message, so the notch for Y is not uniquely determined.
    # Choose a known-good value that does not introduce extra turnovers in the provided log.
    notch_y = chr_(notches["Y"]) if "Y" in notches else "Q"
    RY = ("".join(chr_(v) for v in p_variants["Y"][tY]), notch_y)
    RZ = ("".join(chr_(v) for v in p_variants["Z"][tZ]), chr_(notches.get("Z", 0)))
    ref_pairs = format_ref_pairs(ref)

    # Print recovered secrets.
    print("Recovered rotors (notches shown if recovered from log):")
    print("  RX =", RX[0], "notch=", RX[1])
    print("  RY =", RY[0], "notch=", RY[1], "(not uniquely recoverable from this log)" if "Y" not in notches else "")
    print("  RZ =", RZ[0], "notch=", RZ[1])
    print("Recovered reflector pairs:", " ".join("".join(p) for p in ref_pairs))
    print("Reflector fixed points:", " ".join(chr_(i) for i in fixed_points(ref)))

    # Print flag using the canonical formatting from rotor_cipher.py.
    from rotor_cipher import format_flag

    flag = format_flag(RX, RY, RZ, ref_pairs)
    print("\nFLAG:", flag)

    if args.verify:
        from rotor_cipher import RotorCipher

        # Verify sample line.
        sample_setting = ["O", "J", "B"]
        sample_plugboard = [("B", "P"), ("C", "D"), ("F", "W"), ("N", "X"), ("S", "V"), ("U", "Y")]
        calc = RotorCipher(ref_pairs, [RX, RY, RZ], sample_plugboard, sample_setting).encrypt(sample_plaintext)
        if calc != sample_ciphertext:
            raise SystemExit("Sample ciphertext verification failed.")
        rotors = {"X": RX, "Y": RY, "Z": RZ}
        ok, err = verify_full_log(rotors, ref_pairs, days)
        if not ok:
            raise SystemExit(f"Log verification failed: {err}")
        print("\nVerification: OK (sample + full log)")


if __name__ == "__main__":
    main()
