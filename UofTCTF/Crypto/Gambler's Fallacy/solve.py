#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import random
import re
from dataclasses import dataclass

from pwn import remote  # type: ignore


HOST = "34.162.20.138"
PORT = 5000


def _unshift_right_xor(y: int, shift: int) -> int:
    x = y & 0xFFFFFFFF
    for _ in range(5):
        x = y ^ (x >> shift)
    return x & 0xFFFFFFFF


def _unshift_left_xor_mask(y: int, shift: int, mask: int) -> int:
    x = y & 0xFFFFFFFF
    for _ in range(5):
        x = y ^ ((x << shift) & mask)
    return x & 0xFFFFFFFF


def untemper(y: int) -> int:
    y &= 0xFFFFFFFF
    y = _unshift_right_xor(y, 18)
    y = _unshift_left_xor_mask(y, 15, 0xEFC60000)
    y = _unshift_left_xor_mask(y, 7, 0x9D2C5680)
    y = _unshift_right_xor(y, 11)
    return y & 0xFFFFFFFF


def roll_from(server_seed: int, client_seed: str, nonce: int) -> int:
    nonce_client_msg = f"{client_seed}-{nonce}".encode()
    sig = hmac.new(str(server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()
    index = 0
    lucky = int(sig[index * 5 : index * 5 + 5], 16)
    while lucky >= 1e6:
        index += 1
        lucky = int(sig[index * 5 : index * 5 + 5], 16)
        if index * 5 + 5 > 129:
            lucky = 9999
            break
    return round((lucky % 1e4) * 1e-2)


BAL_RE = re.compile(r"Final Balance:\s*([0-9.eE+-]+)")
SEED_RE = re.compile(r"Server-Seed:\s*(\d+)")
ROLL_RE = re.compile(r"Roll:\s*(\d+)")


@dataclass
class GameLine:
    roll: int
    server_seed: int


def parse_game_line(line: bytes) -> GameLine:
    s = line.decode(errors="ignore")
    m_seed = SEED_RE.search(s)
    m_roll = ROLL_RE.search(s)
    if not m_seed or not m_roll:
        raise ValueError(f"unexpected game line: {s!r}")
    return GameLine(roll=int(m_roll.group(1)), server_seed=int(m_seed.group(1)))


def menu_sync(io) -> None:
    io.recvuntil(b"> ")


def gamble(io, wager: str, games: int, greed: int) -> None:
    menu_sync(io)
    io.sendline(b"b")
    io.sendlineafter(b"): ", wager.encode())
    io.sendlineafter(b"Number of games (int): ", str(games).encode())
    io.sendlineafter(b"lower numbers): ", str(greed).encode())
    io.sendlineafter(b"(Y/N)", b"Y")


def set_client_seed(io, new_seed: str) -> None:
    menu_sync(io)
    io.sendline(b"c")
    io.sendlineafter(b"Set custom seed: ", new_seed.encode())


def buy_flag(io) -> str:
    menu_sync(io)
    io.sendline(b"a")
    io.recvuntil(b"> ")
    io.sendline(b"a")
    # flag prints as a single line
    flag_line = io.recvline(timeout=3)
    return flag_line.decode(errors="ignore").strip()


def main() -> None:
    io = remote(HOST, PORT)
    nonce = 0

    # 1) Collect 624 MT outputs (server seeds) with low-risk play.
    gamble(io, wager="1", games=624, greed=98)
    seeds: list[int] = []
    for _ in range(624):
        gl = parse_game_line(io.recvline())
        seeds.append(gl.server_seed)
        nonce += 1

    m = BAL_RE.search(io.recvline().decode(errors="ignore"))
    if not m:
        raise RuntimeError("could not parse final balance after seed collection")
    balance = float(m.group(1))

    # 2) Recover MT state and sync a local predictor.
    state = [untemper(x) for x in seeds]
    predictor = random.Random()
    predictor.setstate((3, tuple(state + [624]), None))

    # 3) Sanity-check: predict the next server seed with a tiny wager.
    predicted_seed = predictor.getrandbits(32)
    gamble(io, wager=str(max(1.0, balance / 800.0)), games=1, greed=98)
    gl = parse_game_line(io.recvline())
    if gl.server_seed != predicted_seed:
        raise RuntimeError(f"prediction desync: got {gl.server_seed}, expected {predicted_seed}")
    m = BAL_RE.search(io.recvline().decode(errors="ignore"))
    if not m:
        raise RuntimeError("could not parse balance after sanity-check gamble")
    balance = float(m.group(1))
    nonce += 1

    # 4) Force a low roll by choosing a client seed (key is predictable now).
    predicted_seed = predictor.getrandbits(32)
    target_nonce = nonce
    target_roll = None
    chosen_seed = None
    for i in range(1, 5000):
        candidate = f"seed{i}"
        r = roll_from(predicted_seed, candidate, target_nonce)
        if r <= 7:
            chosen_seed = candidate
            target_roll = r
            break
    if chosen_seed is None or target_roll is None:
        raise RuntimeError("failed to find a favorable client seed")

    set_client_seed(io, chosen_seed)

    greed = max(2, target_roll)
    gamble(io, wager=str(balance), games=1, greed=greed)
    gl = parse_game_line(io.recvline())
    if gl.server_seed != predicted_seed:
        raise RuntimeError("prediction desync on all-in bet")
    m = BAL_RE.search(io.recvline().decode(errors="ignore"))
    if not m:
        raise RuntimeError("could not parse balance after all-in gamble")
    balance = float(m.group(1))
    nonce += 1

    if balance < 10000:
        raise RuntimeError(f"balance too low after all-in: {balance}")

    flag = buy_flag(io)
    print(flag)


if __name__ == "__main__":
    main()
